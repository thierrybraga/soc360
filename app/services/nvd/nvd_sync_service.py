"""
SOC360 NVD Sync Service
Orquestrador de sincronização com NVD.
"""
import json
import logging
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Optional

from flask import current_app
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.jobs.fetchers import NVDFetcher
from app.models.nvd import Vulnerability
from app.models.system import SyncMetadata
from app.services.core.base_sync_service import BaseSyncService, SyncStatus
from app.services.monitoring.alert_service import AlertService
from app.services.nvd.bulk_database_service import BulkDatabaseService


logger = logging.getLogger(__name__)


class SyncMode(Enum):
    """Modos de sincronização."""

    FULL = 'full'
    INCREMENTAL = 'incremental'
    INITIAL = 'initial'
    CUSTOM = 'custom'


class NVDOperationAlreadyRunning(RuntimeError):
    """Raised when another NVD write operation already owns the sync lock."""


class NVDSyncService(BaseSyncService):
    """
    Serviço de sincronização com NVD.

    O estado crítico fica em SyncMetadata para funcionar entre processos:
    controller Flask, Celery worker e threads locais observam o mesmo lock e
    flag de cancelamento.
    """

    LOCK_KEY = 'nvd_sync_lock'
    CANCEL_KEY = 'nvd_sync_cancel_requested'
    TASK_ID_KEY = 'nvd_sync_task_id'
    AUTO_SYNC_LAST_CHECK_KEY = 'nvd_auto_sync_last_check'
    AUTO_SYNC_LAST_REASON_KEY = 'nvd_auto_sync_last_reason'
    LOCK_TTL_SECONDS = 6 * 60 * 60

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(prefix='nvd')
        if not api_key:
            api_key = SyncMetadata.get('nvd_api_key')

        self.fetcher = NVDFetcher(api_key)
        self.db_service = BulkDatabaseService()
        self._lock = threading.Lock()
        self._cancel_flag = False
        self._lock_token: Optional[str] = None

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _now_db() -> datetime:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _encode_lock(cls, token: str, mode: SyncMode) -> str:
        expires_at = cls._now() + timedelta(seconds=cls.LOCK_TTL_SECONDS)
        return json.dumps(
            {
                'token': token,
                'mode': mode.value,
                'started_at': cls._now().isoformat(),
                'expires_at': expires_at.isoformat(),
            },
            separators=(',', ':'),
        )

    @staticmethod
    def _decode_lock(value: Optional[str]) -> Dict:
        if not value:
            return {}
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    @classmethod
    def _lock_payload_expired(cls, payload: Dict) -> bool:
        expires_at = cls._parse_datetime(payload.get('expires_at'))
        return not expires_at or expires_at <= cls._now()

    def _acquire_sync_lock(self, mode: SyncMode) -> Optional[str]:
        """Cria ou assume lock expirado de forma atômica."""
        token = uuid.uuid4().hex
        payload = self._encode_lock(token, mode)

        try:
            db.session.add(SyncMetadata(key=self.LOCK_KEY, value=payload))
            db.session.commit()
            self._lock_token = token
            return token
        except IntegrityError:
            db.session.rollback()
        except Exception as exc:
            db.session.rollback()
            logger.warning('Failed to create NVD sync lock: %s', exc)
            return None

        existing = db.session.get(SyncMetadata, self.LOCK_KEY)
        existing_value = existing.value if existing else None
        if not self._lock_payload_expired(self._decode_lock(existing_value)):
            return None

        try:
            result = db.session.execute(
                update(SyncMetadata)
                .where(
                    SyncMetadata.key == self.LOCK_KEY,
                    SyncMetadata.value == existing_value,
                )
                .values(value=payload, last_modified=self._now_db())
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning('Failed to replace expired NVD sync lock: %s', exc)
            return None

        if result.rowcount:
            self._lock_token = token
            return token
        return None

    def _claim_reserved_lock(self, lock_token: str, mode: SyncMode) -> bool:
        existing = db.session.get(SyncMetadata, self.LOCK_KEY)
        payload = self._decode_lock(existing.value if existing else None)
        if payload.get('token') != lock_token:
            return False

        self._lock_token = lock_token
        self._refresh_sync_lock(mode=mode)
        return True

    def _refresh_sync_lock(self, mode: Optional[SyncMode] = None) -> None:
        if not self._lock_token:
            return

        existing = db.session.get(SyncMetadata, self.LOCK_KEY)
        current_payload = self._decode_lock(existing.value if existing else None)
        if current_payload.get('token') != self._lock_token:
            return

        try:
            refresh_mode = mode or SyncMode(current_payload.get('mode', SyncMode.INCREMENTAL.value))
        except ValueError:
            refresh_mode = SyncMode.INCREMENTAL
        new_value = self._encode_lock(self._lock_token, refresh_mode)
        try:
            db.session.execute(
                update(SyncMetadata)
                .where(
                    SyncMetadata.key == self.LOCK_KEY,
                    SyncMetadata.value == existing.value,
                )
                .values(value=new_value, last_modified=self._now_db())
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning('Failed to refresh NVD sync lock: %s', exc)

    def _release_sync_lock(self) -> None:
        if not self._lock_token:
            return

        existing = db.session.get(SyncMetadata, self.LOCK_KEY)
        payload = self._decode_lock(existing.value if existing else None)
        if payload.get('token') != self._lock_token:
            self._lock_token = None
            return

        try:
            db.session.delete(existing)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning('Failed to release NVD sync lock: %s', exc)
        finally:
            self._lock_token = None

    def _set_cancel_requested(self, requested: bool) -> None:
        SyncMetadata.set(self.CANCEL_KEY, 'true' if requested else 'false')

    def _is_cancel_requested(self) -> bool:
        if self._cancel_flag:
            return True
        if SyncMetadata.get(self.CANCEL_KEY, 'false') == 'true':
            return True
        return SyncMetadata.get(self._get_key('status')) == SyncStatus.CANCELLED.value

    @property
    def is_running(self) -> bool:
        """Verificar se sync está em execução."""
        status = SyncMetadata.get(self._get_key('status'))
        if status not in {SyncStatus.RUNNING.value, 'starting'}:
            return False

        lock_value = SyncMetadata.get(self.LOCK_KEY)
        payload = self._decode_lock(lock_value)
        return bool(payload) and not self._lock_payload_expired(payload)

    def get_sync_health(self, max_age_hours: Optional[int] = None) -> Dict:
        """Avalia se a base NVD local precisa ser sincronizada."""
        max_age_hours = max_age_hours or int(current_app.config.get('NVD_AUTO_SYNC_MAX_AGE_HOURS', 4))
        status = SyncMetadata.get(self._get_key('status')) or SyncStatus.IDLE.value
        last_sync_raw = SyncMetadata.get('nvd_last_successful_sync')
        last_sync = self._parse_datetime(last_sync_raw)
        running = self.is_running
        now = self._now()

        try:
            has_local_data = Vulnerability.query.limit(1).first() is not None
            latest_modified = db.session.query(db.func.max(Vulnerability.last_modified_date)).scalar()
        except Exception as exc:
            logger.warning('Unable to inspect NVD local database health: %s', exc)
            return {
                'needs_sync': False,
                'can_sync': False,
                'reason': 'database_unavailable',
                'status': status,
                'is_running': running,
                'last_sync': last_sync_raw,
                'max_age_hours': max_age_hours,
                'has_local_data': False,
                'latest_local_modified': None,
                'error': str(exc),
            }

        if latest_modified and latest_modified.tzinfo is None:
            latest_modified = latest_modified.replace(tzinfo=timezone.utc)

        reason = 'in_sync'
        needs_sync = False

        if running:
            reason = 'sync_running'
        elif status in {SyncStatus.FAILED.value, SyncStatus.CANCELLED.value}:
            reason = f'last_sync_{status}'
            needs_sync = True
        elif not has_local_data:
            reason = 'empty_database'
            needs_sync = True
        elif not last_sync:
            reason = 'never_synced'
            needs_sync = True
        elif now - last_sync > timedelta(hours=max_age_hours):
            reason = 'last_sync_too_old'
            needs_sync = True

        return {
            'needs_sync': needs_sync,
            'can_sync': True,
            'reason': reason,
            'status': status,
            'is_running': running,
            'last_sync': last_sync_raw,
            'max_age_hours': max_age_hours,
            'has_local_data': has_local_data,
            'latest_local_modified': latest_modified.isoformat() if latest_modified else None,
        }

    def reserve_sync(self, mode: SyncMode) -> Optional[str]:
        """Reserva o lock para um worker assíncrono assumir depois."""
        token = self._acquire_sync_lock(mode)
        if not token:
            return None

        self._set_cancel_requested(False)
        self._update_progress(
            status='starting',
            mode=mode.value,
            started_at=self._now().isoformat(),
            processed=0,
            processed_cves=0,
            total=0,
            total_cves=0,
            inserted=0,
            updated=0,
            errors=0,
            skipped=0,
            error=None,
            message='Sincronização enfileirada...',
        )
        return token

    @contextmanager
    def locked_operation(
        self,
        mode: SyncMode = SyncMode.CUSTOM,
        message: str = 'Operação NVD em execução...',
        lock_token: Optional[str] = None,
    ):
        """Run non-standard NVD write paths under the same persistent sync lock."""
        with self._lock:
            if lock_token:
                if not self._claim_reserved_lock(lock_token, mode):
                    raise NVDOperationAlreadyRunning('Lock reservado para operação NVD não é válido.')
            else:
                lock_token = self._acquire_sync_lock(mode)
                if not lock_token:
                    raise NVDOperationAlreadyRunning('Outra sincronização NVD já está em execução.')

            self._cancel_flag = False
            self._set_cancel_requested(False)
            self._update_progress(
                status=SyncStatus.RUNNING.value,
                mode=mode.value,
                started_at=self._now().isoformat(),
                processed=0,
                processed_cves=0,
                total=0,
                total_cves=0,
                inserted=0,
                updated=0,
                errors=0,
                skipped=0,
                error=None,
                message=message,
            )

        try:
            yield self
        except Exception as exc:
            if self._is_cancel_requested():
                self._mark_cancelled()
            else:
                self._update_progress(
                    status=SyncStatus.FAILED.value,
                    error=str(exc),
                    message=f'Falha na operação NVD: {exc}',
                    last_updated=self._now().isoformat(),
                )
            raise
        else:
            if self._is_cancel_requested():
                self._mark_cancelled()
            else:
                self._update_progress(
                    status=SyncStatus.COMPLETED.value,
                    message='Operação NVD concluída com sucesso.',
                    last_updated=self._now().isoformat(),
                )
                self._set_cancel_requested(False)
        finally:
            self._release_sync_lock()

    def cancel_sync(self) -> bool:
        """Cancelar sync em execução."""
        with self._lock:
            if not self.is_running:
                return False

            self._cancel_flag = True
            self._set_cancel_requested(True)
            self._update_progress(
                status=SyncStatus.CANCELLED.value,
                message='Cancelamento solicitado. A sincronização será interrompida no próximo checkpoint.',
            )
            logger.info('NVD sync cancellation requested')
            return True

    def start_sync(
        self,
        mode: SyncMode = SyncMode.INCREMENTAL,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        async_mode: bool = True,
        lock_token: Optional[str] = None,
    ) -> bool:
        """
        Iniciar sincronização.

        Args:
            mode: Modo de sincronização
            start_date: Data inicial (para CUSTOM)
            end_date: Data final (para CUSTOM)
            async_mode: Executar em thread separada
            lock_token: Token previamente reservado para Celery
        """
        with self._lock:
            if lock_token:
                if not self._claim_reserved_lock(lock_token, mode):
                    logger.warning('Reserved NVD sync lock is not valid')
                    return False
            else:
                lock_token = self._acquire_sync_lock(mode)
                if not lock_token:
                    logger.warning('NVD sync already running')
                    return False

            start_date, end_date = self._resolve_date_range(mode, start_date, end_date)
            if not start_date or not end_date:
                self._release_sync_lock()
                logger.error('Invalid NVD sync date range')
                return False

            self._cancel_flag = False
            self._set_cancel_requested(False)
            self._update_progress(
                status=SyncStatus.RUNNING.value,
                mode=mode.value,
                started_at=self._now().isoformat(),
                processed=0,
                processed_cves=0,
                total=0,
                total_cves=0,
                inserted=0,
                updated=0,
                errors=0,
                skipped=0,
                error=None,
                message='Iniciando sincronização...',
            )

            if async_mode:
                app = current_app._get_current_object()
                thread = threading.Thread(
                    target=self._run_sync,
                    args=(mode, start_date, end_date, app),
                    daemon=True,
                )
                thread.start()
            else:
                app = current_app._get_current_object()
                self._run_sync(mode, start_date, end_date, app)

            return True

    def _resolve_date_range(
        self,
        mode: SyncMode,
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        now = self._now()

        if mode == SyncMode.FULL:
            return datetime(1999, 1, 1, tzinfo=timezone.utc), now
        if mode == SyncMode.INITIAL:
            return now - timedelta(days=365), now
        if mode == SyncMode.INCREMENTAL:
            last_sync = self.db_service.get_last_sync_date()
            if last_sync:
                return last_sync - timedelta(hours=1), now
            return now - timedelta(days=1), now
        return start_date, end_date

    def _run_sync(
        self,
        mode: SyncMode,
        start_date: datetime,
        end_date: datetime,
        app=None,
    ) -> None:
        """Executar sincronização."""
        if app:
            with app.app_context():
                self._execute_sync_logic(mode, start_date, end_date)
        else:
            self._execute_sync_logic(mode, start_date, end_date)

    def _execute_sync_logic(self, mode: SyncMode, start_date: datetime, end_date: datetime) -> None:
        """Lógica interna de sincronização."""
        try:
            self.db_service.reset_stats()
            self._refresh_sync_lock(mode=mode)
            logger.info(
                'Starting NVD sync: mode=%s, range=%s to %s',
                mode.value,
                start_date.date(),
                end_date.date(),
            )

            if mode == SyncMode.FULL:
                self._calculate_full_sync_total(start_date, end_date)

            if self._is_cancel_requested():
                self._mark_cancelled()
                return

            if mode == SyncMode.INCREMENTAL:
                self._run_incremental_sync(start_date, end_date)
            else:
                self._run_windowed_sync(start_date, end_date, is_full_sync=(mode == SyncMode.FULL))

            if self._is_cancel_requested():
                self._mark_cancelled()
                return

            watermark = end_date.isoformat()
            self.db_service.update_sync_metadata('nvd_last_successful_sync', watermark)
            self.db_service.update_sync_metadata('nvd_last_sync_date', watermark)

            if mode == SyncMode.FULL:
                self.db_service.update_sync_metadata('nvd_first_sync_completed', 'true')

            self._update_progress(
                status=SyncStatus.COMPLETED.value,
                message='Sincronização concluída com sucesso.',
                last_updated=self._now().isoformat(),
            )
            self._set_cancel_requested(False)
            logger.info('NVD sync completed successfully')

        except Exception as exc:
            logger.error('NVD sync failed: %s', exc)
            self._update_progress(
                status=SyncStatus.FAILED.value,
                error=str(exc),
                message=f'Falha na sincronização: {exc}',
            )
        finally:
            self._release_sync_lock()

    def _calculate_full_sync_total(self, start_date: datetime, end_date: datetime) -> None:
        """Calcula o total sem apagar os dados existentes."""
        logger.info('Calculating total CVEs to fetch for full sync...')
        windows = self.fetcher.generate_date_windows(start_date, end_date)
        grand_total = 0

        for index, (window_start, window_end) in enumerate(windows):
            if self._is_cancel_requested():
                break
            try:
                response = self.fetcher.fetch_page(
                    results_per_page=1,
                    pub_start_date=window_start,
                    pub_end_date=window_end,
                )
                if response:
                    grand_total += response.total_results
                    self._update_progress(total=grand_total, total_cves=grand_total)
                    self._refresh_sync_lock(mode=SyncMode.FULL)
            except Exception as exc:
                logger.error('Error calculating full-sync total for window %s: %s', index, exc)

        logger.info('Grand total CVEs to fetch: %s', grand_total)
        self._update_progress(total=grand_total, total_cves=grand_total)

    def _mark_cancelled(self) -> None:
        self._update_progress(
            status=SyncStatus.CANCELLED.value,
            message='Sincronização cancelada.',
            last_updated=self._now().isoformat(),
        )
        logger.info('NVD sync cancelled')

    def _run_incremental_sync(self, start_date: datetime, end_date: datetime) -> None:
        """Sync incremental usando lastModified."""
        logger.info('Running incremental NVD sync from %s to %s', start_date, end_date)

        vulnerabilities = self.fetcher.fetch_all_pages(
            last_mod_start_date=start_date,
            last_mod_end_date=end_date,
            progress_callback=self._fetch_progress_callback,
            cancel_callback=self._is_cancel_requested,
        )

        if self._is_cancel_requested():
            return

        self._update_progress(total=len(vulnerabilities), total_cves=len(vulnerabilities))

        self.db_service.process_vulnerabilities(
            vulnerabilities,
            progress_callback=self._db_progress_callback,
        )

        if self._is_cancel_requested():
            return

        self._generate_alerts(vulnerabilities)

    def _generate_alerts(self, vulnerabilities: list[Dict]) -> None:
        try:
            logger.info('Generating alerts for incremental NVD sync...')
            cve_ids = [
                item.get('cve', {}).get('id')
                for item in vulnerabilities
                if item.get('cve', {}).get('id')
            ]
            cve_ids = list(dict.fromkeys(cve_ids))

            chunk_size = 100
            total_processed = 0
            for index in range(0, len(cve_ids), chunk_size):
                if self._is_cancel_requested():
                    return
                chunk_ids = cve_ids[index:index + chunk_size]
                with self.db_service.bulk_session() as session:
                    vulns = session.query(Vulnerability).filter(Vulnerability.cve_id.in_(chunk_ids)).all()
                    for vuln in vulns:
                        AlertService.process_new_vulnerability(vuln)
                    total_processed += len(vulns)

            logger.info('Alert generation completed. Processed %s vulnerabilities.', total_processed)
        except Exception as exc:
            logger.error('Error generating alerts: %s', exc)

    def _run_windowed_sync(
        self,
        start_date: datetime,
        end_date: datetime,
        is_full_sync: bool = False,
    ) -> None:
        """Sync com janelas de 120 dias."""
        windows = self.fetcher.generate_date_windows(start_date, end_date)
        total_windows = len(windows)

        logger.info('Running NVD windowed sync with %s windows', total_windows)

        self._update_progress(current_window=0, total_windows=total_windows)
        global_processed = (self.get_progress().get('processed_cves') or 0) if is_full_sync else 0

        for index, (window_start, window_end) in enumerate(windows):
            if self._is_cancel_requested():
                break

            logger.info(
                'Processing NVD window %s/%s: %s to %s',
                index + 1,
                total_windows,
                window_start.date(),
                window_end.date(),
            )
            self._update_progress(
                current_window=index + 1,
                message=f'Processing window {index + 1}/{total_windows}: {window_start.date()} to {window_end.date()}',
            )
            self._refresh_sync_lock(mode=SyncMode.FULL if is_full_sync else SyncMode.INITIAL)

            def progress_callback(current: int, total: int) -> None:
                if is_full_sync:
                    self._update_progress(
                        processed=global_processed + current,
                        processed_cves=global_processed + current,
                        last_updated=self._now().isoformat(),
                    )
                    return
                self._fetch_progress_callback(current, total)

            vulnerabilities = self.fetcher.fetch_all_pages(
                pub_start_date=window_start,
                pub_end_date=window_end,
                progress_callback=progress_callback,
                cancel_callback=self._is_cancel_requested,
            )

            if self._is_cancel_requested():
                break

            self.db_service.process_vulnerabilities(
                vulnerabilities,
                progress_callback=self._db_progress_callback,
            )

            if is_full_sync:
                global_processed += len(vulnerabilities)
                self._update_progress(processed=global_processed, processed_cves=global_processed)

            self.db_service.update_sync_metadata('nvd_sync_checkpoint', window_end.isoformat())

    def _fetch_progress_callback(self, current: int, total: int) -> None:
        """Callback de progresso do fetch."""
        self._update_progress(
            processed=current,
            processed_cves=current,
            total=total,
            total_cves=total,
            last_updated=self._now().isoformat(),
        )
        self._refresh_sync_lock()

    def _db_progress_callback(self, processed: int, total: int, stats: Dict = None) -> None:
        """Callback de progresso do banco."""
        updates = {
            'processed': processed,
            'processed_cves': processed,
            'last_updated': self._now().isoformat(),
        }

        if stats:
            updates.update(
                {
                    'inserted': stats.get('inserted', 0),
                    'updated': stats.get('updated', 0),
                    'errors': stats.get('errors', 0),
                    'skipped': stats.get('skipped', 0),
                }
            )

        self._update_progress(**updates)
        self._refresh_sync_lock()


def trigger_nvd_sync(mode: str = 'incremental') -> bool:
    """
    Função helper para disparar sync.

    Usa Celery quando o app estiver configurado com worker; caso contrário,
    mantém o fallback local assíncrono para ambiente de desenvolvimento.
    """
    sync_mode = SyncMode(mode)
    service = NVDSyncService()

    try:
        from app.extensions.celery_extension import CELERY_AVAILABLE
        from app.tasks.nvd import sync_nvd_task

        testing = bool(current_app.config.get('TESTING', False))
        eager = bool(current_app.config.get('CELERY_TASK_ALWAYS_EAGER', False))
        can_dispatch = (
            CELERY_AVAILABLE
            and hasattr(sync_nvd_task, 'delay')
            and not testing
            and not eager
        )

        if can_dispatch:
            token = service.reserve_sync(sync_mode)
            if not token:
                return False
            try:
                result = sync_nvd_task.delay(mode=sync_mode.value, lock_token=token)
                SyncMetadata.set(service.TASK_ID_KEY, getattr(result, 'id', None))
                return True
            except Exception as exc:
                logger.error('Failed to dispatch NVD sync task: %s', exc)
                service._update_progress(
                    status=SyncStatus.FAILED.value,
                    error=str(exc),
                    message=f'Falha ao enfileirar sincronização: {exc}',
                )
                service._release_sync_lock()
                return False
    except Exception as exc:
        logger.warning('Celery dispatch unavailable for NVD sync: %s', exc)

    return service.start_sync(mode=sync_mode, async_mode=True)


def ensure_nvd_sync_if_needed(async_mode: bool = True, dispatch: bool = True) -> tuple[bool, Dict]:
    """Força sync incremental quando a base local está fora de sincronia."""
    service = NVDSyncService()
    health = service.get_sync_health()

    SyncMetadata.set(service.AUTO_SYNC_LAST_REASON_KEY, health.get('reason'))

    if not health.get('needs_sync') or health.get('is_running') or not health.get('can_sync', True):
        return False, health

    logger.info('NVD local database is out of sync: %s', health.get('reason'))
    if dispatch:
        return trigger_nvd_sync(mode=SyncMode.INCREMENTAL.value), health

    return service.start_sync(mode=SyncMode.INCREMENTAL, async_mode=async_mode), health
