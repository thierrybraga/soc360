"""
SOC360 SyncMetadata Model
Armazena metadados de sincronização com APIs externas.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from app.extensions.db import db


def _utcnow_naive():
    """Return UTC now as naive datetime for existing DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SyncMetadata(db.Model):
    """
    Armazena metadados de sincronização.
    
    Chaves utilizadas:
    - nvd_sync_progress_status: Status atual do sync (IDLE, RUNNING, COMPLETED, FAILED)
    - nvd_sync_progress_current: Página/janela atual sendo processada
    - nvd_sync_progress_total: Total de páginas/janelas a processar
    - nvd_first_sync_completed: Se o primeiro sync completo foi realizado
    - nvd_last_sync_date: Data do último sync bem-sucedido
    - nvd_last_modified_date: Última data de modificação processada
    - cisa_kev_last_sync: Último sync do CISA KEV
    - system_initialized: Se o sistema foi inicializado
    """
    __tablename__ = 'sync_metadata'
    
    key = Column(String(255), primary_key=True)
    value = Column(Text(), nullable=True)
    last_modified = Column(
        DateTime,
        default=_utcnow_naive,
        onupdate=_utcnow_naive,
        nullable=False
    )
    
    # Constantes para chaves conhecidas
    KEY_SYNC_STATUS = 'nvd_sync_progress_status'
    KEY_SYNC_CURRENT = 'nvd_sync_progress_current'
    KEY_SYNC_TOTAL = 'nvd_sync_progress_total'
    KEY_SYNC_MESSAGE = 'nvd_sync_progress_message'
    KEY_FIRST_SYNC_COMPLETED = 'nvd_first_sync_completed'
    KEY_LAST_SYNC_DATE = 'nvd_last_sync_date'
    KEY_LAST_MODIFIED_DATE = 'nvd_last_modified_date'
    KEY_CISA_KEV_LAST_SYNC = 'cisa_kev_last_sync'
    KEY_SYSTEM_INITIALIZED = 'system_initialized'
    KEY_ROOT_USER_CREATED = 'root_user_created'
    
    @classmethod
    def get_value(cls, key, default=None):
        """Alias para get (compatibilidade)."""
        return cls.get(key, default)

    @classmethod
    def set_value(cls, key, value):
        """Alias para set (compatibilidade)."""
        return cls.set(key, value)

    @classmethod
    def get(cls, key, default=None):
        """Obtém valor de uma chave."""
        metadata = db.session.get(cls, key)
        if metadata:
            return metadata.value
        return default

    @classmethod
    def set(cls, key, value):
        """Define valor de uma chave (cria ou atualiza). Tolerante a falha."""
        try:
            metadata = db.session.get(cls, key)
            if metadata:
                metadata.value = str(value) if value is not None else None
                metadata.last_modified = _utcnow_naive()
            else:
                metadata = cls(key=key, value=str(value) if value is not None else None)
                db.session.add(metadata)
            db.session.commit()
            return metadata
        except Exception as e:
            # Rollback to unstick the session so subsequent writes don't
            # fail with PendingRollbackError. This is vital for sync jobs
            # running on SQLite where transient locks can occur.
            import logging
            logging.getLogger(__name__).warning(
                "SyncMetadata.set failed for key=%s: %s", key, e
            )
            try:
                db.session.rollback()
            except Exception:
                pass
            return None

    @classmethod
    def set_multi(cls, data: dict):
        """Define múltiplos valores de uma vez. Tolerante a falha."""
        if not data:
            return

        try:
            for key, value in data.items():
                metadata = db.session.get(cls, key)
                if metadata:
                    metadata.value = str(value) if value is not None else None
                    metadata.last_modified = _utcnow_naive()
                else:
                    metadata = cls(key=key, value=str(value) if value is not None else None)
                    db.session.add(metadata)

            db.session.commit()
        except Exception as e:
            # Rollback to keep the session usable even if the commit failed
            # (e.g. SQLite "database is locked" races). Progress updates are
            # best-effort — losing one should never break the sync.
            import logging
            logging.getLogger(__name__).warning(
                "SyncMetadata.set_multi failed (%d keys): %s", len(data), e
            )
            try:
                db.session.rollback()
            except Exception:
                pass

    @classmethod
    def delete(cls, key):
        """Remove uma chave."""
        metadata = db.session.get(cls, key)
        if metadata:
            db.session.delete(metadata)
            db.session.commit()
            return True
        return False
    
    @classmethod
    def get_sync_progress(cls):
        """Retorna progresso atual do sync NVD."""
        return {
            'status': cls.get(cls.KEY_SYNC_STATUS, 'IDLE'),
            'current': int(cls.get(cls.KEY_SYNC_CURRENT, 0)),
            'total': int(cls.get(cls.KEY_SYNC_TOTAL, 0)),
            'message': cls.get(cls.KEY_SYNC_MESSAGE, ''),
            'first_sync_completed': cls.get(cls.KEY_FIRST_SYNC_COMPLETED, 'false') == 'true',
            'last_sync_date': cls.get(cls.KEY_LAST_SYNC_DATE)
        }
    
    @classmethod
    def update_sync_progress(cls, status=None, current=None, total=None, message=None):
        """Atualiza progresso do sync."""
        if status is not None:
            cls.set(cls.KEY_SYNC_STATUS, status)
        if current is not None:
            cls.set(cls.KEY_SYNC_CURRENT, current)
        if total is not None:
            cls.set(cls.KEY_SYNC_TOTAL, total)
        if message is not None:
            cls.set(cls.KEY_SYNC_MESSAGE, message)
    
    @classmethod
    def mark_first_sync_completed(cls):
        """Marca que o primeiro sync foi completado."""
        cls.set(cls.KEY_FIRST_SYNC_COMPLETED, 'true')
        cls.set(cls.KEY_LAST_SYNC_DATE, _utcnow_naive().isoformat())
    
    @classmethod
    def is_system_initialized(cls):
        """Verifica se o sistema foi inicializado."""
        return cls.get(cls.KEY_SYSTEM_INITIALIZED, 'false') == 'true'
    
    @classmethod
    def mark_system_initialized(cls):
        """Marca sistema como inicializado."""
        cls.set(cls.KEY_SYSTEM_INITIALIZED, 'true')
    
    def __repr__(self):
        return f"<SyncMetadata(key='{self.key}', value='{self.value[:50] if self.value else None}...')>"
