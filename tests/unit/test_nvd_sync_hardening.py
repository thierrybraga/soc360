"""
Tests for NVD sync orchestration hardening.
"""
import inspect
from datetime import datetime, timedelta, timezone

import pytest


def _make_uninitialized_service():
    from app.services.nvd.nvd_sync_service import NVDSyncService

    service = NVDSyncService.__new__(NVDSyncService)
    service.prefix = 'nvd'
    service._cancel_flag = False
    return service


def test_nvd_cancel_check_uses_persistent_metadata(monkeypatch):
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import NVDSyncService

    def fake_get(key, default=None):
        if key == NVDSyncService.CANCEL_KEY:
            return 'true'
        return default

    monkeypatch.setattr(SyncMetadata, 'get', fake_get)
    service = _make_uninitialized_service()

    assert service._is_cancel_requested() is True


def test_nvd_is_running_requires_active_persistent_lock(monkeypatch):
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import NVDSyncService, SyncMode

    lock_value = NVDSyncService._encode_lock('token', SyncMode.INCREMENTAL)

    def fake_get(key, default=None):
        values = {
            'nvd_sync_progress_status': 'running',
            NVDSyncService.LOCK_KEY: lock_value,
        }
        return values.get(key, default)

    monkeypatch.setattr(SyncMetadata, 'get', fake_get)
    service = _make_uninitialized_service()

    assert service.is_running is True


def test_full_sync_no_longer_clears_data_before_fetch():
    from app.services.nvd.nvd_sync_service import NVDSyncService

    source = inspect.getsource(NVDSyncService._execute_sync_logic)
    assert 'clear_all_data' not in source


def test_bulk_dedupe_preserves_last_record():
    from app.services.nvd.bulk_database_service import _dedupe

    records = [
        {'cve_id': 'CVE-2024-0001', 'value': 'old'},
        {'cve_id': 'CVE-2024-0002', 'value': 'kept'},
        {'cve_id': 'CVE-2024-0001', 'value': 'new'},
    ]

    deduped = _dedupe(records, ('cve_id',))

    assert deduped == [
        {'cve_id': 'CVE-2024-0001', 'value': 'new'},
        {'cve_id': 'CVE-2024-0002', 'value': 'kept'},
    ]


def test_child_tables_define_natural_unique_constraints():
    from app.models.nvd import AffectedProduct, Credit

    credit_constraints = {constraint.name for constraint in Credit.__table__.constraints}
    product_constraints = {constraint.name for constraint in AffectedProduct.__table__.constraints}

    assert 'uq_credit_cve_value_type_user' in credit_constraints
    assert 'uq_affected_product_cve_vendor_product' in product_constraints


def test_nvd_sync_health_detects_empty_database(db):
    from app.models.nvd import AffectedProduct, Credit, CvssMetric, Reference, Vulnerability, Weakness
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import NVDSyncService

    for model in (AffectedProduct, Credit, CvssMetric, Reference, Weakness, Vulnerability):
        db.session.query(model).delete()
    db.session.commit()
    SyncMetadata.set('nvd_sync_progress_status', 'completed')
    SyncMetadata.set('nvd_last_successful_sync', '2026-01-01T00:00:00+00:00')

    health = NVDSyncService().get_sync_health(max_age_hours=4)

    assert health['needs_sync'] is True
    assert health['reason'] == 'empty_database'


def test_nvd_sync_health_accepts_fresh_local_database(db):
    from datetime import datetime, timezone

    from app.models.nvd import AffectedProduct, Credit, CvssMetric, Reference, Vulnerability, Weakness
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import NVDSyncService

    for model in (AffectedProduct, Credit, CvssMetric, Reference, Weakness, Vulnerability):
        db.session.query(model).delete()
    db.session.add(Vulnerability(cve_id='CVE-2026-9999', description='fresh'))
    db.session.commit()
    SyncMetadata.set('nvd_sync_progress_status', 'completed')
    SyncMetadata.set('nvd_last_successful_sync', datetime.now(timezone.utc).isoformat())

    health = NVDSyncService().get_sync_health(max_age_hours=4)

    assert health['needs_sync'] is False
    assert health['reason'] == 'in_sync'


def test_ensure_nvd_sync_if_needed_dispatches_incremental(monkeypatch, db):
    import app.services.nvd.nvd_sync_service as module

    calls = []

    monkeypatch.setattr(
        module.NVDSyncService,
        'get_sync_health',
        lambda self: {
            'needs_sync': True,
            'can_sync': True,
            'is_running': False,
            'reason': 'last_sync_too_old',
        },
    )
    monkeypatch.setattr(module, 'trigger_nvd_sync', lambda mode='incremental': calls.append(mode) or True)

    started, health = module.ensure_nvd_sync_if_needed(async_mode=True, dispatch=True)

    assert started is True
    assert health['reason'] == 'last_sync_too_old'
    assert calls == ['incremental']


def test_nvd_fetch_all_pages_raises_on_intermediate_failure():
    from app.jobs.fetchers.nvd_client import NVDDownloadError, NVDFetcher
    from app.jobs.fetchers.nvd_types import NVDResponse

    fetcher = NVDFetcher.__new__(NVDFetcher)
    responses = [
        NVDResponse(
            vulnerabilities=[
                {'cve': {'id': 'CVE-2026-0001'}},
                {'cve': {'id': 'CVE-2026-0002'}},
            ],
            results_per_page=2,
            start_index=0,
            total_results=3,
            timestamp=datetime.now(timezone.utc),
        ),
        None,
    ]

    def fake_fetch_page(**kwargs):
        return responses.pop(0)

    fetcher.fetch_page = fake_fetch_page

    with pytest.raises(NVDDownloadError):
        fetcher.fetch_all_pages()


def test_nvd_date_windows_do_not_leave_boundary_gap():
    from app.jobs.fetchers.nvd_client import NVDFetcher

    fetcher = NVDFetcher.__new__(NVDFetcher)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=240, seconds=1)

    windows = fetcher.generate_date_windows(start, end)

    assert len(windows) == 3
    for previous, current in zip(windows, windows[1:]):
        assert current[0] == previous[1]


def test_nvd_locked_operation_blocks_concurrent_writers(db):
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import (
        NVDOperationAlreadyRunning,
        NVDSyncService,
    )

    first = NVDSyncService()
    second = NVDSyncService()

    with first.locked_operation(message='test operation'):
        with pytest.raises(NVDOperationAlreadyRunning):
            with second.locked_operation(message='concurrent operation'):
                pass

    assert SyncMetadata.get(NVDSyncService.LOCK_KEY) is None


def test_nvd_locked_operation_accepts_reserved_token(db):
    from app.models.system import SyncMetadata
    from app.services.nvd.nvd_sync_service import NVDSyncService, SyncMode

    reserver = NVDSyncService()
    worker = NVDSyncService()
    token = reserver.reserve_sync(SyncMode.CUSTOM)

    assert token

    with worker.locked_operation(
        mode=SyncMode.CUSTOM,
        message='reserved operation',
        lock_token=token,
    ):
        assert worker._lock_token == token

    assert SyncMetadata.get(NVDSyncService.LOCK_KEY) is None


def test_nvd_bulk_processing_raises_on_batch_error(monkeypatch):
    from app.services.nvd.bulk_database_service import BulkDatabaseService

    service = BulkDatabaseService()

    def fail_batch(batch):
        raise RuntimeError('db batch failed')

    monkeypatch.setattr(service, '_process_batch', fail_batch)

    with pytest.raises(RuntimeError, match='db batch failed'):
        service.process_vulnerabilities([{'cve': {'id': 'CVE-2026-0001'}}])

    assert service.stats['errors'] == 1
