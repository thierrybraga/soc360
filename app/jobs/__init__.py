"""
SOC360 Jobs Package
Background jobs and data fetchers.
"""

from .fetchers import *
from .dispatchers import *
from .report_generation import trigger_report_generation


def trigger_nvd_sync(full_sync=False, mode=None):
    """Dispara sincronizacao NVD sem executar side effects no import."""
    from app.services.nvd.nvd_sync_service import trigger_nvd_sync as service_trigger_nvd_sync

    sync_mode = mode or ('full' if full_sync else 'incremental')
    return service_trigger_nvd_sync(mode=sync_mode)


__all__ = ['trigger_nvd_sync', 'trigger_report_generation']
