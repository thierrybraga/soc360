# app/services/monitoring/__init__.py

try:
    from .alert_service import AlertService
except ImportError:
    AlertService = None

__all__ = ['AlertService']
