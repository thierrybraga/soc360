"""
SOC360 Extensions Module
Inicialização centralizada de todas as extensões Flask.
"""
from app.extensions.db import db, migrate
from app.extensions.login import login_manager
from app.extensions.csrf import csrf, init_csrf, get_csrf, exempt_csrf
from app.utils.security import (
    admin_required,
    role_required,
    owner_required,
    owner_or_admin_required,
    api_key_required
)
from app.extensions.celery_extension import celery, init_celery
from app.utils.security.headers import security_headers
__all__ = [
    # Database
    'db',
    'migrate',
    
    # Login
    'login_manager',


    # CSRF
    'csrf',
    'init_csrf',
    'get_csrf',
    'exempt_csrf',
    
    # Permissions
    'admin_required',
    'role_required',
    'owner_required',
    'owner_or_admin_required',
    'api_key_required',
    
    # Celery
    'celery'
]
