"""
SOC360 Development Settings
Configurations optimized for local development.
"""
import os
from app.settings.base import BaseConfig
from app.settings.database import DEFAULT_SQLITE_PATH, sqlite_database_config


class DevelopmentConfig(BaseConfig):
    """Development configurations."""
    
    DEBUG = True
    TESTING = False
    
    # Security - Relaxed for development
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    CSP_ENABLED = False  # Disable CSP in dev to avoid rendering issues
    
    # Development database - can use SQLite for quick tests
    DB_CORE_HOST = os.environ.get('DB_CORE_HOST', 'localhost')
    DB_PUBLIC_HOST = os.environ.get('DB_PUBLIC_HOST', 'localhost')
    
    # Redis - localhost
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
    
    # Performance - Development friendly
    TEMPLATES_AUTO_RELOAD = True
    SEND_FILE_MAX_AGE_DEFAULT = 0
    
    # Database pool - smaller for development
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 5,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'echo': False,  # Set True to see SQL queries
    }
    
    # SQLite fallback support - Enabled by default if file exists or USE_SQLITE is set
    db_path = str(DEFAULT_SQLITE_PATH)

    if os.environ.get('USE_SQLITE') or not os.environ.get('DB_CORE_HOST') or not os.path.exists(db_path):
        # If no DB host configured or explicitly requested, use SQLite
        # However, maintain compatibility: if app.db doesn't exist, force SQLite
        # for automatic initialization.
        SQLALCHEMY_DATABASE_URI, SQLALCHEMY_BINDS = sqlite_database_config(db_path)
        # Disable Redis if using SQLite mode
        # REDIS_URL = None # Keep Redis if available, but Celery can use DB
        if os.environ.get('USE_SQLITE'):
            CELERY_BROKER_URL = 'memory://'
            CELERY_RESULT_BACKEND = 'db+sqlite:///' + os.path.join(os.path.dirname(db_path), 'celery.db')

    @classmethod
    def init_app(cls, app):
        """Development-specific initialization."""
        # Check if configured PostgreSQL is accessible; if not, use SQLite fallback.
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        cls.fallback_to_sqlite(app, db_uri)


class TestingConfig(BaseConfig):
    """Configurations for automated tests."""
    
    DEBUG = True
    TESTING = True
    
    # Tests are isolated and never depend on an external PostgreSQL service.
    SQLALCHEMY_DATABASE_URI, SQLALCHEMY_BINDS = sqlite_database_config(':memory:')
    from sqlalchemy.pool import StaticPool
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {'check_same_thread': False},
        'poolclass': StaticPool,
    }
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Disable rate limiting for tests
    RATE_LIMIT_LOGIN_ATTEMPTS = 1000
    RATE_LIMIT_API_REQUESTS = 10000
    
    # Use lower bcrypt rounds for faster tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Disable Redis caching
    CACHE_DEFAULT_TTL = 0
    NVD_AUTO_SYNC_ENABLED = False
    
    @classmethod
    def init_app(cls, app):
        """Inicialização específica de testes."""
        pass
