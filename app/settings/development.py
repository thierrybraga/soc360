"""
SOC360 Development Settings
Configurations optimized for local development.
"""
import os
from app.settings.base import BaseConfig


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
    
    # Re-define URIs to use local hosts (overriding BaseConfig)
    SQLALCHEMY_DATABASE_URI = f"postgresql://{BaseConfig.DB_CORE_USER}:{BaseConfig.DB_CORE_PASSWORD}@{DB_CORE_HOST}:{BaseConfig.DB_CORE_PORT}/{BaseConfig.DB_CORE_NAME}"
    
    SQLALCHEMY_BINDS = {
        'public': f"postgresql://{BaseConfig.DB_PUBLIC_USER}:{BaseConfig.DB_PUBLIC_PASSWORD}@{DB_PUBLIC_HOST}:{os.environ.get('DB_PUBLIC_PORT', BaseConfig.DB_PUBLIC_PORT)}/{BaseConfig.DB_PUBLIC_NAME}"
    }

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
    basedir = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    db_path = os.path.join(basedir, 'instance', 'app.db')

    if os.environ.get('USE_SQLITE') or not os.environ.get('DB_CORE_HOST') or not os.path.exists(db_path):
        # If no DB host configured or explicitly requested, use SQLite
        # However, maintain compatibility: if app.db doesn't exist, force SQLite
        # for automatic initialization.
        print(f"DEBUG: Enabling SQLite Mode (DB Path: {db_path})")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + db_path
        SQLALCHEMY_BINDS = {
            'public': 'sqlite:///' + db_path
        }
        # SQLite não suporta pool_size/pool_recycle; StaticPool evita erros de thread
        from sqlalchemy.pool import StaticPool
        SQLALCHEMY_ENGINE_OPTIONS = {
            'connect_args': {'check_same_thread': False},
            'poolclass': StaticPool,
        }
        # Disable Redis if using SQLite mode
        # REDIS_URL = None # Keep Redis if available, but Celery can use DB
        if os.environ.get('USE_SQLITE'):
            CELERY_BROKER_URL = 'memory://'
            CELERY_RESULT_BACKEND = 'db+sqlite:///' + os.path.join(basedir, 'instance', 'celery.db')

    @staticmethod
    def _is_postgres_available(uri, timeout=3):
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(uri, pool_pre_ping=True, connect_args={'connect_timeout': timeout})
            with engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            return True
        except Exception:
            return False

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
    
    # Force localhost for testing if not set
    DB_CORE_HOST = os.environ.get('DB_CORE_HOST', 'localhost')
    DB_PUBLIC_HOST = os.environ.get('DB_PUBLIC_HOST', 'localhost')
    
    # Re-define URIs to use local hosts
    SQLALCHEMY_DATABASE_URI = f"postgresql://{BaseConfig.DB_CORE_USER}:{BaseConfig.DB_CORE_PASSWORD}@{DB_CORE_HOST}:{BaseConfig.DB_CORE_PORT}/{BaseConfig.DB_CORE_NAME}"
    
    SQLALCHEMY_BINDS = {
        'public': f"postgresql://{BaseConfig.DB_PUBLIC_USER}:{BaseConfig.DB_PUBLIC_PASSWORD}@{DB_PUBLIC_HOST}:{BaseConfig.DB_PUBLIC_PORT}/{BaseConfig.DB_PUBLIC_NAME}"
    }
    
    # Use SQLite in-memory for tests ONLY if explicitly requested or if no DB configured
    # Otherwise, respect BaseConfig (PostgreSQL)
    if os.environ.get('USE_SQLITE_TEST'):
        SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        SQLALCHEMY_BINDS = {
            'public': 'sqlite:///:memory:'
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
