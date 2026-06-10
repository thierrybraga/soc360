"""
SOC360 Base Settings
Shared configurations across all environments.
"""
import os
from datetime import timedelta
from urllib.parse import quote as _urlquote


class BaseConfig:
    """Base configurations for SOC360."""
    
    # Application
    APP_NAME = "SOC360"
    APP_VERSION = "3.0.0"
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    WTF_CSRF_ENABLED = True
    # Token is tied to the Flask session — no separate time-based expiry
    # (session lifetime controls the token lifetime). Prevents false-positive
    # "CSRF token expired" errors when the user leaves a tab/modal open.
    WTF_CSRF_TIME_LIMIT = None
    # Headers accepted by Flask-WTF for token lookup (first match wins)
    WTF_CSRF_HEADERS = ['X-CSRFToken', 'X-CSRF-Token', 'X-XSRF-TOKEN']
    # Não exigir checagem de Referer em HTTPS. Atrás de um proxy que termina TLS
    # (nginx), a checagem SSL-strict de Referer é frágil (depende de Referrer-
    # Policy do browser/extensões) e pode bloquear o login em loop. O próprio
    # token CSRF (ligado à sessão) continua sendo a proteção efetiva.
    WTF_CSRF_SSL_STRICT = False

    # Session
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # 8h sliding session — long enough to cover a normal workday of reports
    # without the CSRF token silently dying while a modal is open.
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    # Refresh the cookie expiry on every request so idle time inside the app
    # does not expire the session mid-workflow.
    SESSION_REFRESH_EACH_REQUEST = True
    
    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # Database URLs
    DB_CORE_HOST = os.environ.get('DB_CORE_HOST', 'postgres_core')
    DB_CORE_PORT = os.environ.get('DB_CORE_PORT', '5432')
    DB_CORE_NAME = os.environ.get('DB_CORE_NAME', 'soc360_core')
    DB_CORE_USER = os.environ.get('DB_CORE_USER', 'soc360')
    DB_CORE_PASSWORD = os.environ.get('DB_CORE_PASSWORD', 'change_me')
    
    DB_PUBLIC_HOST = os.environ.get('DB_PUBLIC_HOST', 'postgres_public')
    DB_PUBLIC_PORT = os.environ.get('DB_PUBLIC_PORT', '5432')
    DB_PUBLIC_NAME = os.environ.get('DB_PUBLIC_NAME', 'soc360_public')
    DB_PUBLIC_USER = os.environ.get('DB_PUBLIC_USER', 'soc360')
    DB_PUBLIC_PASSWORD = os.environ.get('DB_PUBLIC_PASSWORD', 'change_me')
    
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_CORE_USER}:{DB_CORE_PASSWORD}@{DB_CORE_HOST}:{DB_CORE_PORT}/{DB_CORE_NAME}"
    
    # 'core' é o bind DEFAULT (SQLALCHEMY_DATABASE_URI acima); apenas 'public'
    # é um bind nomeado. Evita duplicar o engine do core e o footgun de
    # autogenerate do Alembic (default == core).
    SQLALCHEMY_BINDS = {
        'public': f"postgresql://{DB_PUBLIC_USER}:{DB_PUBLIC_PASSWORD}@{DB_PUBLIC_HOST}:{DB_PUBLIC_PORT}/{DB_PUBLIC_NAME}"
    }
    
    # Redis
    REDIS_HOST = os.environ.get('REDIS_HOST', 'redis')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
    # URL-encode the password so special chars like # $ @ don't break URL parsing
    _redis_pw_encoded = _urlquote(REDIS_PASSWORD, safe='') if REDIS_PASSWORD else None
    _redis_auth = f":{_redis_pw_encoded}@" if _redis_pw_encoded else ""
    REDIS_URL = os.environ.get('REDIS_URL', f"redis://{_redis_auth}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
    CACHE_DEFAULT_TTL = 900  # 15 minutes

    # Celery
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', f"redis://{_redis_auth}{REDIS_HOST}:{REDIS_PORT}/1")
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', f"redis://{_redis_auth}{REDIS_HOST}:{REDIS_PORT}/2")
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TIMEZONE = 'UTC'
    
    try:
        from celery.schedules import crontab
        CELERY_BEAT_SCHEDULE = {
            'sync-nvd-incremental': {
                'task': 'nvd.sync',
                'schedule': crontab(minute=0, hour='*/4'),  # Every 4 hours
                'args': ('incremental',)
            },
            'ensure-nvd-sync-if-stale': {
                'task': 'nvd.ensure_sync',
                'schedule': crontab(minute='*/15'),
            },
        }
    except ImportError:
        CELERY_BEAT_SCHEDULE = {}
    
    # NVD API
    NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.environ.get('NVD_API_KEY', None)
    NVD_RATE_LIMIT_WITH_KEY = 50  # requests per 30 seconds
    NVD_RATE_LIMIT_WITHOUT_KEY = 5  # requests per 30 seconds
    NVD_SYNC_WINDOW_DAYS = 120  # NVD API limit
    NVD_INCREMENTAL_DAYS = 30
    NVD_RESULTS_PER_PAGE = 2000
    NVD_AUTO_SYNC_ENABLED = os.environ.get('NVD_AUTO_SYNC_ENABLED', 'true').lower() == 'true'
    NVD_AUTO_SYNC_MAX_AGE_HOURS = int(os.environ.get('NVD_AUTO_SYNC_MAX_AGE_HOURS', 4))
    NVD_AUTO_SYNC_CHECK_INTERVAL_SECONDS = int(os.environ.get('NVD_AUTO_SYNC_CHECK_INTERVAL_SECONDS', 900))
    
    # ── AI Provider ────────────────────────────────────────────────────────
    # AI_PROVIDER: 'openai' (padrão, demo mode sem chave) | 'ollama' (local)
    AI_PROVIDER = os.environ.get('AI_PROVIDER', 'openai')

    # Ollama (local)
    OLLAMA_BASE_URL   = os.environ.get('OLLAMA_BASE_URL',  'http://localhost:11434/v1')
    OLLAMA_MODEL      = os.environ.get('OLLAMA_MODEL',     'gemma4:e4b')
    OLLAMA_MAX_TOKENS = int(os.environ.get('OLLAMA_MAX_TOKENS', 2048))
    OLLAMA_TEMPERATURE = float(os.environ.get('OLLAMA_TEMPERATURE', 0.7))

    # OpenAI (cloud — opcional)
    OPENAI_API_KEY    = os.environ.get('OPENAI_API_KEY', None)
    OPENAI_MODEL      = os.environ.get('OPENAI_MODEL',  'gpt-4o-mini')
    OPENAI_MAX_TOKENS = int(os.environ.get('OPENAI_MAX_TOKENS', 2048))
    OPENAI_TEMPERATURE = float(os.environ.get('OPENAI_TEMPERATURE', 0.7))
    OPENAI_TIMEOUT = float(os.environ.get('OPENAI_TIMEOUT', 30))
    OPENAI_MAX_RETRIES = int(os.environ.get('OPENAI_MAX_RETRIES', 2))
    
    # Email (SMTP)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', None)
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', None)
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@soc360.local')
    
    # Rate Limiting
    RATE_LIMIT_LOGIN_ATTEMPTS = 5
    RATE_LIMIT_LOGIN_WINDOW = 300  # 5 minutes
    RATE_LIMIT_API_REQUESTS = 100
    RATE_LIMIT_API_WINDOW = 60  # 1 minute
    
    # Password Policy
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_RESET_TOKEN_EXPIRY = 86400  # 24 hours
    
    # Bcrypt
    BCRYPT_LOG_ROUNDS = 12
    
    # Pagination
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 100
    
    # File Uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Reports
    REPORTS_DIR = os.environ.get('REPORTS_DIR', '/app/reports')

    # Cisco Umbrella
    UMBRELLA_USE_MOCK = os.environ.get('UMBRELLA_USE_MOCK', 'true').lower() == 'true'
    UMBRELLA_API_KEY = os.environ.get('UMBRELLA_API_KEY', None)
    UMBRELLA_API_SECRET = os.environ.get('UMBRELLA_API_SECRET', None)
    UMBRELLA_REPORTS_DIR = os.environ.get('UMBRELLA_REPORTS_DIR', os.path.join(REPORTS_DIR, 'umbrella'))
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = 'json'
    
    # Auto Root User
    AUTO_CREATE_ROOT = os.environ.get('AUTO_CREATE_ROOT', 'false').lower() == 'true'
    AUTO_ROOT_USERNAME = os.environ.get('AUTO_ROOT_USERNAME', 'admin')
    AUTO_ROOT_EMAIL = os.environ.get('AUTO_ROOT_EMAIL', 'admin@soc360.local')
    AUTO_ROOT_PASSWORD = os.environ.get('AUTO_ROOT_PASSWORD', None)

    @staticmethod
    def _is_postgres_available(uri, timeout=3):
        """Check if PostgreSQL is available at the given URI."""
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(uri, pool_pre_ping=True, connect_args={'connect_timeout': timeout})
            with engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            return True
        except Exception:
            return False

    @classmethod
    def fallback_to_sqlite(cls, app, db_uri):
        """Fallback to SQLite if PostgreSQL is not available."""
        if db_uri and db_uri.startswith('postgresql://') and not cls._is_postgres_available(db_uri):
            basedir = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            db_path = os.path.join(basedir, 'instance', 'app.db')
            app.logger.warning('PostgreSQL not accessible (%s). Falling back to SQLite at %s', db_uri, db_path)
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
            app.config['SQLALCHEMY_BINDS'] = {
                'public': 'sqlite:///' + db_path
            }
            # NullPool: cada thread obtém sua própria conexão SQLite independente.
            # timeout=30: threads aguardam até 30s pelo lock ao invés de falhar imediatamente.
            # WAL mode via creator: permite leituras concorrentes durante escritas.
            from sqlalchemy.pool import NullPool
            import sqlite3

            def _sqlite_creator():
                conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                conn.execute('PRAGMA busy_timeout=30000')
                return conn

            app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
                'creator': _sqlite_creator,
                'poolclass': NullPool,
            }
            app.config['DB_CORE_HOST'] = 'localhost'
            app.config['DB_PUBLIC_HOST'] = 'localhost'
