"""
SOC360 Production Settings
Configurations optimized for production environment.
"""
import os
from app.settings.base import BaseConfig


class ProductionConfig(BaseConfig):
    """Production configurations."""
    
    DEBUG = False
    TESTING = False
    
    # Security - Strict settings
    # SESSION_COOKIE_SECURE is inherited from BaseConfig which reads from env
    WTF_CSRF_ENABLED = True
    
    # Database - Production pools
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 10,
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'WARNING')
    
    # Performance
    TEMPLATES_AUTO_RELOAD = False
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year
    
    # Security headers handled by NGINX in production
    
    @classmethod
    def init_app(cls, app):
        """Production-specific initialization."""
        # Configure logging for production
        import logging
        from logging.handlers import RotatingFileHandler

        if not app.debug:
            log_file = os.environ.get('LOG_FILE', '/app/logs/app.log')
            log_dir = os.path.dirname(log_file)
            handler = None

            if os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                    handler = RotatingFileHandler(
                        log_file,
                        maxBytes=10485760,  # 10MB
                        backupCount=10
                    )
                except (PermissionError, OSError):
                    pass  # fall through to StreamHandler below

            if handler is None:
                handler = logging.StreamHandler()

            handler.setLevel(logging.WARNING)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s '
                '[in %(pathname)s:%(lineno)d]'
            ))
            app.logger.addHandler(handler)

        # SQLite só é permitido em modo local. Em produção NÃO há fallback
        # silencioso: se o Postgres estiver inacessível, falha com mensagem clara
        # (a menos que ALLOW_SQLITE_FALLBACK=true seja definido explicitamente).
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if os.environ.get('ALLOW_SQLITE_FALLBACK', '').strip().lower() == 'true':
            cls.fallback_to_sqlite(app, db_uri)
        elif db_uri and db_uri.startswith('postgresql://') and not cls._is_postgres_available(db_uri):
            raise RuntimeError(
                f"PostgreSQL inacessível em produção ({db_uri}). SQLite só é "
                "permitido em modo local. Garanta o serviço Postgres ou defina "
                "ALLOW_SQLITE_FALLBACK=true (não recomendado em produção)."
            )


