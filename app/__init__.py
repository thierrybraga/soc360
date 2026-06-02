"""
SOC360 Application Factory
Plataforma Enterprise de Gerenciamento de Vulnerabilidades
"""
import os
import logging
from flask import Flask, render_template, redirect, url_for, request
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import db, migrate, login_manager, csrf, init_csrf
from app.extensions.middleware import init_middleware
from app.settings import get_config


def create_app(config_name: str | dict | None = None) -> Flask:
    """
    Application Factory Pattern.
    
    Args:
        config_name: Nome do ambiente (development, production, testing)
        
    Returns:
        Flask application configurada
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Criar aplicação
    app = Flask(
        __name__,
        template_folder='static/templates',
        static_folder='static'
    )
    os.makedirs(app.instance_path, exist_ok=True)
    
    # Carregar configuração
    if isinstance(config_name, dict):
        config = None
        app.config.update(config_name)
    else:
        config = get_config(config_name)
        app.config.from_object(config)

        # Executar init_app da configuração (fallbacks locais, etc.)
        if hasattr(config, 'init_app') and callable(getattr(config, 'init_app')):
            config.init_app(app)
    
    # Configurar logging
    configure_logging(app)
    
    # Proxy fix para NGINX
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_prefix=1
    )
    
    # Inicializar extensões
    init_extensions(app)
    
    # Inicializar banco de dados se necessário (SQLite auto-init)
    with app.app_context():
        from app.utils.db import check_and_init_db
        check_and_init_db(app)
    
    # Registrar blueprints
    register_blueprints(app)
    
    # Registrar error handlers
    register_error_handlers(app)
    
    # Registrar context processors
    register_context_processors(app)
    
    # Registrar CLI commands
    register_cli_commands(app)
    
    # Configurar shell context
    configure_shell_context(app)
    
    # Importar tarefas Celery para registro
    from app import tasks
    
    if isinstance(config_name, dict):
        app.logger.info("SOC360 initialized with explicit config override")
    else:
        app.logger.info(f"SOC360 initialized in {config_name} mode")
    
    return app


def configure_logging(app: Flask) -> None:
    """Configurar logging estruturado."""
    log_level = logging.DEBUG if app.debug else logging.INFO
    
    # Formato estruturado
    log_format = (
        '%(asctime)s - %(name)s - %(levelname)s - '
        '[%(filename)s:%(lineno)d] - %(message)s'
    )
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler()
        ]
    )
    
    # Reduzir verbosidade de libs externas
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)


def init_extensions(app: Flask) -> None:
    """Inicializar extensões Flask."""
    # SQLAlchemy
    db.init_app(app)
    migrate.init_app(app, db)

    # Celery
    from app.extensions.celery_extension import init_celery
    init_celery(app)
    
    # Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor, faça login para acessar esta página.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'
    
    # CSRF Protection
    init_csrf(app)
    
    # Middleware customizado
    init_middleware(app)
    
    # Security Headers
    from app.utils.security import security_headers
    security_headers.init_app(app)
    
    # Configurar user_loader
    from app.models.auth import User
    
    @login_manager.user_loader
    def load_user(user_id: str):
        """Carregar usuário da sessão."""
        return db.session.get(User, int(user_id))


def register_blueprints(app: Flask) -> None:
    """Registrar todos os blueprints."""
    # Core routes
    from app.controllers.core import core_bp
    app.register_blueprint(core_bp)
    
    # Auth routes
    from app.controllers.auth import auth_bp
    app.register_blueprint(auth_bp)
    
    # API routes
    from app.controllers.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Vulnerability routes
    from app.controllers.nvd import nvd_bp
    app.register_blueprint(nvd_bp, url_prefix='/vulnerabilities')
    
    # Asset routes
    from app.controllers.inventory import inventory_bp
    app.register_blueprint(inventory_bp, url_prefix='/assets')
    
    # Monitoring routes
    from app.controllers.monitoring import monitoring_bp
    app.register_blueprint(monitoring_bp, url_prefix='/monitoring')
    
    # Reports routes
    from app.controllers.reports import reports_bp
    app.register_blueprint(reports_bp, url_prefix='/reports')
    
    # Analytics routes
    from app.controllers.analytics import analytics_bp
    app.register_blueprint(analytics_bp, url_prefix='/analytics')

    # EUVD routes
    from app.controllers.euvd import euvd_bp
    app.register_blueprint(euvd_bp)

    # MITRE routes
    from app.controllers.mitre import mitre_bp
    app.register_blueprint(mitre_bp)

    # Fortinet routes
    from app.controllers.fortinet import fortinet_bp
    app.register_blueprint(fortinet_bp)

    # Account routes
    from app.controllers.account import account_bp
    app.register_blueprint(account_bp)

    # Chatbot routes
    from app.controllers.chatbot import chatbot_bp
    app.register_blueprint(chatbot_bp)

    # Wazuh SIEM integration
    from app.controllers.wazuh import wazuh_bp
    app.register_blueprint(wazuh_bp)

    # Cisco Umbrella integration
    from app.controllers.umbrella import umbrella_bp
    app.register_blueprint(umbrella_bp)

    # D3FEND integration
    from app.controllers.d3fend import d3fend_bp
    app.register_blueprint(d3fend_bp)


def register_error_handlers(app: Flask) -> None:
    """Registrar handlers de erro customizados."""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        if request.path.startswith('/api/'):
            return {'error': 'Bad Request', 'message': str(error)}, 400
        return render_template('errors/error.html', error_code=400, error_title='Bad Request', error_message='The request could not be understood by the server due to malformed syntax.'), 400
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        if request.path.startswith('/api/'):
            return {'error': 'Unauthorized', 'message': 'Authentication required'}, 401
        return redirect(url_for('auth.login'))
    
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith('/api/'):
            return {'error': 'Forbidden', 'message': 'Permission denied'}, 403
        return render_template('errors/error.html', error_code=403, error_title='Forbidden', error_message='You do not have permission to access this resource.'), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return {'error': 'Not Found', 'message': 'Resource not found'}, 404
        return render_template('errors/error.html', error_code=404, error_title='Not Found', error_message='The requested resource could not be found.'), 404
    
    @app.errorhandler(429)
    def rate_limit_error(error):
        if request.path.startswith('/api/'):
            return {'error': 'Too Many Requests', 'message': 'Rate limit exceeded'}, 429
        return render_template('errors/error.html', error_code=429, error_title='Too Many Requests', error_message='You have sent too many requests in a given amount of time.'), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        import traceback
        try:
            _logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
            os.makedirs(_logs_dir, exist_ok=True)
            with open(os.path.join(_logs_dir, 'error_debug.txt'), 'w') as f:
                f.write(str(error) + '\n' + traceback.format_exc())
        except Exception:
            pass
        app.logger.error(f'Internal Server Error: {error}', exc_info=True)
        if request.path.startswith('/api/'):
            return {'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}, 500
        return render_template('errors/error.html', error_code=500, error_title='Internal Server Error', error_message='An unexpected error occurred on the server.', error_id=request.headers.get('X-Request-ID')), 500


def register_context_processors(app: Flask) -> None:
    """Registrar context processors globais."""
    
    @app.context_processor
    def inject_globals():
        """Injetar variáveis globais em todos os templates."""
        from flask_login import current_user
        from app.models.system import SyncMetadata
        from app.utils.security.headers import security_headers
        
        # Verificar status do sync
        sync_status = None
        try:
            sync_meta = SyncMetadata.get_value('nvd_sync_progress_status')
            sync_status = sync_meta if sync_meta else 'idle'
        except Exception:
            sync_status = 'unknown'
        
        return {
            'app_name': 'SOC360',
            'app_version': '3.0.0',
            'sync_status': sync_status,
            'current_year': __import__('datetime').datetime.now().year,
            'csp_nonce': security_headers.get_nonce
        }


def register_cli_commands(app: Flask) -> None:
    """Registrar comandos CLI."""
    
    @app.cli.command('init-db')
    def init_db():
        """Inicializar banco de dados."""
        from app.utils.db import initialize_database
        initialize_database(app)
        print('Database initialized successfully.')
    
    @app.cli.command('create-admin')
    def create_admin():
        """Criar usuário admin."""
        from app.models.auth import User, Role
        import getpass
        
        username = input('Username: ')
        email = input('Email: ')
        password = getpass.getpass('Password: ')
        
        # Verificar se já existe
        if User.query.filter_by(username=username).first():
            print(f'User {username} already exists.')
            return
        
        # Criar usuário
        user = User(
            username=username,
            email=email,
            is_admin=True,
            is_active=True,
            email_confirmed=True
        )
        user.set_password(password)
        
        # Associar role admin
        admin_role = Role.query.filter_by(name='ADMIN').first()
        if admin_role:
            user.roles.append(admin_role)
        
        db.session.add(user)
        db.session.commit()
        
        print(f'Admin user {username} created successfully.')
    
    @app.cli.command('sync-nvd')
    def sync_nvd():
        """Disparar sincronização NVD manualmente."""
        from app.jobs import trigger_nvd_sync
        trigger_nvd_sync()
        print('NVD sync triggered.')
    
    @app.cli.command('clear-cache')
    def clear_cache():
        """Limpar cache Redis."""
        from app.services.core import RedisCacheService
        cache = RedisCacheService()
        cache.clear_all()
        print('Cache cleared.')


def configure_shell_context(app: Flask) -> None:
    """Configurar contexto do shell Flask."""
    
    @app.shell_context_processor
    def make_shell_context():
        from app.models import (
            User, Role, UserRole,
            Vulnerability, CvssMetric, Weakness, Reference,
            Asset, AssetVulnerability, Vendor, Product,
            MonitoringRule, Report, ApiCallLog, SyncMetadata
        )
        return {
            'db': db,
            'User': User,
            'Role': Role,
            'Vulnerability': Vulnerability,
            'Asset': Asset,
            'MonitoringRule': MonitoringRule,
            'Report': Report,
            'SyncMetadata': SyncMetadata
        }
