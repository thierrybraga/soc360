#!/usr/bin/env python3
"""
Open-Monitor v3.0 - Application Entry Point
Production-ready Flask application launcher
"""
import os
import sys
import logging
import signal
from dotenv import load_dotenv

# Load environment variables BEFORE any other imports
load_dotenv()

from app import create_app

# Configure structured logging (structlog integration)
def setup_logging():
    """Configure application logging based on environment."""
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Production: JSON logs for log aggregation systems
    if os.getenv('FLASK_ENV') == 'production' or os.getenv('FLASK_DEBUG') == '0':
        try:
            import structlog
            structlog.configure(
                processors=[
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.JSONRenderer()
                ],
                context_class=dict,
                logger_factory=structlog.PrintLoggerFactory(sys.stdout),
                cache_logger_on_first_use=True,
            )
            return structlog.get_logger()
        except ImportError:
            pass
    
    # Development: Human-readable logs
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    return logging.getLogger(__name__)


def parse_bool_env(value: str, default: bool = False) -> bool:
    """Safely parse boolean environment variables."""
    if value is None:
        return default
    return str(value).lower().strip() in ('true', '1', 'yes', 'on', 't')


def validate_config(logger) -> bool:
    """Validate critical configuration before startup."""
    required_vars = ['SECRET_KEY']
    missing = [var for var in required_vars if not os.getenv(var)]
    
    if missing:
        logger.error(f"Missing required environment variables: {missing}")
        return False
    
    # Warn about insecure settings in production
    if os.getenv('FLASK_DEBUG') == '1' or os.getenv('FLASK_ENV') == 'development':
        logger.warning("WARNING: Running in DEBUG/development mode - NOT suitable for production")
    
    if not parse_bool_env(os.getenv('SESSION_COOKIE_SECURE'), default=False):
        logger.warning("WARNING: SESSION_COOKIE_SECURE is not enabled - cookies may be sent over HTTP")
    
    return True


def graceful_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    sys.exit(0)


# Register signal handlers for graceful shutdown
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


def main():
    """Application entry point."""
    logger = setup_logging()
    
    # Validate configuration
    if not validate_config(logger):
        sys.exit(1)
    
    # Application configuration
    host = os.getenv('FLASK_RUN_HOST', '0.0.0.0')
    
    try:
        port = int(os.getenv('FLASK_RUN_PORT', 5000))
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid PORT configuration: {e}")
        sys.exit(1)
    
    debug = parse_bool_env(os.getenv('FLASK_DEBUG'), default=False)
    
    # Create Flask application
    try:
        app = create_app(os.getenv('FLASK_ENV', 'production'))
    except Exception as e:
        logger.error(f"Failed to create application: {e}", exc_info=True)
        sys.exit(1)
    
    # Development server warning
    if debug and 'werkzeug' in sys.modules:
        logger.warning(
            "WARNING: Using Flask development server. For production, use: "
            "gunicorn --bind 0.0.0.0:5000 --workers 4 app:create_app"
        )
    
    logger.info(
        f"Starting Open-Monitor v3.0 on {host}:{port}",
        extra={"host": host, "port": port, "debug": debug, "env": os.getenv('FLASK_ENV')}
    )
    
    # NOTE: app.run() is ONLY for development
    # For production, use Gunicorn via Docker CMD or systemd
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


if __name__ == '__main__':
    main()
