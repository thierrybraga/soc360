"""
SOC360 Security Utils
Funções de segurança: rate limiting, validação de senha, decorators.
"""
import re
import functools
from datetime import datetime, timedelta, timezone
from typing import Callable, Tuple
from flask import request, jsonify, abort, current_app
from flask_login import current_user


# =============================================================================
# PASSWORD VALIDATION
# =============================================================================

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validar força da senha.
    
    Requisitos:
    - Mínimo 12 caracteres
    - Pelo menos uma letra maiúscula
    - Pelo menos uma letra minúscula
    - Pelo menos um dígito
    - Pelo menos um caractere especial
    
    Args:
        password: Senha a validar
        
    Returns:
        Tuple (is_valid, message)
    """
    if len(password) < 12:
        return False, 'Password must be at least 12 characters long.'
    
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit.'
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        return False, 'Password must contain at least one special character.'
    
    # Check for common passwords
    common_passwords = [
        'password123', 'qwerty123456', '123456789012',
        'admin123456', 'welcome12345'
    ]
    
    if password.lower() in common_passwords:
        return False, 'This password is too common. Please choose another one.'
    
    return True, 'Password is valid.'


# =============================================================================
# RATE LIMITING
# =============================================================================

# Armazenamento em memória (use Redis em produção)
_rate_limit_storage = {}


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Decorator para rate limiting.
    
    Args:
        max_requests: Número máximo de requisições na janela
        window_seconds: Tamanho da janela em segundos
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Bypass rate limit in debug/testing mode
            if current_app.debug or current_app.config.get('TESTING'):
                return f(*args, **kwargs)

            # Identificador do cliente
            client_id = _get_client_identifier()
            key = f'{f.__name__}:{client_id}'
            
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(seconds=window_seconds)
            
            # Limpar entradas antigas
            if key in _rate_limit_storage:
                _rate_limit_storage[key] = [
                    ts for ts in _rate_limit_storage[key]
                    if ts > window_start
                ]
            else:
                _rate_limit_storage[key] = []
            
            # Verificar limite
            if len(_rate_limit_storage[key]) >= max_requests:
                current_app.logger.warning(
                    f'Rate limit exceeded for {key}'
                )
                
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Too Many Requests',
                        'message': f'Rate limit exceeded. Try again in {window_seconds} seconds.'
                    }), 429
                
                abort(429)
            
            # Adicionar timestamp
            _rate_limit_storage[key].append(now)
            
            return f(*args, **kwargs)
        
        return wrapped
    return decorator


def _get_client_identifier() -> str:
    """Obter identificador único do cliente."""
    # Prioridade: user_id > IP + User-Agent
    if current_user.is_authenticated:
        return f'user:{current_user.id}'
    
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip:
        ip = ip.split(',')[0].strip()
    
    user_agent = request.headers.get('User-Agent', '')[:50]
    
    return f'anon:{ip}:{hash(user_agent)}'


# =============================================================================
# AUTHORIZATION DECORATORS
# =============================================================================

def admin_required(f: Callable) -> Callable:
    """Decorator que requer usuário admin."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            abort(401)
        
        if not current_user.is_admin:
            current_app.logger.warning(
                f'Admin access denied for user {current_user.username}'
            )
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Forbidden', 'message': 'Admin access required'}), 403
            abort(403)
        
        return f(*args, **kwargs)
    
    return wrapped


def role_required(*required_roles):
    """
    Decorator que requer uma ou mais roles.
    
    Args:
        required_roles: Nomes das roles permitidas
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Unauthorized'}), 401
                abort(401)
            
            # Admin tem acesso a tudo
            if current_user.is_admin:
                return f(*args, **kwargs)
            
            # Verificar se tem alguma das roles requeridas
            user_roles = [role.name for role in current_user.roles]
            
            if not any(role in user_roles for role in required_roles):
                current_app.logger.warning(
                    f'Role access denied for user {current_user.username}. '
                    f'Required: {required_roles}, Has: {user_roles}'
                )
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Forbidden',
                        'message': f'Required roles: {", ".join(required_roles)}'
                    }), 403
                abort(403)
            
            return f(*args, **kwargs)
        
        return wrapped
    return decorator


def owner_required(get_owner_id: Callable):
    """
    Decorator que requer ser owner do recurso (sem permitir admin).
    
    Args:
        get_owner_id: Função que extrai owner_id dos kwargs
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Unauthorized'}), 401
                abort(401)
            
            # Verificar ownership
            owner_id = get_owner_id(kwargs)
            
            if owner_id != current_user.id:
                current_app.logger.warning(
                    f'Owner access denied for user {current_user.username}'
                )
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Forbidden',
                        'message': 'You do not have access to this resource'
                    }), 403
                abort(403)
            
            return f(*args, **kwargs)
        
        return wrapped
    return decorator


def owner_or_admin_required(get_owner_id: Callable):
    """
    Decorator que requer ser owner do recurso ou admin.
    
    Args:
        get_owner_id: Função que extrai owner_id dos kwargs
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Unauthorized'}), 401
                abort(401)
            
            # Admin tem acesso a tudo
            if current_user.is_admin:
                return f(*args, **kwargs)
            
            # Verificar ownership
            owner_id = get_owner_id(kwargs)
            
            if owner_id != current_user.id:
                current_app.logger.warning(
                    f'Owner access denied for user {current_user.username}'
                )
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Forbidden',
                        'message': 'You do not have access to this resource'
                    }), 403
                abort(403)
            
            return f(*args, **kwargs)
        
        return wrapped
    return decorator


def api_key_required(f: Callable) -> Callable:
    """Decorator que requer API key válida."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        from app.models.auth import User
        
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key required'
            }), 401
        
        # Buscar usuário pela API key
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        
        if not user:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid API key'
            }), 401
        
        # Verificar se API key está revogada
        if user.api_key_revoked_at:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key has been revoked'
            }), 401
        
        # Adicionar user ao contexto
        from flask_login import login_user
        login_user(user)
        
        return f(*args, **kwargs)
    
    return wrapped
