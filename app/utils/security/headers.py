"""
SOC360 Security Headers Service
CSP, HSTS, and other security headers configuration.
"""
import hashlib
import secrets
from typing import Dict, List, Optional
from flask import Flask, request, g


class SecurityHeadersService:
    """
    Serviço para configuração de security headers.
    
    Implementa:
    - Content Security Policy (CSP)
    - HTTP Strict Transport Security (HSTS)
    - X-Content-Type-Options
    - X-Frame-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    """
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self._csp_config = self._default_csp_config()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with Flask app."""
        self.app = app
        
        # Load CSP config from app config
        if 'CSP_CONFIG' in app.config:
            self._csp_config.update(app.config['CSP_CONFIG'])
        
        # Register after_request handler
        app.after_request(self._add_security_headers)
        
        # Register before_request for nonce generation
        app.before_request(self._generate_nonce)
    
    def _default_csp_config(self) -> Dict[str, List[str]]:
        """Default Content Security Policy configuration."""
        return {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'nonce-{nonce}'"],
            'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'", "https://fonts.gstatic.com"],
            'connect-src': ["'self'"],
            'frame-src': ["'none'"],
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'frame-ancestors': ["'none'"],
            'upgrade-insecure-requests': [],
        }
    
    def _generate_nonce(self) -> None:
        """Generate CSP nonce for this request."""
        g.csp_nonce = secrets.token_urlsafe(16)
    
    def get_nonce(self) -> str:
        """Get CSP nonce for current request."""
        return getattr(g, 'csp_nonce', '')
    
    def _build_csp_header(self, nonce: str) -> str:
        """
        Build Content-Security-Policy header value.
        
        Args:
            nonce: Unique nonce for this request
            
        Returns:
            CSP header string
        """
        directives = []
        
        for directive, sources in self._csp_config.items():
            if not sources:
                # Directives without values (e.g., upgrade-insecure-requests)
                directives.append(directive)
            else:
                # Replace {nonce} placeholder with actual nonce
                processed_sources = [
                    s.replace('{nonce}', nonce) for s in sources
                ]
                directives.append(f"{directive} {' '.join(processed_sources)}")
        
        return '; '.join(directives)
    
    def _add_security_headers(self, response):
        """Add security headers to response."""
        # Skip for certain paths
        if request.path.startswith('/static/'):
            return response
        
        nonce = self.get_nonce()
        
        # Content Security Policy
        if self.app.config.get('CSP_ENABLED', True):
            csp_header = self._build_csp_header(nonce)
            
            if self.app.config.get('CSP_REPORT_ONLY', False):
                response.headers['Content-Security-Policy-Report-Only'] = csp_header
            else:
                response.headers['Content-Security-Policy'] = csp_header
        
        # HTTP Strict Transport Security (HTTPS only)
        if self.app.config.get('HSTS_ENABLED', True) and request.is_secure:
            max_age = self.app.config.get('HSTS_MAX_AGE', 31536000)  # 1 year
            include_subdomains = self.app.config.get('HSTS_INCLUDE_SUBDOMAINS', True)
            preload = self.app.config.get('HSTS_PRELOAD', False)
            
            hsts_value = f'max-age={max_age}'
            if include_subdomains:
                hsts_value += '; includeSubDomains'
            if preload:
                hsts_value += '; preload'
            
            response.headers['Strict-Transport-Security'] = hsts_value
        
        # X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options (backup for older browsers)
        response.headers['X-Frame-Options'] = 'DENY'
        
        # X-XSS-Protection (legacy, but still useful for older browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer-Policy
        response.headers['Referrer-Policy'] = self.app.config.get(
            'REFERRER_POLICY', 'strict-origin-when-cross-origin'
        )
        
        # Permissions-Policy
        permissions_policy = self._build_permissions_policy()
        if permissions_policy:
            response.headers['Permissions-Policy'] = permissions_policy
        
        # Cross-Origin policies
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        # Cache-Control for sensitive pages
        if self._is_sensitive_page():
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
    
    def _build_permissions_policy(self) -> str:
        """Build Permissions-Policy header."""
        policies = self.app.config.get('PERMISSIONS_POLICY', {
            'accelerometer': [],
            'camera': [],
            'geolocation': [],
            'gyroscope': [],
            'magnetometer': [],
            'microphone': [],
            'payment': [],
            'usb': [],
        })
        
        directives = []
        for feature, origins in policies.items():
            if not origins:
                directives.append(f'{feature}=()')
            else:
                origins_str = ' '.join(f'"{o}"' for o in origins)
                directives.append(f'{feature}=({origins_str})')
        
        return ', '.join(directives)
    
    def _is_sensitive_page(self) -> bool:
        """Check if current page contains sensitive data."""
        sensitive_paths = [
            '/auth/',
            '/admin/',
            '/api/v1/users/',
            '/settings/',
            '/profile/',
        ]
        
        return any(request.path.startswith(p) for p in sensitive_paths)
    
    def add_csp_source(self, directive: str, source: str) -> None:
        """
        Add a source to CSP directive.
        
        Args:
            directive: CSP directive name
            source: Source to add
        """
        if directive not in self._csp_config:
            self._csp_config[directive] = []
        
        if source not in self._csp_config[directive]:
            self._csp_config[directive].append(source)
    
    def remove_csp_source(self, directive: str, source: str) -> None:
        """
        Remove a source from CSP directive.
        
        Args:
            directive: CSP directive name
            source: Source to remove
        """
        if directive in self._csp_config and source in self._csp_config[directive]:
            self._csp_config[directive].remove(source)


# Global instance
security_headers = SecurityHeadersService()
