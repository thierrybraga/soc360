"""
TACACS+ authentication integration.

Provides a thin wrapper around the ``tacacs_plus`` client plus a small
config helper backed by :class:`SyncMetadata` (so no schema migration is
required). Secret keys are encrypted with Fernet, keyed from the Flask
``SECRET_KEY`` — that means rotating ``SECRET_KEY`` invalidates stored
TACACS secrets (by design: a leaked DB without the app key cannot reveal
TACACS shared secrets).

The module is deliberately tolerant when the optional ``tacacs_plus``
dependency is not installed: importing this module never fails, and the
UI surfaces a clear message via :meth:`TacacsService.dependency_status`.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple

from flask import current_app

from app.models.system import SyncMetadata

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Config keys (all persisted in the generic ``sync_metadata`` key/value table)
# ─────────────────────────────────────────────────────────────────────────────

KEY_ENABLED            = 'tacacs_enabled'
KEY_HOST               = 'tacacs_host'
KEY_PORT               = 'tacacs_port'
KEY_SECRET_ENC         = 'tacacs_secret_enc'     # Fernet-encrypted shared secret
KEY_TIMEOUT            = 'tacacs_timeout'
KEY_AUTH_TYPE          = 'tacacs_auth_type'      # ascii | pap | chap
KEY_FALLBACK_LOCAL     = 'tacacs_fallback_local'
KEY_AUTO_CREATE_USER   = 'tacacs_auto_create_user'
KEY_DEFAULT_EMAIL_DOM  = 'tacacs_default_email_domain'
KEY_LAST_TEST_AT       = 'tacacs_last_test_at'
KEY_LAST_TEST_OK       = 'tacacs_last_test_ok'
KEY_LAST_TEST_MESSAGE  = 'tacacs_last_test_message'

VALID_AUTH_TYPES = ('ascii', 'pap', 'chap')
DEFAULT_PORT = 49
DEFAULT_TIMEOUT = 10


# ─────────────────────────────────────────────────────────────────────────────
# Config dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TacacsConfig:
    enabled: bool = False
    host: str = ''
    port: int = DEFAULT_PORT
    secret: str = ''                       # plaintext only in-memory / in-form
    timeout: int = DEFAULT_TIMEOUT
    auth_type: str = 'ascii'
    fallback_local: bool = True
    auto_create_user: bool = False
    default_email_domain: str = ''
    has_secret: bool = field(default=False)  # UI hint — True if a secret is stored

    # ── Persistence ─────────────────────────────────────────────────────────

    @classmethod
    def load(cls) -> 'TacacsConfig':
        """Load configuration from the metadata store (never returns None)."""
        def _b(v, default=False):
            if v is None:
                return default
            return str(v).strip().lower() in ('1', 'true', 'yes', 'on')

        def _i(v, default):
            try:
                return int(v) if v not in (None, '') else default
            except (TypeError, ValueError):
                return default

        secret_enc = SyncMetadata.get(KEY_SECRET_ENC) or ''
        return cls(
            enabled=_b(SyncMetadata.get(KEY_ENABLED)),
            host=SyncMetadata.get(KEY_HOST) or '',
            port=_i(SyncMetadata.get(KEY_PORT), DEFAULT_PORT),
            secret='',  # never surfaced to the UI — ``has_secret`` signals presence
            timeout=_i(SyncMetadata.get(KEY_TIMEOUT), DEFAULT_TIMEOUT),
            auth_type=(SyncMetadata.get(KEY_AUTH_TYPE) or 'ascii').lower(),
            fallback_local=_b(SyncMetadata.get(KEY_FALLBACK_LOCAL), default=True),
            auto_create_user=_b(SyncMetadata.get(KEY_AUTO_CREATE_USER)),
            default_email_domain=SyncMetadata.get(KEY_DEFAULT_EMAIL_DOM) or '',
            has_secret=bool(secret_enc),
        )

    def save(self) -> None:
        """Persist to metadata store. Encrypts ``secret`` when provided."""
        if self.auth_type not in VALID_AUTH_TYPES:
            raise ValueError(f'Invalid auth_type: {self.auth_type}')
        if self.port <= 0 or self.port > 65535:
            raise ValueError('port must be between 1 and 65535')
        if self.timeout <= 0 or self.timeout > 120:
            raise ValueError('timeout must be between 1 and 120 seconds')

        payload = {
            KEY_ENABLED: 'true' if self.enabled else 'false',
            KEY_HOST: (self.host or '').strip(),
            KEY_PORT: str(int(self.port)),
            KEY_TIMEOUT: str(int(self.timeout)),
            KEY_AUTH_TYPE: self.auth_type,
            KEY_FALLBACK_LOCAL: 'true' if self.fallback_local else 'false',
            KEY_AUTO_CREATE_USER: 'true' if self.auto_create_user else 'false',
            KEY_DEFAULT_EMAIL_DOM: (self.default_email_domain or '').strip().lower(),
        }
        # Only overwrite secret when the form actually provides a new value;
        # the UI sends an empty string to mean "keep the existing secret".
        if self.secret:
            payload[KEY_SECRET_ENC] = _encrypt_secret(self.secret)

        SyncMetadata.set_multi(payload)
        logger.info('TACACS config saved (enabled=%s host=%s)', self.enabled, self.host)

    def to_dict(self, *, include_secret: bool = False) -> dict:
        data = asdict(self)
        if not include_secret:
            data.pop('secret', None)
        return data


# ─────────────────────────────────────────────────────────────────────────────
# Secret encryption (Fernet keyed from Flask SECRET_KEY)
# ─────────────────────────────────────────────────────────────────────────────

def _fernet():
    from cryptography.fernet import Fernet
    secret_key = current_app.config.get('SECRET_KEY') or ''
    if not secret_key:
        raise RuntimeError('SECRET_KEY not configured; cannot encrypt TACACS secret')
    digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def _encrypt_secret(plaintext: str) -> str:
    token = _fernet().encrypt(plaintext.encode('utf-8'))
    return token.decode('ascii')


def _decrypt_secret(token: str) -> str:
    if not token:
        return ''
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except Exception as exc:  # noqa: BLE001 — do not leak internals
        logger.error('Failed to decrypt TACACS secret (rotated SECRET_KEY?): %s', exc)
        return ''


# ─────────────────────────────────────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────────────────────────────────────

class TacacsService:
    """Stateless helper for TACACS+ operations.

    All methods are safe to call even when the optional ``tacacs_plus``
    package is not installed — in that case authentication attempts return
    ``(False, 'tacacs_plus not installed')`` and the UI surfaces guidance.
    """

    # ── Dependency probing ──────────────────────────────────────────────

    @staticmethod
    def dependency_status() -> dict:
        """Report whether the TACACS+ client library is available."""
        try:
            import tacacs_plus  # noqa: F401
            return {'available': True, 'package': 'tacacs_plus'}
        except ImportError:
            return {
                'available': False,
                'package': 'tacacs_plus',
                'hint': 'pip install tacacs_plus',
            }

    # ── Config helpers ──────────────────────────────────────────────────

    @staticmethod
    def load_config() -> TacacsConfig:
        return TacacsConfig.load()

    @staticmethod
    def is_enabled() -> bool:
        cfg = TacacsConfig.load()
        return bool(cfg.enabled and cfg.host and cfg.has_secret)

    # ── Low-level client construction ───────────────────────────────────

    @staticmethod
    def _build_client(cfg: TacacsConfig):
        try:
            from tacacs_plus.client import TACACSClient
            from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPE_ASCII  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                'tacacs_plus package is not installed. Run: pip install tacacs_plus'
            ) from exc

        secret = _decrypt_secret(SyncMetadata.get(KEY_SECRET_ENC) or '')
        if not secret:
            raise RuntimeError('TACACS shared secret is not configured or cannot be decrypted')

        # `TACACSClient(host, port, secret, timeout=...)` is the stable signature
        # across tacacs_plus >=2.0. We pass ``family`` implicitly via the host.
        return TACACSClient(
            cfg.host,
            int(cfg.port),
            secret,
            timeout=int(cfg.timeout),
            session_id=None,
        )

    @staticmethod
    def _authen_type(cfg: TacacsConfig):
        from tacacs_plus.flags import (
            TAC_PLUS_AUTHEN_TYPE_ASCII,
            TAC_PLUS_AUTHEN_TYPE_PAP,
            TAC_PLUS_AUTHEN_TYPE_CHAP,
        )
        return {
            'ascii': TAC_PLUS_AUTHEN_TYPE_ASCII,
            'pap':   TAC_PLUS_AUTHEN_TYPE_PAP,
            'chap':  TAC_PLUS_AUTHEN_TYPE_CHAP,
        }.get(cfg.auth_type, TAC_PLUS_AUTHEN_TYPE_ASCII)

    # ── Public operations ──────────────────────────────────────────────

    @classmethod
    def authenticate(cls, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Attempt to authenticate a user against the configured TACACS+ server.

        Returns ``(ok, error_message)``. ``error_message`` is non-None when
        the call could not complete for infrastructure reasons (timeout,
        DNS failure, library missing); a simple credential rejection
        returns ``(False, None)``.
        """
        cfg = TacacsConfig.load()
        if not cfg.enabled:
            return False, 'TACACS+ is disabled'
        if not cfg.host:
            return False, 'TACACS+ host is not configured'

        try:
            client = cls._build_client(cfg)
            authen_type = cls._authen_type(cfg)
        except RuntimeError as exc:
            return False, str(exc)

        try:
            result = client.authenticate(username, password, authen_type=authen_type)
        except (socket.timeout, socket.error, OSError) as exc:
            logger.warning('TACACS network error for user=%s: %s', username, exc)
            return False, f'Network error: {exc}'
        except Exception as exc:  # noqa: BLE001 — any protocol/client exception
            logger.exception('TACACS authenticate raised for user=%s: %s', username, exc)
            return False, f'TACACS error: {exc}'

        valid = bool(getattr(result, 'valid', False))
        return valid, None  # credential failure => (False, None); infra errors handled above

    @classmethod
    def test_connection(cls, probe_username: Optional[str] = None,
                        probe_password: Optional[str] = None) -> dict:
        """Diagnostics routine used by the settings page.

        Runs, in order: (1) TCP connect to ``host:port`` with the configured
        timeout, (2) optional auth round-trip with the supplied probe
        credentials. The result is persisted as the last-test status so the
        UI can show it on subsequent page loads.
        """
        cfg = TacacsConfig.load()
        from datetime import datetime, timezone

        now_iso = datetime.now(timezone.utc).isoformat()
        result = {
            'timestamp': now_iso,
            'host': cfg.host,
            'port': cfg.port,
            'tcp_ok': False,
            'auth_attempted': False,
            'auth_ok': False,
            'message': '',
        }

        if not cfg.host:
            result['message'] = 'Host TACACS+ não configurado.'
            cls._record_test(False, result['message'], now_iso)
            return result

        dep = cls.dependency_status()
        if not dep['available']:
            result['message'] = "Pacote 'tacacs_plus' não instalado (pip install tacacs_plus)."
            cls._record_test(False, result['message'], now_iso)
            return result

        # 1) TCP probe
        try:
            with socket.create_connection((cfg.host, int(cfg.port)), timeout=int(cfg.timeout)):
                result['tcp_ok'] = True
        except (socket.timeout, socket.gaierror, OSError) as exc:
            result['message'] = f'Falha de conexão TCP: {exc}'
            cls._record_test(False, result['message'], now_iso)
            return result

        # 2) Optional auth probe
        if probe_username and probe_password:
            result['auth_attempted'] = True
            ok, err = cls.authenticate(probe_username, probe_password)
            result['auth_ok'] = bool(ok)
            if ok:
                result['message'] = 'Conexão TCP OK e credenciais de teste aceitas.'
            elif err:
                result['message'] = f'TCP OK, mas falha na autenticação: {err}'
            else:
                result['message'] = 'TCP OK, mas o servidor rejeitou as credenciais de teste.'
        else:
            result['message'] = 'Conexão TCP com o servidor TACACS+ estabelecida.'

        cls._record_test(
            ok=result['tcp_ok'] and (not result['auth_attempted'] or result['auth_ok']),
            message=result['message'],
            now_iso=now_iso,
        )
        return result

    @staticmethod
    def _record_test(ok: bool, message: str, now_iso: str) -> None:
        SyncMetadata.set_multi({
            KEY_LAST_TEST_AT: now_iso,
            KEY_LAST_TEST_OK: 'true' if ok else 'false',
            KEY_LAST_TEST_MESSAGE: message[:500],
        })

    @staticmethod
    def last_test_status() -> dict:
        return {
            'at': SyncMetadata.get(KEY_LAST_TEST_AT),
            'ok': (SyncMetadata.get(KEY_LAST_TEST_OK) or '').lower() == 'true',
            'message': SyncMetadata.get(KEY_LAST_TEST_MESSAGE) or '',
        }
