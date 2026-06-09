"""
Secure Cisco Umbrella API credentials configuration.

Credentials are resolved from an encrypted value in SyncMetadata first,
then from UMBRELLA_API_KEY / UMBRELLA_API_SECRET environment variables.
Plaintext secrets are never returned by public methods.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from flask import current_app

from app.models.system import SyncMetadata

logger = logging.getLogger(__name__)

_KEY_API_KEY_ENC     = 'umbrella_api_key_enc'
_KEY_API_SECRET_ENC  = 'umbrella_api_secret_enc'
_KEY_LAST_TEST_AT    = 'umbrella_last_test_at'
_KEY_LAST_TEST_OK    = 'umbrella_last_test_ok'
_KEY_LAST_TEST_MSG   = 'umbrella_last_test_message'


def _fernet():
    from cryptography.fernet import Fernet

    secret_key = current_app.config.get('SECRET_KEY') or ''
    if not secret_key:
        raise RuntimeError('SECRET_KEY not configured; cannot encrypt Umbrella credentials')
    digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')


def _decrypt(token: str) -> str:
    if not token:
        return ''
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except Exception as exc:
        logger.error('Failed to decrypt Umbrella credential (SECRET_KEY rotated?): %s', exc)
        return ''


def _mask(value: str) -> str:
    value = (value or '').strip()
    if not value:
        return ''
    if len(value) <= 8:
        return '****'
    return f'{value[:4]}...{value[-4:]}'


class UmbrellaConfigService:
    """Stateless helper for Umbrella credential storage and diagnostics."""

    @staticmethod
    def validate_credentials(api_key: str, api_secret: str) -> Tuple[bool, str]:
        key = (api_key or '').strip()
        secret = (api_secret or '').strip()
        if not key:
            return False, 'API Key não pode estar vazia.'
        if len(key) < 8:
            return False, 'API Key muito curta (mínimo 8 caracteres).'
        if not secret:
            return False, 'API Secret não pode estar vazio.'
        if len(secret) < 8:
            return False, 'API Secret muito curto (mínimo 8 caracteres).'
        return True, ''

    @classmethod
    def get_stored_credentials(cls) -> Tuple[str, str]:
        key    = _decrypt(SyncMetadata.get(_KEY_API_KEY_ENC) or '')
        secret = _decrypt(SyncMetadata.get(_KEY_API_SECRET_ENC) or '')
        return key, secret

    @classmethod
    def get_runtime_credentials(cls) -> Tuple[str, str]:
        key, secret = cls.get_stored_credentials()
        if key and secret:
            return key, secret
        env_key    = (current_app.config.get('UMBRELLA_API_KEY') or '').strip()
        env_secret = (current_app.config.get('UMBRELLA_API_SECRET') or '').strip()
        return env_key, env_secret

    @classmethod
    def has_stored_credentials(cls) -> bool:
        return bool(
            SyncMetadata.get(_KEY_API_KEY_ENC)
            and SyncMetadata.get(_KEY_API_SECRET_ENC)
        )

    @classmethod
    def status(cls) -> dict:
        api_key, api_secret = cls.get_runtime_credentials()
        configured = bool(api_key and api_secret)

        source = None
        if cls.has_stored_credentials():
            source = 'database'
        elif (current_app.config.get('UMBRELLA_API_KEY')
              and current_app.config.get('UMBRELLA_API_SECRET')):
            source = 'environment'

        use_mock = current_app.config.get('UMBRELLA_USE_MOCK', True)

        return {
            'configured': configured,
            'source': source,
            'masked_key': _mask(api_key) if api_key else None,
            'masked_secret': _mask(api_secret) if api_secret else None,
            'use_mock': use_mock,
            'last_test': cls.last_test_status(),
        }

    @classmethod
    def save_credentials(cls, api_key: str, api_secret: str) -> dict:
        ok, err = cls.validate_credentials(api_key, api_secret)
        if not ok:
            raise ValueError(err)

        key    = api_key.strip()
        secret = api_secret.strip()
        SyncMetadata.set_multi({
            _KEY_API_KEY_ENC:    _encrypt(key),
            _KEY_API_SECRET_ENC: _encrypt(secret),
        })
        logger.info(
            'Umbrella credentials saved by admin (key_masked=%s)', _mask(key)
        )
        return cls.status()

    @classmethod
    def remove_credentials(cls) -> dict:
        SyncMetadata.delete(_KEY_API_KEY_ENC)
        SyncMetadata.delete(_KEY_API_SECRET_ENC)
        logger.info('Umbrella credentials removed from encrypted database storage')
        return cls.status()

    @classmethod
    def test_connection(
        cls,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
    ) -> dict:
        """Authenticate against the real Cisco Umbrella API and persist result."""
        now_iso = datetime.now(timezone.utc).isoformat()
        result: dict = {'ok': False, 'at': now_iso, 'message': ''}

        if api_key and api_secret:
            key, secret = api_key.strip(), api_secret.strip()
        else:
            key, secret = cls.get_runtime_credentials()

        if not key or not secret:
            result['message'] = 'Credenciais Umbrella não configuradas.'
            cls._record_test(result)
            return result

        ok, err = cls.validate_credentials(key, secret)
        if not ok:
            result['message'] = err
            cls._record_test(result)
            return result

        try:
            import importlib
            requests = importlib.import_module('requests')
            from requests.auth import HTTPBasicAuth

            token_url = 'https://api.umbrella.com/auth/v2/token'
            resp = requests.post(
                token_url,
                auth=HTTPBasicAuth(key, secret),
                data={'grant_type': 'client_credentials'},
                timeout=15,
            )
            if resp.status_code == 200:
                result['ok'] = True
                result['message'] = 'Autenticação Cisco Umbrella realizada com sucesso.'
            elif resp.status_code in (401, 403):
                result['message'] = 'Falha de autenticação: API Key ou Secret inválidos.'
            else:
                result['message'] = (
                    f'Resposta inesperada da API Umbrella: HTTP {resp.status_code}.'
                )
        except Exception as exc:
            name = exc.__class__.__name__
            logger.warning('Umbrella connection test failed: %s — %s', name, exc)
            if 'ConnectionError' in name or 'Timeout' in name:
                result['message'] = 'Erro de rede ao conectar com api.umbrella.com.'
            else:
                result['message'] = 'Erro inesperado ao testar conexão Umbrella.'

        cls._record_test(result)
        return result

    @staticmethod
    def _record_test(result: dict) -> None:
        SyncMetadata.set_multi({
            _KEY_LAST_TEST_AT:  result.get('at') or '',
            _KEY_LAST_TEST_OK:  'true' if result.get('ok') else 'false',
            _KEY_LAST_TEST_MSG: (result.get('message') or '')[:500],
        })

    @staticmethod
    def last_test_status() -> dict:
        return {
            'at':      SyncMetadata.get(_KEY_LAST_TEST_AT),
            'ok':      (SyncMetadata.get(_KEY_LAST_TEST_OK) or '').lower() == 'true',
            'message': SyncMetadata.get(_KEY_LAST_TEST_MSG) or '',
        }
