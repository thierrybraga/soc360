"""
Secure OpenAI API key configuration.

The runtime key is resolved from an encrypted value in SyncMetadata first,
then from OPENAI_API_KEY in the environment. The plaintext key is never
returned by public methods intended for controllers/templates.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from flask import current_app

from app.models.system import SyncMetadata

logger = logging.getLogger(__name__)


KEY_OPENAI_API_KEY_ENC = 'openai_api_key_enc'
KEY_OPENAI_LAST_TEST_AT = 'openai_last_test_at'
KEY_OPENAI_LAST_TEST_OK = 'openai_last_test_ok'
KEY_OPENAI_LAST_TEST_MESSAGE = 'openai_last_test_message'
KEY_OPENAI_LAST_TEST_MODEL = 'openai_last_test_model'

_OPENAI_KEY_RE = re.compile(r'^sk-[A-Za-z0-9_\-]{12,}$')


def _fernet():
    from cryptography.fernet import Fernet

    secret_key = current_app.config.get('SECRET_KEY') or ''
    if not secret_key:
        raise RuntimeError('SECRET_KEY not configured; cannot encrypt OpenAI key')
    digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')


def _decrypt_secret(token: str) -> str:
    if not token:
        return ''
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except Exception as exc:  # noqa: BLE001 - do not leak internals/key material
        logger.error('Failed to decrypt OpenAI API key (SECRET_KEY rotated?): %s', exc)
        return ''


class OpenAIConfigService:
    """Small stateless helper for OpenAI key storage and diagnostics."""

    @staticmethod
    def validate_key_format(api_key: str) -> bool:
        return bool(_OPENAI_KEY_RE.match((api_key or '').strip()))

    @staticmethod
    def mask_key(api_key: str) -> str:
        value = (api_key or '').strip()
        if not value:
            return ''
        if len(value) <= 10:
            return 'sk-...'
        return f'{value[:3]}...{value[-4:]}'

    @classmethod
    def get_stored_key(cls) -> str:
        return _decrypt_secret(SyncMetadata.get(KEY_OPENAI_API_KEY_ENC) or '')

    @classmethod
    def get_runtime_key(cls) -> str:
        stored = cls.get_stored_key()
        if stored:
            return stored
        return (current_app.config.get('OPENAI_API_KEY') or '').strip()

    @classmethod
    def has_stored_key(cls) -> bool:
        return bool(SyncMetadata.get(KEY_OPENAI_API_KEY_ENC))

    @classmethod
    def status(cls) -> dict:
        runtime_key = cls.get_runtime_key()
        source = None
        if cls.has_stored_key():
            source = 'database'
        elif current_app.config.get('OPENAI_API_KEY'):
            source = 'environment'

        return {
            'configured': bool(runtime_key),
            'source': source,
            'masked_key': cls.mask_key(runtime_key) if runtime_key else None,
            'model': current_app.config.get('OPENAI_MODEL', 'gpt-4o-mini'),
            'last_test': cls.last_test_status(),
        }

    @classmethod
    def save_key(cls, api_key: str) -> dict:
        value = (api_key or '').strip()
        if not cls.validate_key_format(value):
            raise ValueError('Formato de chave OpenAI inválido.')

        SyncMetadata.set(KEY_OPENAI_API_KEY_ENC, _encrypt_secret(value))
        logger.info('OpenAI API key saved by admin (masked=%s)', cls.mask_key(value))
        return cls.status()

    @classmethod
    def remove_key(cls) -> dict:
        SyncMetadata.delete(KEY_OPENAI_API_KEY_ENC)
        logger.info('OpenAI API key removed from encrypted database storage')
        return cls.status()

    @classmethod
    def test_connection(cls, api_key: Optional[str] = None) -> dict:
        """Run a minimal OpenAI chat completion test and persist safe status."""
        from openai import (
            APIConnectionError,
            APIError,
            APITimeoutError,
            AuthenticationError,
            OpenAI,
            RateLimitError,
        )

        key = (api_key or cls.get_runtime_key() or '').strip()
        model = current_app.config.get('OPENAI_MODEL', 'gpt-4o-mini')
        now_iso = datetime.now(timezone.utc).isoformat()

        result = {
            'ok': False,
            'at': now_iso,
            'model': model,
            'message': '',
        }

        if not key:
            result['message'] = 'Chave OpenAI não configurada.'
            cls._record_test(result)
            return result
        if not cls.validate_key_format(key):
            result['message'] = 'Formato de chave OpenAI inválido.'
            cls._record_test(result)
            return result

        try:
            client = OpenAI(api_key=key, timeout=15.0, max_retries=1)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {'role': 'system', 'content': 'Responda apenas OK.'},
                    {'role': 'user', 'content': 'Teste de conexão SOC360.'},
                ],
                max_tokens=5,
                temperature=0,
            )
            content = (response.choices[0].message.content or '').strip()
            if not content:
                result['message'] = 'A API respondeu, mas retornou conteúdo vazio.'
            else:
                result['ok'] = True
                result['message'] = 'Conexão OpenAI testada com sucesso.'
        except AuthenticationError:
            result['message'] = 'Falha de autenticação: chave inválida ou revogada.'
        except RateLimitError:
            result['message'] = 'Limite de requisições atingido na OpenAI.'
        except APITimeoutError:
            result['message'] = 'Timeout ao conectar com a OpenAI.'
        except APIConnectionError:
            result['message'] = 'Erro de rede ao conectar com a OpenAI.'
        except APIError as exc:
            result['message'] = f'Erro interno da API OpenAI: {getattr(exc, "status_code", "desconhecido")}.'
        except Exception as exc:  # noqa: BLE001 - keep response sanitized
            logger.warning('OpenAI connection test failed with unexpected error: %s', exc.__class__.__name__)
            result['message'] = 'Erro inesperado ao validar a chave OpenAI.'

        cls._record_test(result)
        return result

    @staticmethod
    def _record_test(result: dict) -> None:
        SyncMetadata.set_multi({
            KEY_OPENAI_LAST_TEST_AT: result.get('at') or '',
            KEY_OPENAI_LAST_TEST_OK: 'true' if result.get('ok') else 'false',
            KEY_OPENAI_LAST_TEST_MESSAGE: (result.get('message') or '')[:500],
            KEY_OPENAI_LAST_TEST_MODEL: result.get('model') or '',
        })

    @staticmethod
    def last_test_status() -> dict:
        return {
            'at': SyncMetadata.get(KEY_OPENAI_LAST_TEST_AT),
            'ok': (SyncMetadata.get(KEY_OPENAI_LAST_TEST_OK) or '').lower() == 'true',
            'message': SyncMetadata.get(KEY_OPENAI_LAST_TEST_MESSAGE) or '',
            'model': SyncMetadata.get(KEY_OPENAI_LAST_TEST_MODEL) or '',
        }
