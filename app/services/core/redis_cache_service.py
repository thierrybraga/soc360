"""
SOC360 Redis Cache Service
Serviço de cache usando Redis com TTL e operações comuns.
"""
import json
import logging
from typing import Any, Optional
from datetime import timedelta

import redis
from flask import current_app


logger = logging.getLogger(__name__)


class RedisCacheService:
    """
    Serviço de cache Redis.
    
    Suporta:
    - Cache com TTL configurável
    - Serialização JSON automática
    - Operações atômicas (incr, decr)
    - Pub/Sub para invalidação
    - Fallback gracioso quando Redis não disponível
    """
    
    _instance: Optional['RedisCacheService'] = None
    _client: Optional[redis.Redis] = None
    
    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Inicializar conexão Redis."""
        if self._client is None:
            self._connect()
    
    def _connect(self):
        """Estabelecer conexão com Redis."""
        try:
            redis_url = current_app.config.get('REDIS_URL') or 'redis://localhost:6379/0'
            
            self._client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            
            # Testar conexão
            self._client.ping()
            logger.info('Redis connection established')
            
        except Exception as e:
            logger.warning(f'Redis connection failed: {e}. Cache disabled.')
            self._client = None
    
    def ping(self) -> bool:
        """Verificar se Redis está disponível."""
        if not self._client:
            return False
        
        try:
            return self._client.ping()
        except Exception:
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """
        Obter valor do cache.
        
        Args:
            key: Chave do cache
            
        Returns:
            Valor deserializado ou None
        """
        if not self._client:
            return None
        
        try:
            value = self._client.get(key)
            
            if value is None:
                return None
            
            # Tentar deserializar JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
                
        except Exception as e:
            logger.error(f'Redis GET error for key {key}: {e}')
            return None
    
    def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """
        Armazenar valor no cache.
        
        Args:
            key: Chave do cache
            value: Valor a armazenar (será serializado em JSON se necessário)
            ttl: Time-to-live em segundos (default: config CACHE_TTL)
            
        Returns:
            True se sucesso, False caso contrário
        """
        if not self._client:
            return False
        
        if ttl is None:
            ttl = current_app.config.get('CACHE_TTL', 900)
        
        try:
            # Serializar para JSON se não for string
            if not isinstance(value, str):
                value = json.dumps(value, default=str)
            
            self._client.setex(key, ttl, value)
            return True
            
        except Exception as e:
            logger.error(f'Redis SET error for key {key}: {e}')
            return False
    
    def delete(self, key: str) -> bool:
        """
        Remover chave do cache.
        
        Args:
            key: Chave a remover
            
        Returns:
            True se removido, False caso contrário
        """
        if not self._client:
            return False
        
        try:
            self._client.delete(key)
            return True
        except Exception as e:
            logger.error(f'Redis DELETE error for key {key}: {e}')
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        """
        Remover todas as chaves que correspondem ao padrão.
        
        Args:
            pattern: Padrão glob (ex: 'analytics:*')
            
        Returns:
            Número de chaves removidas
        """
        if not self._client:
            return 0
        
        try:
            keys = self._client.keys(pattern)
            if keys:
                return self._client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f'Redis DELETE PATTERN error for {pattern}: {e}')
            return 0
    
    def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Incrementar contador atomicamente.
        
        Args:
            key: Chave do contador
            amount: Valor a incrementar
            
        Returns:
            Novo valor ou None
        """
        if not self._client:
            return None
        
        try:
            return self._client.incrby(key, amount)
        except Exception as e:
            logger.error(f'Redis INCR error for key {key}: {e}')
            return None
    
    def decr(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Decrementar contador atomicamente.
        
        Args:
            key: Chave do contador
            amount: Valor a decrementar
            
        Returns:
            Novo valor ou None
        """
        if not self._client:
            return None
        
        try:
            return self._client.decrby(key, amount)
        except Exception as e:
            logger.error(f'Redis DECR error for key {key}: {e}')
            return None
    
    def expire(self, key: str, ttl: int) -> bool:
        """
        Definir TTL em uma chave existente.
        
        Args:
            key: Chave
            ttl: TTL em segundos
            
        Returns:
            True se chave existe e TTL foi definido
        """
        if not self._client:
            return False
        
        try:
            return bool(self._client.expire(key, ttl))
        except Exception as e:
            logger.error(f'Redis EXPIRE error for key {key}: {e}')
            return False
    
    def ttl(self, key: str) -> int:
        """
        Obter TTL restante de uma chave.
        
        Args:
            key: Chave
            
        Returns:
            TTL em segundos, -1 se não tem TTL, -2 se não existe
        """
        if not self._client:
            return -2
        
        try:
            return self._client.ttl(key)
        except Exception as e:
            logger.error(f'Redis TTL error for key {key}: {e}')
            return -2
    
    def exists(self, key: str) -> bool:
        """
        Verificar se chave existe.
        
        Args:
            key: Chave
            
        Returns:
            True se existe
        """
        if not self._client:
            return False
        
        try:
            return bool(self._client.exists(key))
        except Exception as e:
            logger.error(f'Redis EXISTS error for key {key}: {e}')
            return False
    
    def clear_all(self) -> bool:
        """
        Limpar todo o cache (CUIDADO!).
        
        Returns:
            True se sucesso
        """
        if not self._client:
            return False
        
        try:
            self._client.flushdb()
            logger.warning('Redis cache cleared (FLUSHDB)')
            return True
        except Exception as e:
            logger.error(f'Redis FLUSHDB error: {e}')
            return False
    
    # =========================================================================
    # Hash operations (para objetos complexos)
    # =========================================================================
    
    def hget(self, name: str, key: str) -> Optional[Any]:
        """Obter campo de um hash."""
        if not self._client:
            return None
        
        try:
            value = self._client.hget(name, key)
            if value:
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            return None
        except Exception as e:
            logger.error(f'Redis HGET error: {e}')
            return None
    
    def hset(self, name: str, key: str, value: Any) -> bool:
        """Definir campo em um hash."""
        if not self._client:
            return False
        
        try:
            if not isinstance(value, str):
                value = json.dumps(value, default=str)
            self._client.hset(name, key, value)
            return True
        except Exception as e:
            logger.error(f'Redis HSET error: {e}')
            return False
    
    def hgetall(self, name: str) -> dict:
        """Obter todos os campos de um hash."""
        if not self._client:
            return {}
        
        try:
            data = self._client.hgetall(name)
            result = {}
            for k, v in data.items():
                try:
                    result[k] = json.loads(v)
                except (json.JSONDecodeError, TypeError):
                    result[k] = v
            return result
        except Exception as e:
            logger.error(f'Redis HGETALL error: {e}')
            return {}
    
    # =========================================================================
    # Pub/Sub (para invalidação de cache distribuído)
    # =========================================================================
    
    def publish(self, channel: str, message: Any) -> int:
        """
        Publicar mensagem em um canal.
        
        Args:
            channel: Nome do canal
            message: Mensagem (será serializada em JSON)
            
        Returns:
            Número de subscribers que receberam
        """
        if not self._client:
            return 0
        
        try:
            if not isinstance(message, str):
                message = json.dumps(message, default=str)
            return self._client.publish(channel, message)
        except Exception as e:
            logger.error(f'Redis PUBLISH error: {e}')
            return 0
