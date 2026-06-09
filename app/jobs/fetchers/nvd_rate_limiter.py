"""
SOC360 NVD Rate Limiter
Rate limiting logic for NVD API.
"""
import logging
import threading
import time
from typing import List

logger = logging.getLogger(__name__)


class NVDRateLimiter:
    """
    Rate limiter for NVD API requests.

    - No key: 5 req/30s
    - With key: 50 req/30s

    Thread-safe: a janela deslizante de timestamps é protegida por Lock para
    suportar fetchers compartilhados/concorrentes sem corromper a lista.
    """

    def __init__(self, rate_limit: int, window: int = 30):
        self.rate_limit = rate_limit
        self.window = window
        self._request_times: List[float] = []
        self._lock = threading.Lock()

    def wait_if_needed(self):
        """Aguardar se necessário para respeitar rate limit."""
        with self._lock:
            now = time.time()

            # Limpar timestamps antigos
            self._request_times = [
                t for t in self._request_times
                if now - t < self.window
            ]

            # Se atingiu limite, aguardar
            if len(self._request_times) >= self.rate_limit:
                oldest = min(self._request_times)
                sleep_time = self.window - (now - oldest) + 0.1

                if sleep_time > 0:
                    logger.debug(f'Rate limit reached, sleeping {sleep_time:.1f}s')
                    time.sleep(sleep_time)

            # Registrar request
            self._request_times.append(time.time())