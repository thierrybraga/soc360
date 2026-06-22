import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from .base_fetcher import BaseFetcher

logger = logging.getLogger(__name__)

class EUVDFetcher(BaseFetcher):
    """
    Fetcher para a API da European Vulnerability Database (EUVD).
    Fonte: https://euvd.enisa.europa.eu/apidoc
    """
    
    BASE_URL = "https://euvdservices.enisa.europa.eu/api/"
    
    def __init__(self, timeout: int = 30):
        # A API da ENISA fica atrás de um WAF (Cloudflare) que responde 403 a
        # User-Agents não-browser (ex.: 'SOC360/1.0'). Usamos um UA de browser
        # + headers de navegador para evitar o bloqueio.
        super().__init__(
            timeout,
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            ),
        )
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })

    def fetch_search(
        self,
        page: int = 0,
        size: int = 100,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Buscar vulnerabilidades usando o endpoint de busca.
        
        Args:
            page: Número da página (0-indexado)
            size: Tamanho da página (max 100)
            from_date: Data inicial (YYYY-MM-DD)
            to_date: Data final (YYYY-MM-DD)
            **kwargs: Outros filtros (vendor, product, etc)
        """
        endpoint = "search"
        params = {
            "page": page,
            "size": size,
            **kwargs
        }
        
        if from_date:
            params["fromDate"] = from_date
        if to_date:
            params["toDate"] = to_date
            
        return self._make_request(endpoint, params)

    def fetch_latest(self) -> List[Dict[str, Any]]:
        """Buscar as últimas vulnerabilidades registradas."""
        return self._make_request("lastvulnerabilities")

    def fetch_exploited(self) -> List[Dict[str, Any]]:
        """Buscar as últimas vulnerabilidades exploradas (KEV)."""
        return self._make_request("exploitedvulnerabilities")

    def fetch_eu_csirt(self) -> List[Dict[str, Any]]:
        """Buscar vulnerabilidades coordenadas pela EU CSIRT."""
        return self._make_request("eucsirtcoordinatedvulnerabilities")

    def fetch_critical(self) -> List[Dict[str, Any]]:
        """Buscar vulnerabilidades críticas recentes."""
        return self._make_request("criticalvulnerabilities")

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """Executar requisição HTTP com tratamento de erros."""
        url = urljoin(self.BASE_URL, endpoint)
        
        try:
            logger.debug(f"Fetching EUVD URL: {url} Params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"EUVD API Error {response.status_code}: {response.text}")
                response.raise_for_status()
                
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise

