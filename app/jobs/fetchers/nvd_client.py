"""
SOC360 NVD Client
HTTP client for NVD API with retry logic and rate limiting.
"""
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import current_app

from .base_fetcher import BaseFetcher
from .nvd_types import NVDResponse
from .nvd_rate_limiter import NVDRateLimiter

logger = logging.getLogger(__name__)


class NVDDownloadError(RuntimeError):
    """Raised when the NVD response stream is incomplete."""


class NVDFetcher(BaseFetcher):
    """
    HTTP client for NVD API 2.0.
    
    Features:
    - Rate limiting automático (5 req/30s sem key, 50 req/30s com key)
    - Retry com exponential backoff
    - Suporte a API key
    - Janelas de tempo de 120 dias (limitação NVD)
    """
    
    BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    # Rate limits
    RATE_LIMIT_NO_KEY = 5  # req por 30 segundos
    RATE_LIMIT_WITH_KEY = 50  # req por 30 segundos
    RATE_WINDOW = 30  # segundos
    
    # Limites da API
    MAX_RESULTS_PER_PAGE = 2000
    MAX_DATE_RANGE_DAYS = 120

    @staticmethod
    def _format_nvd_datetime(value: datetime) -> str:
        """Format datetimes for NVD without dropping millisecond precision."""
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat(timespec='milliseconds')
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Inicializar fetcher.
        
        Args:
            api_key: API key do NVD (opcional, mas recomendado)
        """
        super().__init__(timeout=60, user_agent='SOC360/3.0 (Vulnerability Scanner)')
        
        self.api_key = api_key or current_app.config.get('NVD_API_KEY')
        
        # Rate limiting
        rate_limit = self.RATE_LIMIT_WITH_KEY if self.api_key else self.RATE_LIMIT_NO_KEY
        self.rate_limiter = NVDRateLimiter(rate_limit, self.RATE_WINDOW)
        
        # Add API key to headers if available
        if self.api_key:
            self.session.headers['apiKey'] = self.api_key
        
        logger.info(
            f'NVDFetcher initialized (rate limit: {rate_limit} req/{self.RATE_WINDOW}s)'
        )
    
    def fetch_page(
        self,
        start_index: int = 0,
        results_per_page: int = 2000,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        keyword_search: Optional[str] = None,
        cve_id: Optional[str] = None
    ) -> Optional[NVDResponse]:
        """
        Buscar uma página de CVEs da API.
        
        Args:
            start_index: Índice inicial (paginação)
            results_per_page: Resultados por página (max 2000)
            pub_start_date: Data inicial de publicação
            pub_end_date: Data final de publicação
            last_mod_start_date: Data inicial de modificação
            last_mod_end_date: Data final de modificação
            keyword_search: Busca por palavra-chave
            cve_id: CVE específico
            
        Returns:
            NVDResponse ou None se erro
        """
        # Rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Construir parâmetros
        params = {
            'startIndex': start_index,
            'resultsPerPage': min(results_per_page, self.MAX_RESULTS_PER_PAGE)
        }
        
        # Filtros de data
        if pub_start_date:
            params['pubStartDate'] = self._format_nvd_datetime(pub_start_date)
        if pub_end_date:
            params['pubEndDate'] = self._format_nvd_datetime(pub_end_date)
        if last_mod_start_date:
            params['lastModStartDate'] = self._format_nvd_datetime(last_mod_start_date)
        if last_mod_end_date:
            params['lastModEndDate'] = self._format_nvd_datetime(last_mod_end_date)
        
        # Outros filtros
        if keyword_search:
            params['keywordSearch'] = keyword_search
        if cve_id:
            params['cveId'] = cve_id
        
        try:
            logger.debug(f'Fetching NVD API: startIndex={start_index}')
            
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            
            data = response.json()
            
            return NVDResponse(
                vulnerabilities=data.get('vulnerabilities', []),
                results_per_page=data.get('resultsPerPage', 0),
                start_index=data.get('startIndex', 0),
                total_results=data.get('totalResults', 0),
                timestamp=datetime.now(timezone.utc)
            )
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error('NVD API: Access forbidden. Check API key.')
            elif e.response.status_code == 429:
                logger.warning('NVD API: Rate limit exceeded. Waiting...')
                time.sleep(30)
            else:
                logger.error(f'NVD API HTTP error: {e}')
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f'NVD API request error: {e}')
            return None
        
        except Exception as e:
            logger.error(f'NVD API unexpected error: {e}')
            return None
    
    def fetch_all_pages(
        self,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        keyword_search: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        cancel_callback: Optional[Callable[[], bool]] = None
    ) -> List[Dict]:
        """
        Buscar todas as páginas para um período.
        
        Args:
            pub_start_date: Data inicial de publicação
            pub_end_date: Data final de publicação
            last_mod_start_date: Data inicial de modificação
            last_mod_end_date: Data final de modificação
            keyword_search: Busca por palavra-chave
            progress_callback: Callback(current, total) para progresso
            cancel_callback: Callback que retorna True para interromper paginação
            
        Returns:
            Lista de todos os CVEs
        """
        all_vulnerabilities = []
        start_index = 0
        total_results = None
        
        while True:
            if cancel_callback and cancel_callback():
                logger.info('NVD fetch cancelled before page startIndex=%s', start_index)
                break

            response = self.fetch_page(
                start_index=start_index,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                last_mod_start_date=last_mod_start_date,
                last_mod_end_date=last_mod_end_date,
                keyword_search=keyword_search,
            )
            
            if response is None:
                if start_index == 0:
                    raise NVDDownloadError("Failed to connect to NVD API. Check API Key and connectivity.")
                raise NVDDownloadError(
                    f'Failed to fetch NVD page at startIndex={start_index}; download is incomplete.'
                )

            if cancel_callback and cancel_callback():
                logger.info('NVD fetch cancelled after page startIndex=%s', start_index)
                break
            
            if total_results is None:
                total_results = response.total_results
                logger.info(f'Total CVEs to fetch: {total_results}')
            
            all_vulnerabilities.extend(response.vulnerabilities)

            # Callback de progresso
            if progress_callback:
                progress_callback(len(all_vulnerabilities), total_results)

            page_count = len(response.vulnerabilities)

            # Guard anti-loop-infinito: se a página não trouxe nada mas o total
            # diz que há mais, o download está incompleto e não pode avançar
            # watermark/checkpoint como sucesso.
            if page_count <= 0:
                if total_results and start_index < total_results:
                    raise NVDDownloadError(
                        f'NVD returned an empty page at startIndex={start_index} '
                        f'with totalResults={total_results}; download is incomplete.'
                    )
                logger.warning(
                    'NVD page returned 0 results at startIndex=%s (total=%s). '
                    'Stopping pagination to avoid infinite loop.',
                    start_index, total_results
                )
                break

            # Verificar se terminou
            if start_index + page_count >= total_results:
                break

            start_index += page_count

        return all_vulnerabilities
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Buscar um CVE específico.
        
        Args:
            cve_id: ID do CVE (ex: CVE-2021-44228)
            
        Returns:
            Dados do CVE ou None
        """
        response = self.fetch_page(cve_id=cve_id.upper())
        
        if response and response.vulnerabilities:
            return response.vulnerabilities[0]
        
        return None
    
    def generate_date_windows(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[tuple]:
        """
        Gerar janelas de 120 dias para full sync.
        
        Args:
            start_date: Data inicial
            end_date: Data final
            
        Returns:
            Lista de tuplas (start, end) de 120 dias cada
        """
        windows = []
        current = start_date
        
        while current < end_date:
            window_end = min(
                current + timedelta(days=self.MAX_DATE_RANGE_DAYS),
                end_date
            )
            windows.append((current, window_end))
            if window_end >= end_date:
                break
            current = window_end
        
        return windows
