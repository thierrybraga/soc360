"""
SOC360 RAG Service
Busca dados CVE no banco e gera respostas enriquecidas pelo provedor de IA ativo.
"""
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, or_

from app.extensions.db import db
from app.models.nvd import Vulnerability
from app.services.core.ai_service import get_ai_service


logger = logging.getLogger(__name__)


class RAGService:
    """
    Servico RAG (Retrieval-Augmented Generation) para consulta de dados CVE.

    Combina busca em vulnerabilidades NVD com o provedor de IA configurado
    pela factory central da aplicacao.
    """

    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'critica': 'CRITICAL',
        'crítica': 'CRITICAL',
        'high': 'HIGH',
        'alta': 'HIGH',
        'medium': 'MEDIUM',
        'media': 'MEDIUM',
        'média': 'MEDIUM',
        'low': 'LOW',
        'baixa': 'LOW',
    }

    def __init__(self):
        self.ai_service = None
        logger.info("RAG Service inicializado")

    def _get_ai_service(self):
        """Obtem instancia do provedor de IA ativo por lazy loading."""
        if self.ai_service is None:
            self.ai_service = get_ai_service()
        return self.ai_service

    def search_and_generate_response(
        self,
        user_query: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Busca dados relevantes e gera resposta usando IA."""
        try:
            entities = self._extract_entities(user_query or '')
            relevant_data = self._search_relevant_data(user_query or '', entities)
            context = self._build_context(relevant_data, user_query or '')

            ai_service = self._get_ai_service()
            ai_response = ai_service.generate_chat_response(
                user_query,
                context,
                conversation_history,
            )

            return {
                'response': ai_response,
                'relevant_cves': relevant_data.get('vulnerabilities', []),
                'context_used': bool(context),
                'entities_found': entities,
            }

        except Exception as exc:
            logger.exception("Erro no RAG Service: %s", exc)
            return {
                'response': 'Desculpe, ocorreu um erro ao processar sua pergunta. Tente novamente.',
                'relevant_cves': [],
                'context_used': False,
                'entities_found': {},
            }

    def _extract_entities(self, query: str) -> Dict[str, List[str]]:
        """Extrai entidades relevantes da query do usuario."""
        entities = {
            'cve_ids': [],
            'products': [],
            'vendors': [],
            'severities': [],
            'years': [],
            'keywords': [],
        }
        query_lower = query.lower()

        entities['cve_ids'] = [
            cve.upper()
            for cve in re.findall(r'cve-\d{4}-\d{4,}', query_lower)
        ]
        entities['years'] = re.findall(r'\b(20\d{2})\b', query)

        for severity in self.SEVERITY_MAP:
            if severity in query_lower:
                entities['severities'].append(severity)

        common_products = [
            'windows',
            'linux',
            'apache',
            'nginx',
            'mysql',
            'postgresql',
            'wordpress',
            'drupal',
            'joomla',
            'php',
            'java',
            'python',
            'log4j',
            'spring',
            'struts',
            'tomcat',
            'iis',
            'exchange',
            'outlook',
            'chrome',
            'firefox',
            'safari',
            'edge',
        ]
        for product in common_products:
            if product in query_lower:
                entities['products'].append(product)

        common_vendors = [
            'microsoft',
            'google',
            'apple',
            'oracle',
            'adobe',
            'cisco',
            'vmware',
            'redhat',
            'ubuntu',
            'debian',
        ]
        for vendor in common_vendors:
            if vendor in query_lower:
                entities['vendors'].append(vendor)

        security_keywords = [
            'rce',
            'sql injection',
            'xss',
            'csrf',
            'buffer overflow',
            'privilege escalation',
            'denial of service',
            'dos',
            'ddos',
            'authentication bypass',
            'directory traversal',
            'lfi',
            'rfi',
        ]
        for keyword in security_keywords:
            if keyword in query_lower:
                entities['keywords'].append(keyword)

        return entities

    def _search_relevant_data(
        self,
        query: str,
        entities: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Busca vulnerabilidades relevantes no banco."""
        relevant_data = {
            'vulnerabilities': [],
            'total_found': 0,
        }

        try:
            base_query = Vulnerability.query
            filters = []

            if entities['cve_ids']:
                filters.append(
                    Vulnerability.cve_id.in_([cve.upper() for cve in entities['cve_ids']])
                )

            json_text_products = db.cast(Vulnerability.nvd_products_data, db.Text)
            json_text_vendors = db.cast(Vulnerability.nvd_vendors_data, db.Text)

            if entities['products']:
                filters.append(or_(*[
                    json_text_products.ilike(f'%{product}%')
                    for product in entities['products']
                ]))

            if entities['vendors']:
                filters.append(or_(*[
                    json_text_vendors.ilike(f'%{vendor}%')
                    for vendor in entities['vendors']
                ]))

            severity_filters = [
                Vulnerability.base_severity == self.SEVERITY_MAP[severity]
                for severity in entities['severities']
                if severity in self.SEVERITY_MAP
            ]
            if severity_filters:
                filters.append(or_(*severity_filters))

            if entities['years']:
                year_filters = []
                for year in entities['years']:
                    year_start = datetime(int(year), 1, 1)
                    year_end = datetime(int(year), 12, 31, 23, 59, 59)
                    year_filters.append(
                        and_(
                            Vulnerability.published_date >= year_start,
                            Vulnerability.published_date <= year_end,
                        )
                    )
                filters.append(or_(*year_filters))

            if entities['keywords'] or not any(entities.values()):
                text_search_terms = entities['keywords'] + [query]
                text_filters = [
                    Vulnerability.description.ilike(f'%{term}%')
                    for term in text_search_terms
                    if term and len(term) > 2
                ]
                if text_filters:
                    filters.append(or_(*text_filters))

            if filters:
                final_query = base_query.filter(or_(*filters))
            else:
                recent_date = datetime.utcnow() - timedelta(days=365)
                final_query = base_query.filter(Vulnerability.published_date >= recent_date)

            final_query = final_query.order_by(
                Vulnerability.cvss_score.desc(),
                Vulnerability.published_date.desc(),
            )

            vulnerabilities = final_query.limit(10).all()
            relevant_data['vulnerabilities'] = [
                self._vulnerability_to_dict(vulnerability)
                for vulnerability in vulnerabilities
            ]
            relevant_data['total_found'] = final_query.count()

        except Exception as exc:
            logger.exception("Erro na busca de dados RAG: %s", exc)

        return relevant_data

    def _vulnerability_to_dict(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Converte Vulnerability para dicionario compacto."""
        return {
            'cve_id': vulnerability.cve_id,
            'description': vulnerability.description,
            'base_severity': vulnerability.base_severity,
            'cvss_score': vulnerability.cvss_score,
            'published_date': vulnerability.published_date.isoformat() if vulnerability.published_date else None,
            'patch_available': vulnerability.patch_available,
            'products': list(vulnerability.products or []),
            'vendors': list(vulnerability.vendors or []),
            'weaknesses': [
                weakness.cwe_id
                for weakness in (vulnerability.weaknesses or [])
                if getattr(weakness, 'cwe_id', None)
            ],
        }

    def _build_context(self, relevant_data: Dict[str, Any], user_query: str) -> str:
        """Constroi contexto para a IA baseado nos dados encontrados."""
        vulnerabilities = relevant_data.get('vulnerabilities') or []
        if not vulnerabilities:
            return ''

        context_parts = [
            f"Consulta do usuario: {user_query}",
            f"Encontradas {len(vulnerabilities)} vulnerabilidades relevantes:",
            '',
        ]

        for index, vulnerability in enumerate(vulnerabilities[:5], 1):
            description = vulnerability.get('description') or ''
            context_parts.append(f"{index}. {vulnerability['cve_id']}")
            context_parts.append(
                f"   Severidade: {vulnerability['base_severity']} "
                f"(CVSS: {vulnerability['cvss_score']})"
            )
            context_parts.append(f"   Descricao: {description[:200]}...")

            if vulnerability['products']:
                context_parts.append(f"   Produtos: {', '.join(vulnerability['products'][:3])}")
            if vulnerability['vendors']:
                context_parts.append(f"   Vendors: {', '.join(vulnerability['vendors'][:3])}")

            published_date = vulnerability.get('published_date')
            context_parts.append(f"   Data: {published_date[:10] if published_date else 'N/A'}")
            context_parts.append('')

        remaining = len(vulnerabilities) - 5
        if remaining > 0:
            context_parts.append(f"... e mais {remaining} vulnerabilidades.")

        return '\n'.join(context_parts)

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Obtem detalhes especificos de uma CVE."""
        try:
            vulnerability = Vulnerability.get_by_cve_id(cve_id)
            return self._vulnerability_to_dict(vulnerability) if vulnerability else None
        except Exception as exc:
            logger.exception("Erro ao buscar CVE %s: %s", cve_id, exc)
            return None

    def get_trending_vulnerabilities(self, days: int = 30) -> List[Dict[str, Any]]:
        """Obtem vulnerabilidades recentes e criticas."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            vulnerabilities = Vulnerability.query.filter(
                and_(
                    Vulnerability.published_date >= cutoff_date,
                    Vulnerability.base_severity.in_(['CRITICAL', 'HIGH']),
                )
            ).order_by(
                Vulnerability.cvss_score.desc(),
                Vulnerability.published_date.desc(),
            ).limit(10).all()

            return [
                self._vulnerability_to_dict(vulnerability)
                for vulnerability in vulnerabilities
            ]

        except Exception as exc:
            logger.exception("Erro ao buscar vulnerabilidades em tendencia: %s", exc)
            return []
