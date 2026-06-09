"""
SOC360 Bulk Database Service
Operações de inserção em lote para CVEs do NVD.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from sqlalchemy import text, inspect, literal_column, bindparam, delete
from sqlalchemy.dialects.sqlite import insert as _sqlite_insert
from sqlalchemy.dialects.postgresql import insert as _pg_insert


def _is_sqlite() -> bool:
    """Runtime check: returns True if the active database is SQLite.

    Uses current_app config so it correctly handles the PostgreSQL→SQLite
    fallback that happens when PostgreSQL is unreachable at startup.
    """
    from flask import current_app
    uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    return uri.startswith('sqlite')


def _insert():
    """Return the correct dialect insert function for the active database."""
    return _sqlite_insert if _is_sqlite() else _pg_insert


def _dedupe(records: list, key_fields: tuple) -> list:
    """Remove duplicatas por chave de conflito, preservando a ÚLTIMA ocorrência.

    PostgreSQL recusa um ``INSERT ... ON CONFLICT DO UPDATE`` cujo VALUES contém
    a mesma chave de conflito duas vezes ("command cannot affect row a second
    time"). O NVD pode repetir o mesmo CVE entre páginas durante modificação
    ativa; sem deduplicar, a exceção derruba o batch inteiro (perda de dados).
    """
    deduped = {}
    for rec in records:
        key = tuple(rec.get(f) for f in key_fields)
        deduped[key] = rec  # última ocorrência vence
    return list(deduped.values())


def _utcnow_naive() -> datetime:
    """Return UTC now as naive datetime for existing DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from app.extensions import db
from app.models.nvd import Vulnerability, CvssMetric, Weakness, Reference, Mitigation, Credit, AffectedProduct
from app.models.system import SyncMetadata


logger = logging.getLogger(__name__)


class BulkDatabaseService:
    """
    Serviço para inserção em lote de CVEs no banco de dados.
    
    Features:
    - Upsert eficiente com ON CONFLICT
    - Batch processing com controle de memória
    - Normalização de vendors/products
    - Progress tracking
    """
    
    BATCH_SIZE = 500
    
    def __init__(self):
        self.stats = {
            'inserted': 0,
            'updated': 0,
            'errors': 0,
            'skipped': 0
        }
    
    def reset_stats(self):
        """Resetar estatísticas de processamento."""
        self.stats = {
            'inserted': 0,
            'updated': 0,
            'errors': 0,
            'skipped': 0
        }

    def clear_all_data(self) -> None:
        """
        Limpar todos os dados de vulnerabilidades (TRUNCATE/DELETE).
        Usado para Full Sync forçado.
        """
        logger.info("Clearing existing vulnerability data...")
        try:
            # Ensure all tables exist
            db.create_all()

            # Prefer the public bind because all NVD tables live there.
            engine = db.engines.get('public') or db.engine
            inspector = inspect(engine)

            if inspector.has_table("vulnerabilities"):
                try:
                    with engine.connect() as conn:
                        if engine.dialect.name == 'sqlite':
                            # SQLite: no TRUNCATE, no CASCADE — delete in order
                            for tbl in (
                                'cvss_metrics',
                                'weaknesses',
                                'references',
                                'credits',
                                'affected_products',
                                'mitigations',
                                'cve_products',
                                'cve_vendors',
                                'version_ref',
                                'cve_d3fend_correlations',
                                'vulnerabilities',
                            ):
                                if inspector.has_table(tbl):
                                    conn.execute(text(f'DELETE FROM "{tbl}"'))
                        else:
                            conn.execute(text('TRUNCATE TABLE vulnerabilities CASCADE'))
                        conn.commit()
                    logger.info("Data cleared successfully.")
                except Exception as trunc_err:
                    logger.warning(f"Could not clear 'vulnerabilities' table: {trunc_err}")
            else:
                logger.warning("Table 'vulnerabilities' not found. Skipping clear.")

        except Exception as e:
            logger.error(f"Error clearing data: {e}")

    @contextmanager
    def bulk_session(self):
        """Context manager para operações em lote."""
        try:
            yield db.session
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f'Bulk session error: {e}')
            raise
    
    def process_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        progress_callback: Optional[callable] = None,
        fail_on_error: bool = True,
    ) -> Dict[str, int]:
        """
        Processar lista de vulnerabilidades do NVD.
        
        Args:
            vulnerabilities: Lista de CVEs do NVD API
            progress_callback: Callback(processed, total, stats)
            fail_on_error: Interrompe o processamento no primeiro batch com erro
            
        Returns:
            Estatísticas de processamento
        """
        total = len(vulnerabilities)
        processed = 0
        
        # Processar em batches
        for i in range(0, total, self.BATCH_SIZE):
            batch = vulnerabilities[i:i + self.BATCH_SIZE]
            
            try:
                self._process_batch(batch)
                processed += len(batch)
                
                if progress_callback:
                    progress_callback(processed, total, self.stats)
                    
            except Exception as e:
                logger.error(f'Batch processing error: {e}')
                self.stats['errors'] += len(batch)
                if fail_on_error:
                    raise
        
        logger.info(
            f'Processing complete: {self.stats["inserted"]} inserted, '
            f'{self.stats["updated"]} updated, '
            f'{self.stats["errors"]} errors'
        )
        
        return self.stats
    
    def _process_batch(self, batch: List[Dict]) -> None:
        """Processar um batch de vulnerabilidades."""
        logger.info(f"Processing batch of {len(batch)} items")
        vuln_records = []
        cvss_records = []
        weakness_records = []
        reference_records = []
        
        credit_records = []
        affected_product_records = []
        cve_ids_in_batch = []

        for item in batch:
            cve = item.get('cve', {})
            cve_id = cve.get('id')

            if not cve_id:
                self.stats['skipped'] += 1
                continue

            cve_ids_in_batch.append(cve_id)

            # Extrair dados da vulnerabilidade
            vuln_data = self._extract_vulnerability_data(cve)
            if vuln_data:
                vuln_records.append(vuln_data)

            # Extrair métricas CVSS
            cvss_data = self._extract_cvss_data(cve)
            cvss_records.extend(cvss_data)

            # Extrair weaknesses (CWEs)
            weakness_data = self._extract_weakness_data(cve)
            weakness_records.extend(weakness_data)

            # Extrair referências
            ref_data = self._extract_reference_data(cve)
            reference_records.extend(ref_data)

            # Extrair créditos
            credit_data = self._extract_credits_data(cve)
            credit_records.extend(credit_data)

            # Extrair produtos afetados detalhados
            ap_data = self._extract_affected_product_records(cve)
            affected_product_records.extend(ap_data)

        # Inserir em lote
        with self.bulk_session():
            if vuln_records:
                self._upsert_vulnerabilities(vuln_records)

            if cvss_records:
                self._upsert_cvss(cvss_records)

            if weakness_records:
                self._upsert_weaknesses(weakness_records)

            if reference_records:
                self._upsert_references(reference_records)

            cve_ids_in_batch = list(dict.fromkeys(cve_ids_in_batch))

            if credit_records:
                self._upsert_credits(cve_ids_in_batch, credit_records)

            if affected_product_records:
                self._upsert_affected_products(cve_ids_in_batch, affected_product_records)
    
    def _extract_vulnerability_data(self, cve: Dict) -> Optional[Dict]:
        """Extrair dados da vulnerabilidade."""
        cve_id = cve.get('id')

        # Descrição em inglês
        descriptions = cve.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            descriptions[0]['value'] if descriptions else ''
        )

        # Datas
        published = cve.get('published')
        modified = cve.get('lastModified')

        # Métricas CVSS (pegar maior severidade + versão + vector)
        metrics = cve.get('metrics', {})
        cvss_score, severity, cvss_version, cvss_vector = self._get_highest_cvss(metrics)

        # Vendors e Products (do configurations)
        vendors_data, products_data = self._extract_affected_products(cve)

        # CISA KEV fields
        cisa_exploit_add = cve.get('cisaExploitAdd')
        cisa_action_due = cve.get('cisaActionDue')
        cisa_required_action = cve.get('cisaRequiredAction')
        cisa_vuln_name = cve.get('cisaVulnerabilityName')

        # Exploit / patch flags derived from references
        references = cve.get('references', [])
        exploit_available = any(
            'exploit' in [t.lower() for t in (r.get('tags') or [])]
            for r in references
        )
        patch_refs = [
            r for r in references
            if 'patch' in [t.lower() for t in (r.get('tags') or [])]
        ]
        patch_available = len(patch_refs) > 0
        patch_url = patch_refs[0]['url'] if patch_refs else None

        return {
            'cve_id': cve_id,
            'description': description[:10000] if description else '',
            'description_lang': 'en',
            'published_date': self._parse_dt(published),
            'last_modified_date': self._parse_dt(modified),
            'vuln_status': cve.get('vulnStatus'),
            'cvss_score': cvss_score,
            'base_severity': severity,
            'cvss_version': cvss_version,
            'cvss_vector_string': cvss_vector,
            'nvd_vendors_data': vendors_data,
            'nvd_products_data': products_data,
            'cpe_configurations': cve.get('configurations'),
            'cisa_exploit_add': self._parse_dt(cisa_exploit_add),
            'cisa_action_due': self._parse_dt(cisa_action_due),
            'cisa_required_action': cisa_required_action,
            'cisa_notes': cisa_vuln_name,
            'is_in_cisa_kev': cisa_exploit_add is not None,
            'exploit_available': exploit_available,
            'patch_available': patch_available,
            'patch_url': patch_url[:2048] if patch_url else None,
            'raw_nvd_data': cve,
        }

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime, tolerant of missing timezone."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None
    
    def _get_highest_cvss(self, metrics: Dict) -> tuple:
        """Obter maior score CVSS, severidade, versão e vector string."""
        score = None
        severity = None
        version = None
        vector = None

        version_map = {
            'cvssMetricV40': '4.0',
            'cvssMetricV31': '3.1',
            'cvssMetricV30': '3.0',
            'cvssMetricV2': '2.0',
        }

        # Priority: v4.0 > v3.1 > v3.0 > v2.0
        for metric_key, ver_label in version_map.items():
            if metric_key in metrics and metrics[metric_key]:
                metric = metrics[metric_key][0]
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity') or metric.get('baseSeverity')
                vector = cvss_data.get('vectorString')
                version = ver_label
                break

        # Derive severity from score when the API field is absent (common for CVSSv2)
        if not severity and score is not None:
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

        return score, severity, version, vector
    
    @staticmethod
    def _iter_cpe_matches(nodes: List[Dict]):
        """Yield all cpeMatch entries from nodes, including nested children."""
        for node in nodes:
            yield from node.get('cpeMatch', [])
            # NVD API nests CPE data under 'children' for AND/OR compound configs
            children = node.get('children', [])
            if children:
                yield from BulkDatabaseService._iter_cpe_matches(children)

    def _extract_affected_products(self, cve: Dict) -> tuple:
        """Extrair vendors e products afetados."""
        vendors = set()
        products = {}

        configurations = cve.get('configurations', [])

        for config in configurations:
            nodes = config.get('nodes', [])
            for cpe_match in self._iter_cpe_matches(nodes):
                criteria = cpe_match.get('criteria', '')

                # Parse CPE 2.3: cpe:2.3:part:vendor:product:version:...
                parts = criteria.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]

                    if vendor and vendor != '*':
                        vendors.add(vendor)

                        if product and product != '*':
                            if vendor not in products:
                                products[vendor] = []
                            if product not in products[vendor]:
                                products[vendor].append(product)

        return list(vendors), products
    
    def _extract_cvss_data(self, cve: Dict) -> List[Dict]:
        """Extrair todas as métricas CVSS."""
        cve_id = cve.get('id')
        records = []
        metrics = cve.get('metrics', {})
        
        # Helper to ensure all fields exist
        def create_record(version, source, type_, cvss_data, metric_data):
            return {
                'cve_id': cve_id,
                'version': version,
                'source': source,
                'type': type_,
                'base_score': cvss_data.get('baseScore'),
                'base_severity': cvss_data.get('baseSeverity') or metric_data.get('baseSeverity'),
                'vector_string': cvss_data.get('vectorString'),
                'exploitability_score': metric_data.get('exploitabilityScore'),
                'impact_score': metric_data.get('impactScore'),
                # V3/V4 fields (default None)
                'attack_vector': cvss_data.get('attackVector'),
                'attack_complexity': cvss_data.get('attackComplexity'),
                'privileges_required': cvss_data.get('privilegesRequired'),
                'user_interaction': cvss_data.get('userInteraction'),
                'scope': cvss_data.get('scope'),
                'confidentiality_impact': cvss_data.get('confidentialityImpact'),
                'integrity_impact': cvss_data.get('integrityImpact'),
                'availability_impact': cvss_data.get('availabilityImpact'),
                # V2 fields (default None)
                'access_vector': cvss_data.get('accessVector'),
                'access_complexity': cvss_data.get('accessComplexity'),
                'authentication': cvss_data.get('authentication')
            }

        # CVSS v4.0
        for metric in metrics.get('cvssMetricV40', []):
            records.append(create_record(
                '4.0', metric.get('source'), metric.get('type'),
                metric.get('cvssData', {}), metric
            ))
        
        # CVSS v3.1
        for metric in metrics.get('cvssMetricV31', []):
            records.append(create_record(
                '3.1', metric.get('source'), metric.get('type'),
                metric.get('cvssData', {}), metric
            ))
        
        # CVSS v3.0
        for metric in metrics.get('cvssMetricV30', []):
            records.append(create_record(
                '3.0', metric.get('source'), metric.get('type'),
                metric.get('cvssData', {}), metric
            ))
        
        # CVSS v2
        for metric in metrics.get('cvssMetricV2', []):
            records.append(create_record(
                '2.0', metric.get('source'), metric.get('type'),
                metric.get('cvssData', {}), metric
            ))
        
        return records
    
    def _extract_weakness_data(self, cve: Dict) -> List[Dict]:
        """Extrair CWEs associados."""
        cve_id = cve.get('id')
        records = []
        
        for weakness in cve.get('weaknesses', []):
            source = weakness.get('source')
            weakness_type = weakness.get('type')
            
            for desc in weakness.get('description', []):
                cwe_id = desc.get('value')
                if cwe_id:
                    records.append({
                        'cve_id': cve_id,
                        'cwe_id': cwe_id,
                        'source': source,
                        'type': weakness_type
                    })
        
        return records
    
    def _extract_reference_data(self, cve: Dict) -> List[Dict]:
        """Extrair referências."""
        cve_id = cve.get('id')
        records = []
        seen_urls = set()
        
        for ref in cve.get('references', []):
            url = ref.get('url')
            if url:
                # Ensure URL is clean and truncated if necessary (though Text is unlimited, good to be safe)
                clean_url = url.replace('\x00', '')[:2048]
                
                # Skip duplicates within the same CVE
                if clean_url in seen_urls:
                    continue
                seen_urls.add(clean_url)
                
                # Ensure tags is a list of strings
                raw_tags = ref.get('tags')
                tags = list(raw_tags) if raw_tags else []
                
                # Compute derived fields
                tags_lower = [t.lower() for t in tags]
                is_patch = 'patch' in tags_lower
                is_vendor_advisory = 'vendor advisory' in tags_lower
                is_exploit = 'exploit' in tags_lower
                
                records.append({
                    'cve_id': cve_id,
                    'url': clean_url,
                    'source': ref.get('source'),
                    'tags': tags,
                    'is_patch': is_patch,
                    'is_vendor_advisory': is_vendor_advisory,
                    'is_exploit': is_exploit
                })
        
        return records
    
    def _extract_credits_data(self, cve: Dict) -> List[Dict]:
        """Extrair créditos/contribuidores da CVE."""
        cve_id = cve.get('id')
        records = []
        for credit in cve.get('credits', []):
            value = credit.get('value', '')
            if value:
                records.append({
                    'cve_id': cve_id,
                    'value': value[:255],
                    'user': credit.get('user', '')[:255] if credit.get('user') else None,
                    'type': credit.get('type', '')[:100] if credit.get('type') else None,
                })
        return records

    def _extract_affected_product_records(self, cve: Dict) -> List[Dict]:
        """Extrair produtos afetados com versões e plataformas dos nós CPE."""
        cve_id = cve.get('id')
        seen = {}  # (vendor, product) -> {versions, platforms}

        for config in cve.get('configurations', []):
            nodes = config.get('nodes', [])
            for cpe_match in self._iter_cpe_matches(nodes):
                criteria = cpe_match.get('criteria', '')
                parts = criteria.split(':')
                if len(parts) < 5:
                    continue
                vendor = parts[3]
                product = parts[4]
                if not vendor or vendor == '*' or not product or product == '*':
                    continue

                # Só consideramos CPEs marcados como vulneráveis — evita criar
                # AffectedProduct vazio para um par (vendor,product) que aparece
                # apenas em nós não-vulneráveis (condição de "running on").
                if not cpe_match.get('vulnerable', True):
                    continue

                key = (vendor, product)
                if key not in seen:
                    seen[key] = {'versions': [], 'platforms': set()}

                # Build version range descriptor
                ver_parts = []
                if cpe_match.get('versionStartIncluding'):
                    ver_parts.append(f">={cpe_match['versionStartIncluding']}")
                if cpe_match.get('versionStartExcluding'):
                    ver_parts.append(f">{cpe_match['versionStartExcluding']}")
                if cpe_match.get('versionEndIncluding'):
                    ver_parts.append(f"<={cpe_match['versionEndIncluding']}")
                if cpe_match.get('versionEndExcluding'):
                    ver_parts.append(f"<{cpe_match['versionEndExcluding']}")

                # Exact version from CPE
                cpe_ver = parts[5] if len(parts) > 5 else '*'
                if not ver_parts and cpe_ver not in ('*', '-', ''):
                    ver_parts.append(cpe_ver)

                # Platform from CPE (edition/sw_edition/target_hw)
                if len(parts) > 10 and parts[10] not in ('*', '-', ''):
                    seen[key]['platforms'].add(parts[10])

                if ver_parts:
                    ver_str = ' '.join(ver_parts)
                    if ver_str not in seen[key]['versions']:
                        seen[key]['versions'].append(ver_str)

        records = []
        for (vendor, product), data in seen.items():
            records.append({
                'cve_id': cve_id,
                'vendor': vendor[:255],
                'product': product[:255],
                'versions': data['versions'] or None,
                'platforms': list(data['platforms']) or None,
            })
        return records

    def _upsert_credits(self, cve_ids: List[str], records: List[Dict]) -> None:
        """Substituir créditos: delete existing + insert new."""
        if not cve_ids:
            return
        cve_ids = list(dict.fromkeys(cve_ids))
        records = _dedupe(records, ('cve_id', 'value', 'type', 'user'))
        db.session.execute(delete(Credit).where(Credit.cve_id.in_(cve_ids)))
        if records:
            ins = _insert()
            stmt = ins(Credit).values(records)
            stmt = stmt.prefix_with('OR IGNORE') if _is_sqlite() else stmt.on_conflict_do_nothing()
            db.session.execute(stmt)

    def _upsert_affected_products(self, cve_ids: List[str], records: List[Dict]) -> None:
        """Substituir produtos afetados: delete existing + insert new."""
        if not cve_ids:
            return
        cve_ids = list(dict.fromkeys(cve_ids))
        records = _dedupe(records, ('cve_id', 'vendor', 'product'))
        db.session.execute(delete(AffectedProduct).where(AffectedProduct.cve_id.in_(cve_ids)))
        if records:
            ins = _insert()
            use_sqlite = _is_sqlite()
            chunk_size = 500
            for i in range(0, len(records), chunk_size):
                chunk = records[i:i + chunk_size]
                stmt = ins(AffectedProduct).values(chunk)
                stmt = stmt.prefix_with('OR IGNORE') if use_sqlite else stmt.on_conflict_do_nothing()
                db.session.execute(stmt)

    def _upsert_vulnerabilities(self, records: List[Dict]) -> None:
        """Upsert de vulnerabilidades."""
        if not records:
            return

        # Dedup por cve_id: evita o erro ON CONFLICT do Postgres quando o mesmo
        # CVE aparece duas vezes no batch (perda de dados).
        records = _dedupe(records, ('cve_id',))

        use_sqlite = _is_sqlite()
        ins = _insert()
        chunk_size = 1000
        total_records = len(records)

        for i in range(0, total_records, chunk_size):
            chunk = records[i:i + chunk_size]
            existing_ids = set()
            if use_sqlite:
                cve_ids = [record['cve_id'] for record in chunk]
                existing_ids = {
                    row[0]
                    for row in db.session.query(Vulnerability.cve_id)
                    .filter(Vulnerability.cve_id.in_(cve_ids))
                    .all()
                }

            stmt = ins(Vulnerability).values(chunk)

            update_dict = {
                'description': stmt.excluded.description,
                'description_lang': stmt.excluded.description_lang,
                'published_date': stmt.excluded.published_date,
                'last_modified_date': stmt.excluded.last_modified_date,
                'vuln_status': stmt.excluded.vuln_status,
                'cvss_score': stmt.excluded.cvss_score,
                'base_severity': stmt.excluded.base_severity,
                'cvss_version': stmt.excluded.cvss_version,
                'cvss_vector_string': stmt.excluded.cvss_vector_string,
                'nvd_vendors_data': stmt.excluded.nvd_vendors_data,
                'nvd_products_data': stmt.excluded.nvd_products_data,
                'cpe_configurations': stmt.excluded.cpe_configurations,
                'cisa_exploit_add': stmt.excluded.cisa_exploit_add,
                'cisa_action_due': stmt.excluded.cisa_action_due,
                'cisa_required_action': stmt.excluded.cisa_required_action,
                'cisa_notes': stmt.excluded.cisa_notes,
                'is_in_cisa_kev': stmt.excluded.is_in_cisa_kev,
                'exploit_available': stmt.excluded.exploit_available,
                'patch_available': stmt.excluded.patch_available,
                'patch_url': stmt.excluded.patch_url,
                'raw_nvd_data': stmt.excluded.raw_nvd_data,
                'updated_at': _utcnow_naive()
            }

            stmt = stmt.on_conflict_do_update(
                index_elements=['cve_id'],
                set_=update_dict
            )

            if not use_sqlite:
                # PostgreSQL: use RETURNING + xmax trick to count inserts vs updates
                stmt = stmt.returning(literal_column('(xmax = 0)::boolean'))
                result = db.session.execute(stmt)
                rows = result.fetchall()
                self.stats['inserted'] += sum(1 for r in rows if r[0])
                self.stats['updated'] += sum(1 for r in rows if not r[0])
            else:
                db.session.execute(stmt)
                self.stats['inserted'] += sum(1 for record in chunk if record['cve_id'] not in existing_ids)
                self.stats['updated'] += sum(1 for record in chunk if record['cve_id'] in existing_ids)
    
    def _upsert_cvss(self, records: List[Dict]) -> None:
        """Upsert de métricas CVSS."""
        if not records:
            return

        records = _dedupe(records, ('cve_id', 'version', 'source'))

        ins = _insert()
        chunk_size = 1000
        total_records = len(records)

        for i in range(0, total_records, chunk_size):
            chunk = records[i:i + chunk_size]
            stmt = ins(CvssMetric).values(chunk)

            stmt = stmt.on_conflict_do_update(
                index_elements=['cve_id', 'version', 'source'],
                set_={
                    'type': stmt.excluded.type,
                    'base_score': stmt.excluded.base_score,
                    'base_severity': stmt.excluded.base_severity,
                    'vector_string': stmt.excluded.vector_string,
                    'attack_vector': stmt.excluded.attack_vector,
                    'attack_complexity': stmt.excluded.attack_complexity,
                    'privileges_required': stmt.excluded.privileges_required,
                    'user_interaction': stmt.excluded.user_interaction,
                    'scope': stmt.excluded.scope,
                    'confidentiality_impact': stmt.excluded.confidentiality_impact,
                    'integrity_impact': stmt.excluded.integrity_impact,
                    'availability_impact': stmt.excluded.availability_impact,
                    'exploitability_score': stmt.excluded.exploitability_score,
                    'impact_score': stmt.excluded.impact_score,
                    'access_vector': stmt.excluded.access_vector,
                    'access_complexity': stmt.excluded.access_complexity,
                    'authentication': stmt.excluded.authentication,
                    'updated_at': _utcnow_naive()
                }
            )
            
            db.session.execute(stmt)
    
    def _upsert_weaknesses(self, records: List[Dict]) -> None:
        """Upsert de CWEs."""
        if not records:
            return

        records = _dedupe(records, ('cve_id', 'cwe_id', 'source'))

        ins = _insert()
        chunk_size = 1000
        total_records = len(records)

        for i in range(0, total_records, chunk_size):
            chunk = records[i:i + chunk_size]
            stmt = ins(Weakness).values(chunk)
            
            stmt = stmt.on_conflict_do_update(
                index_elements=['cve_id', 'cwe_id', 'source'],
                set_={
                    'type': stmt.excluded.type,
                    'updated_at': _utcnow_naive()
                }
            )
            
            db.session.execute(stmt)
    
    def _upsert_references(self, records: List[Dict]) -> None:
        """Upsert de referências."""
        if not records:
            return

        # Dedup por (cve_id, url): refs duplicadas entre CVEs repetidos no batch
        # causariam erro ON CONFLICT no Postgres.
        records = _dedupe(records, ('cve_id', 'url'))

        # Chunking to avoid parameter limit (65535 parameters max in Postgres)
        # Each reference has ~9 parameters. 65535 / 9 ≈ 7281.
        # We use 1000 as a safe chunk size.
        chunk_size = 1000
        total_records = len(records)

        ins = _insert()
        for i in range(0, total_records, chunk_size):
            chunk = records[i:i + chunk_size]
            stmt = ins(Reference).values(chunk)
            stmt = stmt.on_conflict_do_update(
                index_elements=['cve_id', 'url'],
                set_={
                    'source': stmt.excluded.source,
                    'tags': stmt.excluded.tags,
                    'is_patch': stmt.excluded.is_patch,
                    'is_vendor_advisory': stmt.excluded.is_vendor_advisory,
                    'is_exploit': stmt.excluded.is_exploit,
                    'updated_at': _utcnow_naive()
                }
            )
            
            db.session.execute(stmt)
    
    def get_last_sync_date(self) -> Optional[datetime]:
        """Obter data do último sync bem sucedido."""
        value = SyncMetadata.get('nvd_last_successful_sync')
        if value:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None
    
    def update_sync_metadata(self, key: str, value: Any) -> None:
        """Atualizar metadata de sync."""
        SyncMetadata.set(key, value)
