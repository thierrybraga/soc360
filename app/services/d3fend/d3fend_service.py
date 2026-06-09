"""
SOC360 D3FEND Service
Serviço de sincronização com MITRE D3FEND Framework
"""
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional

from app.extensions import db
from app.models.d3fend import (
    D3fendTechnique, D3fendTactic, D3fendArtifact,
    D3fendOffensiveMapping, CveD3fendCorrelation
)
from app.models.nvd import Vulnerability, Weakness
from app.models.system import SyncMetadata
from app.services.core.base_sync_service import BaseSyncService

logger = logging.getLogger(__name__)


class D3FENDService(BaseSyncService):
    """
    Serviço de sincronização com MITRE D3FEND.
    
    Integra dados defensivos do D3FEND e correlaciona com CVEs existentes.
    """
    
    BASE_URL = 'https://d3fend.mitre.org/api'
    
    def __init__(self):
        super().__init__(prefix='d3fend')
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'SOC360-D3FEND/1.0'
        })
    
    def _fetch(self, endpoint: str) -> Optional[Dict]:
        """Faz requisição GET para a API D3FEND."""
        url = f'{self.BASE_URL}{endpoint}'
        try:
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f'D3FEND fetch error for {endpoint}: {e}')
            return None
    
    def sync_all(self):
        """Sincroniza todos os dados D3FEND."""
        try:
            self.start_sync('Starting D3FEND synchronization...')
            
            # Sincronizar em ordem: Tactics → Techniques → Artifacts → Mappings
            self._sync_tactics()
            self._sync_techniques()
            self._sync_artifacts()
            self._sync_offensive_mappings()
            
            self.complete_sync()
            logger.info('D3FEND sync completed successfully')
            return self.stats
            
        except Exception as e:
            self.fail_sync(str(e))
            logger.error(f'D3FEND sync failed: {e}')
            raise
    
    def _sync_tactics(self):
        """Sincroniza táticas D3FEND."""
        logger.info('Syncing D3FEND tactics...')
        data = self._fetch('/tactic/all.json')
        
        if not data or not isinstance(data, list):
            logger.warning('No tactics data received')
            return
        
        for item in data:
            try:
                tactic = D3fendTactic.query.get(item.get('id'))
                if not tactic:
                    tactic = D3fendTactic(id=item.get('id'))
                
                tactic.name = item.get('name', '')
                tactic.description = item.get('description', '')
                tactic.url = item.get('url', '')
                tactic.last_sync = datetime.utcnow()
                
                db.session.add(tactic)
                self.stats['processed'] += 1
                
            except Exception as e:
                logger.warning(f'Error processing tactic {item.get("id")}: {e}')
                self.stats['errors'] += 1
        
        db.session.commit()
        logger.info(f'Tactics synced: {self.stats["processed"]}')
    
    def _sync_techniques(self):
        """Sincroniza técnicas D3FEND."""
        logger.info('Syncing D3FEND techniques...')
        data = self._fetch('/technique/all.json')
        
        if not data or not isinstance(data, list):
            logger.warning('No techniques data received')
            return
        
        for item in data:
            try:
                technique = D3fendTechnique.query.get(item.get('id'))
                if not technique:
                    technique = D3fendTechnique(id=item.get('id'))
                
                technique.name = item.get('name', '')
                technique.description = item.get('description', '')
                technique.url = item.get('url', '')
                technique.tactic_id = item.get('tactic_id')
                technique.last_sync = datetime.utcnow()
                
                db.session.add(technique)
                self.stats['processed'] += 1
                
            except Exception as e:
                logger.warning(f'Error processing technique {item.get("id")}: {e}')
                self.stats['errors'] += 1
        
        db.session.commit()
        logger.info(f'Techniques synced: {self.stats["processed"]}')
    
    def _sync_artifacts(self):
        """Sincroniza artefatos D3FEND."""
        logger.info('Syncing D3FEND artifacts...')
        data = self._fetch('/dao/artifacts.json')
        
        if not data or not isinstance(data, list):
            logger.warning('No artifacts data received')
            return
        
        for item in data:
            try:
                artifact = D3fendArtifact.query.get(item.get('id'))
                if not artifact:
                    artifact = D3fendArtifact(id=item.get('id'))
                
                artifact.name = item.get('name', '')
                artifact.description = item.get('description', '')
                artifact.url = item.get('url', '')
                artifact.artifact_type = item.get('type', '')
                artifact.category = item.get('category', '')
                artifact.last_sync = datetime.utcnow()
                
                db.session.add(artifact)
                self.stats['processed'] += 1
                
            except Exception as e:
                logger.warning(f'Error processing artifact {item.get("id")}: {e}')
                self.stats['errors'] += 1
        
        db.session.commit()
        logger.info(f'Artifacts synced: {self.stats["processed"]}')
    
    def _sync_offensive_mappings(self):
        """Sincroniza mapeamentos ofensivos D3FEND ↔ ATT&CK."""
        logger.info('Syncing D3FEND offensive mappings...')
        data = self._fetch('/offensive-technique/all.json')
        
        if not data or not isinstance(data, list):
            logger.warning('No offensive mappings data received')
            return
        
        for item in data:
            try:
                d3fend_id = item.get('d3fend_technique_id')
                attack_id = item.get('attack_technique_id')
                
                if not d3fend_id or not attack_id:
                    continue
                
                # Verificar se já existe
                existing = D3fendOffensiveMapping.query.filter_by(
                    d3fend_technique_id=d3fend_id,
                    attack_technique_id=attack_id
                ).first()
                
                if not existing:
                    mapping = D3fendOffensiveMapping(
                        d3fend_technique_id=d3fend_id,
                        attack_technique_id=attack_id,
                        mapping_type=item.get('mapping_type', '')
                    )
                    db.session.add(mapping)
                    self.stats['inserted'] += 1
                
                self.stats['processed'] += 1
                
            except Exception as e:
                logger.warning(f'Error processing mapping: {e}')
                self.stats['errors'] += 1
        
        db.session.commit()
        logger.info(f'Offensive mappings synced: {self.stats["processed"]}')
    
    def correlate_cves(self, limit: int = 1000):
        """
        Correlaciona CVEs existentes com técnicas D3FEND.
        
        Fluxo: CVE → CWE → ATT&CK → D3FEND
        """
        logger.info(f'Starting CVE-D3FEND correlation for up to {limit} CVEs...')
        
        try:
            self.start_sync('Correlating CVEs with D3FEND...')
            
            # Buscar CVEs que têm CWEs associadas na tabela normalizada.
            cves = (
                Vulnerability.query
                .join(Weakness, Weakness.cve_id == Vulnerability.cve_id)
                .distinct()
                .limit(limit)
                .all()
            )
            
            correlations_created = 0
            
            for cve in cves:
                try:
                    correlations = self._correlate_single_cve(cve)
                    correlations_created += len(correlations)
                    self.stats['processed'] += 1
                    
                except Exception as e:
                    logger.warning(f'Error correlating CVE {cve.cve_id}: {e}')
                    self.stats['errors'] += 1
            
            db.session.commit()
            self.complete_sync(f'Created {correlations_created} correlations')
            logger.info(f'CVE-D3FEND correlation completed: {correlations_created} correlations')
            return correlations_created
            
        except Exception as e:
            self.fail_sync(str(e))
            logger.error(f'CVE-D3FEND correlation failed: {e}')
            raise
    
    def _correlate_single_cve(self, cve: Vulnerability) -> List[CveD3fendCorrelation]:
        """Correlaciona uma única CVE com técnicas D3FEND."""
        correlations = []
        
        # Implementação simplificada da correlação
        # Na prática, isso usaria o CWE para encontrar ATT&CK e depois D3FEND
        
        # Buscar mapeamentos D3FEND relacionados aos termos da descrição
        keywords = self._extract_keywords(cve.description or '')
        
        for keyword in keywords:
            # Buscar técnicas D3FEND relacionadas
            techniques = D3fendTechnique.query.filter(
                D3fendTechnique.description.ilike(f'%{keyword}%')
            ).limit(5).all()
            
            for technique in techniques:
                # Verificar se já existe correlação
                existing = CveD3fendCorrelation.query.filter_by(
                    cve_id=cve.cve_id,
                    d3fend_technique_id=technique.id
                ).first()
                
                if not existing:
                    correlation = CveD3fendCorrelation(
                        cve_id=cve.cve_id,
                        d3fend_technique_id=technique.id,
                        confidence=0.5,  # Confidence médio para matching por keyword
                        correlation_path={
                            'method': 'keyword_matching',
                            'keywords': keywords
                        }
                    )
                    db.session.add(correlation)
                    correlations.append(correlation)
        
        return correlations
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extrai keywords relevantes de um texto."""
        # Lista de termos de segurança relevantes
        security_terms = [
            'injection', 'overflow', 'execution', 'escalation', 'bypass',
            'disclosure', 'forgery', 'spraying', 'enumeration', 'harvesting',
            'hijacking', 'poisoning', 'smuggling', 'sniffing', 'spoofing',
            'tunneling', 'validation', 'sanitization', 'encoding', 'encryption'
        ]
        
        text_lower = text.lower()
        found = [term for term in security_terms if term in text_lower]
        return found[:5]  # Limitar a 5 keywords
    
    def get_d3fend_for_cve(self, cve_id: str) -> List[Dict]:
        """
        Retorna técnicas D3FEND recomendadas para uma CVE.
        """
        correlations = CveD3fendCorrelation.query.filter_by(cve_id=cve_id).all()
        
        result = []
        for corr in correlations:
            technique = D3fendTechnique.query.get(corr.d3fend_technique_id)
            if technique:
                result.append({
                    'correlation': corr.to_dict(),
                    'technique': technique.to_dict()
                })
        
        return result
