"""
SOC360 CVSS Metric Model
Model para métricas CVSS detalhadas.
"""
from sqlalchemy import Column, String, Float, ForeignKey, Text, Integer, UniqueConstraint
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import PublicModel


class CvssMetric(PublicModel):
    """
    Model de métricas CVSS detalhadas.
    
    Suporta CVSS v2.0, v3.0, v3.1 e v4.0.
    Uma CVE pode ter múltiplas métricas de diferentes fontes.
    """
    __tablename__ = 'cvss_metrics'
    __table_args__ = (
        UniqueConstraint('cve_id', 'version', 'source', name='uq_cvss_metric_cve_version_source'),
    )
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Versão e Fonte
    version = Column(String(10), nullable=False)  # 2.0, 3.0, 3.1, 4.0
    source = Column(String(255), nullable=True)  # nvd@nist.gov, vendor, etc
    type = Column(String(20), nullable=True)  # Primary, Secondary
    
    # Vector String
    vector_string = Column(String(255), nullable=True)
    
    # Scores
    base_score = Column(Float, nullable=True)
    base_severity = Column(String(20), nullable=True)
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)
    
    # CVSS v3.x Base Metrics
    attack_vector = Column(String(20), nullable=True)  # NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL
    attack_complexity = Column(String(20), nullable=True)  # LOW, HIGH
    privileges_required = Column(String(20), nullable=True)  # NONE, LOW, HIGH
    user_interaction = Column(String(20), nullable=True)  # NONE, REQUIRED
    scope = Column(String(20), nullable=True)  # UNCHANGED, CHANGED
    confidentiality_impact = Column(String(20), nullable=True)  # NONE, LOW, HIGH
    integrity_impact = Column(String(20), nullable=True)  # NONE, LOW, HIGH
    availability_impact = Column(String(20), nullable=True)  # NONE, LOW, HIGH
    
    # CVSS v2 specific (legacy)
    access_vector = Column(String(20), nullable=True)  # L, A, N
    access_complexity = Column(String(20), nullable=True)  # H, M, L
    authentication = Column(String(20), nullable=True)  # M, S, N
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='metrics')
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'version': self.version,
            'source': self.source,
            'type': self.type,
            'vector_string': self.vector_string,
            'base_score': self.base_score,
            'base_severity': self.base_severity,
            'exploitability_score': self.exploitability_score,
            'impact_score': self.impact_score,
            'attack_vector': self.attack_vector,
            'attack_complexity': self.attack_complexity,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'scope': self.scope,
            'confidentiality_impact': self.confidentiality_impact,
            'integrity_impact': self.integrity_impact,
            'availability_impact': self.availability_impact
        }
    
    @classmethod
    def get_primary_metric(cls, cve_id):
        """Retorna métrica primária de uma CVE."""
        return cls.query.filter_by(
            cve_id=cve_id,
            type='Primary'
        ).order_by(cls.version.desc()).first()
    
    def __repr__(self):
        return f"<CvssMetric(cve_id='{self.cve_id}', version='{self.version}', score={self.base_score})>"
