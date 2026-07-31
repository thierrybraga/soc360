"""
SOC360 Weakness Model
Model para CWE (Common Weakness Enumeration) associadas a CVEs.
"""
from sqlalchemy import Column, String, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import PublicModel


class Weakness(PublicModel):
    """
    Model de weakness (CWE) associada a uma CVE.
    
    Uma CVE pode ter múltiplas CWEs associadas.
    """
    __tablename__ = 'weaknesses'
    __table_args__ = (
        UniqueConstraint('cve_id', 'cwe_id', 'source', name='uq_weakness_cve_cwe_source'),
    )
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # CWE Data
    cwe_id = Column(String(20), nullable=False, index=True)  # CWE-79, CWE-89, etc
    source = Column(String(255), nullable=True)
    type = Column(String(50), nullable=True)  # Primary, Secondary
    
    # Descrição (cacheada do MITRE)
    description = Column(Text, nullable=True)
    name = Column(String(255), nullable=True)
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='weaknesses')
    
    # CWE Categories conhecidas (para referência)
    COMMON_CWES = {
        'CWE-79': 'Improper Neutralization of Input During Web Page Generation (XSS)',
        'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
        'CWE-20': 'Improper Input Validation',
        'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
        'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
        'CWE-94': 'Improper Control of Generation of Code (Code Injection)',
        'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
        'CWE-125': 'Out-of-bounds Read',
        'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
        'CWE-269': 'Improper Privilege Management',
        'CWE-287': 'Improper Authentication',
        'CWE-352': 'Cross-Site Request Forgery (CSRF)',
        'CWE-400': 'Uncontrolled Resource Consumption',
        'CWE-416': 'Use After Free',
        'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-502': 'Deserialization of Untrusted Data',
        'CWE-787': 'Out-of-bounds Write',
        'CWE-862': 'Missing Authorization',
        'CWE-918': 'Server-Side Request Forgery (SSRF)'
    }
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'source': self.source,
            'type': self.type,
            'name': self.name or self.COMMON_CWES.get(self.cwe_id, ''),
            'description': self.description
        }
    
    @classmethod
    def get_top_cwes(cls, limit=10):
        """Retorna CWEs mais frequentes."""
        from sqlalchemy import func
        result = db.session.query(
            cls.cwe_id,
            func.count(cls.cwe_id).label('count')
        ).group_by(cls.cwe_id).order_by(
            func.count(cls.cwe_id).desc()
        ).limit(limit).all()
        
        return [
            {
                'cwe_id': cwe_id,
                'count': count,
                'name': cls.COMMON_CWES.get(cwe_id, 'Unknown')
            }
            for cwe_id, count in result
        ]
    
    def __repr__(self):
        return f"<Weakness(cve_id='{self.cve_id}', cwe_id='{self.cwe_id}')>"
