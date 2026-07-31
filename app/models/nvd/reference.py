"""
SOC360 Reference Model
Model para referências de CVEs.
"""
from sqlalchemy import Column, String, Text, ForeignKey, Boolean, UniqueConstraint
from app.extensions.db_types import ARRAY
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import PublicModel


class Reference(PublicModel):
    """
    Model de referência associada a uma CVE.
    
    Inclui links para advisories, patches, exploits, etc.
    """
    __tablename__ = 'references'
    __table_args__ = (
        UniqueConstraint('cve_id', 'url', name='uq_reference_cve_url'),
    )
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Reference Data
    url = Column(Text, nullable=False)
    source = Column(String(255), nullable=True)
    
    # Tags (Patch, Vendor Advisory, Third Party Advisory, etc)
    tags = Column(ARRAY(String(255)), nullable=True)
    
    # Computed fields
    is_patch = Column(Boolean, default=False)
    is_vendor_advisory = Column(Boolean, default=False)
    is_exploit = Column(Boolean, default=False)
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='references')
    
    def __init__(self, **kwargs):
        """Inicializa e computa campos derivados."""
        super().__init__(**kwargs)
        self._compute_derived_fields()
    
    def _compute_derived_fields(self):
        """Computa campos derivados das tags."""
        if self.tags:
            tags_lower = [t.lower() for t in self.tags]
            self.is_patch = 'patch' in tags_lower
            self.is_vendor_advisory = 'vendor advisory' in tags_lower
            self.is_exploit = 'exploit' in tags_lower
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'url': self.url,
            'source': self.source,
            'tags': self.tags,
            'is_patch': self.is_patch,
            'is_vendor_advisory': self.is_vendor_advisory,
            'is_exploit': self.is_exploit
        }
    
    @classmethod
    def get_patches_for_cve(cls, cve_id):
        """Retorna referências de patch para uma CVE."""
        return cls.query.filter_by(
            cve_id=cve_id,
            is_patch=True
        ).all()
    
    def __repr__(self):
        return f"<Reference(cve_id='{self.cve_id}', url='{self.url[:50]}...')>"


class Mitigation(PublicModel):
    """
    Model de mitigação/workaround para uma CVE.
    """
    __tablename__ = 'mitigations'
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Mitigation Data
    description = Column(Text, nullable=False)
    source = Column(String(255), nullable=True)  # NVD, Vendor, etc
    type = Column(String(50), nullable=True)  # Workaround, Patch, Configuration
    effectiveness = Column(String(50), nullable=True)  # Full, Partial, None
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='mitigations')
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'description': self.description,
            'source': self.source,
            'type': self.type,
            'effectiveness': self.effectiveness
        }
    
    def __repr__(self):
        return f"<Mitigation(cve_id='{self.cve_id}', type='{self.type}')>"
