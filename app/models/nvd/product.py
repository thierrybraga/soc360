"""
SOC360 Affected Product Model
Model para produtos afetados por CVEs (dados detalhados da MITRE).
"""
from sqlalchemy import Column, String, ForeignKey, UniqueConstraint
from app.extensions.db_types import JSONB
from sqlalchemy.orm import relationship
from app.models.system.base_model import PublicModel


class AffectedProduct(PublicModel):
    """
    Model de produto afetado por uma CVE.
    Armazena dados mais estruturados que o JSON simples do NVD.
    """
    __tablename__ = 'affected_products'
    __table_args__ = (
        UniqueConstraint('cve_id', 'vendor', 'product', name='uq_affected_product_cve_vendor_product'),
    )
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Product Data
    vendor = Column(String(255), nullable=False, index=True)
    product = Column(String(255), nullable=False, index=True)
    
    # Detailed info
    versions = Column(JSONB, nullable=True)  # Lista de versões afetadas
    platforms = Column(JSONB, nullable=True)  # Lista de plataformas
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='affected_products')
    
    def __repr__(self):
        return f"<AffectedProduct(cve_id='{self.cve_id}', product='{self.vendor}/{self.product}')>"
