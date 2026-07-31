"""
SOC360 Credit Model
Model para créditos de descoberta/contribuição de CVEs.
"""
from sqlalchemy import Column, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.models.system.base_model import PublicModel


class Credit(PublicModel):
    """
    Model de crédito/reconhecimento para uma CVE.
    """
    __tablename__ = 'credits'
    __table_args__ = (
        UniqueConstraint('cve_id', 'value', 'type', 'user', name='uq_credit_cve_value_type_user'),
    )
    
    # Foreign Key
    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Credit Data
    value = Column(String(255), nullable=False)
    user = Column(String(255), nullable=True)
    type = Column(String(100), nullable=True)  # finder, reporter, analyst, etc.
    
    # Relationship
    vulnerability = relationship('Vulnerability', back_populates='credits')
    
    def __repr__(self):
        return f"<Credit(cve_id='{self.cve_id}', user='{self.user}')>"
