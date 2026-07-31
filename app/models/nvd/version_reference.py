"""
SOC360 Version Reference Model
Model para referencias de versao afetada/corrigida.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from app.extensions.db import db
from app.models.system.base_model import PublicModel


class VersionReference(PublicModel):
    """
    Modelo para referencias de versao.
    Armazena informacoes sobre versoes afetadas e corrigidas.
    """
    __tablename__ = 'version_ref'

    cve_id = Column(
        String(20),
        ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    product_id = Column(
        Integer,
        ForeignKey('affected_products.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    affected_version = Column(String(100), nullable=False)
    fixed_version = Column(String(100), nullable=True)

    def __repr__(self):
        return f"<VersionReference id={self.id} cve_id={self.cve_id} product_id={self.product_id}>"
