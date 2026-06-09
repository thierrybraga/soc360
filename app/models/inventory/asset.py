"""
SOC360 Asset Model
Model de ativos de TI da organização.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, ForeignKey, Boolean, UniqueConstraint
from app.extensions.db_types import JSONB, INET
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel
from app.models.system.enums import AssetType, AssetStatus


class Asset(CoreModel):
    """
    Model de ativo de TI.
    
    Representa servidores, workstations, dispositivos de rede, etc.
    Inclui informações de BIA (Business Impact Analysis) para cálculo de risco.
    """
    __tablename__ = 'assets'
    
    # Identificação
    name = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    ip_address = Column(INET, nullable=True, index=True)
    mac_address = Column(String(17), nullable=True)
    
    # Classificação
    asset_type = Column(String(50), default=AssetType.SERVER.value, nullable=False)
    status = Column(String(50), default=AssetStatus.ACTIVE.value, nullable=False)
    criticality = Column(String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Categorização e Hierarquia
    category_id = Column(
        Integer,
        ForeignKey('asset_categories.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    parent_id = Column(
        Integer,
        ForeignKey('assets.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    
    # Organização/Cliente (para SOC)
    client_id = Column(String(100), nullable=True, index=True)  # ID do cliente ou Adon
    organization_id = Column(
        Integer,
        ForeignKey('asset_categories.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    environment = Column(String(50), default='PRODUCTION')  # PRODUCTION, STAGING, DEV, DMZ
    exposure = Column(String(20), default='INTERNAL')  # INTERNAL, EXTERNAL, CLOUD
    
    # Localização
    location = Column(String(255), nullable=True)
    data_center = Column(String(100), nullable=True)
    rack = Column(String(50), nullable=True)
    
    # Ownership
    owner_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    department = Column(String(100), nullable=True)
    
    # Vendor/Product (para matching com CVEs)
    vendor_id = Column(
        Integer,
        ForeignKey('vendors.id', ondelete='SET NULL'),
        nullable=True
    )
    product_id = Column(
        Integer,
        ForeignKey('products.id', ondelete='SET NULL'),
        nullable=True
    )
    version = Column(String(100), nullable=True)
    
    # Sistema Operacional
    os_family = Column(String(50), nullable=True)  # Windows, Linux, etc
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(50), nullable=True)
    
    # BIA (Business Impact Analysis)
    rto_hours = Column(Float, nullable=True)  # Recovery Time Objective
    rpo_hours = Column(Float, nullable=True)  # Recovery Point Objective
    operational_cost_per_hour = Column(Float, nullable=True)  # Custo de downtime
    
    # Descrição
    description = Column(Text(), nullable=True)
    notes = Column(Text(), nullable=True)
    
    # Tags e metadados customizados
    tags = Column(JSONB, nullable=True)
    custom_fields = Column(JSONB, nullable=True)
    installed_software = Column(JSONB, nullable=True)
    
    # Datas
    purchase_date = Column(db.Date, nullable=True)
    warranty_expiry = Column(db.Date, nullable=True)
    last_scan_date = Column(db.DateTime, nullable=True)
    
    # Relationships
    owner = relationship('User', back_populates='assets')
    vendor = relationship('Vendor', back_populates='assets')
    product = relationship('Product', back_populates='assets')
    category = relationship('AssetCategory', foreign_keys=[category_id], back_populates='category_assets')
    organization = relationship('AssetCategory', foreign_keys=[organization_id], back_populates='org_assets')
    parent = relationship('Asset', remote_side='Asset.id', backref='children')
    vulnerabilities = relationship('AssetVulnerability', back_populates='asset', cascade='all, delete-orphan')
    
    # Unique constraint: IP único por owner
    __table_args__ = (
        UniqueConstraint('ip_address', 'owner_id', name='uq_asset_ip_owner'),
    )
    
    @property
    def bia_score(self):
        """
        Calcula score BIA (0-100) baseado em RTO, RPO e custo.
        Quanto menor RTO/RPO e maior custo, maior o score.
        """
        from app.services.risk import RiskScoringService

        return RiskScoringService.calculate_bia_score(
            rto_hours=self.rto_hours,
            rpo_hours=self.rpo_hours,
            operational_cost_per_hour=self.operational_cost_per_hour,
        )
    
    def calculate_risk_score(self, cvss_score=None):
        """
        Calcula score de risco contextualizado.
        
        Risk Score = CVSS × BIA_multiplier × Context_multiplier
        """
        from app.services.risk import RiskScoringService

        return RiskScoringService.calculate_asset_risk(self, cvss_score)
    
    @property
    def vulnerability_count(self):
        """Retorna contagem de vulnerabilidades abertas."""
        from app.models.system.enums import VulnerabilityStatus
        return len([
            av for av in self.vulnerabilities
            if av.status in [VulnerabilityStatus.OPEN.value, VulnerabilityStatus.IN_PROGRESS.value]
        ])

    @property
    def risk_score(self):
        """Retorna o maior score de risco contextual entre as vulnerabilidades abertas."""
        from app.models.system.enums import VulnerabilityStatus
        scores = [
            av.contextual_risk_score for av in self.vulnerabilities
            if av.status in [VulnerabilityStatus.OPEN.value, VulnerabilityStatus.IN_PROGRESS.value]
            and av.contextual_risk_score is not None
        ]
        return round(max(scores), 1) if scores else None
    
    @property
    def critical_vulnerability_count(self):
        """Retorna contagem de vulnerabilidades críticas abertas."""
        from app.models.system.enums import VulnerabilityStatus
        return len([
            av for av in self.vulnerabilities 
            if av.status in [VulnerabilityStatus.OPEN.value, VulnerabilityStatus.IN_PROGRESS.value]
            and av.vulnerability and av.vulnerability.base_severity == 'CRITICAL'
        ])
    
    def to_dict(self, include_vulnerabilities=False, include_vuln_stats=True):
        """Converte para dicionário.

        ``include_vuln_stats=True`` (padrão) inclui risk_score e
        critical_vulnerability_count, que disparam lazy loads no DB público
        (um SELECT por AssetVulnerability). Use ``include_vuln_stats=False``
        em endpoints de listagem para evitar N+1.
        """
        data = {
            'id': self.id,
            'name': self.name,
            'hostname': self.hostname,
            'ip_address': str(self.ip_address) if self.ip_address else None,
            'mac_address': self.mac_address,
            'asset_type': self.asset_type,
            'status': self.status,
            'criticality': self.criticality,
            'category_id': self.category_id,
            'organization_id': self.organization_id,
            'organization_name': self.organization.name if self.organization else None,
            'category_name': self.category.name if self.category else None,
            'parent_id': self.parent_id,
            'parent_name': self.parent.name if self.parent else None,
            'client_id': self.client_id,
            'environment': self.environment,
            'exposure': self.exposure,
            'location': self.location,
            'owner_id': self.owner_id,
            'owner_name': self.owner.full_name if self.owner else None,
            'department': self.department,
            'vendor_name': self.vendor.name if self.vendor else None,
            'product_name': self.product.name if self.product else None,
            'version': self.version,
            'os_family': self.os_family,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'rto_hours': self.rto_hours,
            'rpo_hours': self.rpo_hours,
            'operational_cost_per_hour': self.operational_cost_per_hour,
            'bia_score': self.bia_score,
            # vulnerability_count only needs local DB (iterates already-loaded rel)
            'vulnerability_count': self.vulnerability_count,
            'installed_software': self.installed_software,
            'tags': self.tags,
            'last_scan_date': self.last_scan_date.isoformat() if self.last_scan_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_vuln_stats:
            # These properties access av.vulnerability per row — N+1 into the
            # public DB. Only include when the caller is willing to pay the cost
            # (e.g. single-asset detail responses).
            data['risk_score'] = self.risk_score
            data['critical_vulnerability_count'] = self.critical_vulnerability_count
        else:
            data['risk_score'] = None
            data['critical_vulnerability_count'] = None

        if include_vulnerabilities:
            data['vulnerabilities'] = [av.to_dict() for av in self.vulnerabilities]

        return data
    
    @classmethod
    def get_by_ip(cls, ip_address, owner_id=None):
        """Busca ativo por IP."""
        query = cls.query.filter_by(ip_address=ip_address)
        if owner_id:
            query = query.filter_by(owner_id=owner_id)
        return query.first()
    
    @classmethod
    def get_by_owner(cls, owner_id, status=None):
        """Retorna ativos de um owner."""
        query = cls.query.filter_by(owner_id=owner_id)
        if status:
            query = query.filter_by(status=status)
        return query.order_by(cls.name).all()
    
    @classmethod
    def get_critical_assets(cls):
        """Retorna ativos críticos."""
        return cls.query.filter_by(criticality='CRITICAL', status='ACTIVE').all()
    
    def __repr__(self):
        return f"<Asset(id={self.id}, name='{self.name}', ip='{self.ip_address}')>"
