"""
SOC360 Vendor and Product Models
Models para gestão de vendors e produtos.
"""
from sqlalchemy import Column, String, Integer, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel


class Vendor(CoreModel):
    """
    Model de vendor/fabricante.
    
    Representa fabricantes de software/hardware cujos produtos
    são monitorados para vulnerabilidades.
    """
    __tablename__ = 'vendors'
    
    # Identificação
    name = Column(String(255), nullable=False, unique=True, index=True)
    normalized_name = Column(String(255), nullable=True, index=True)  # Nome normalizado para matching
    
    # Detalhes
    website = Column(String(500), nullable=True)
    support_url = Column(String(500), nullable=True)
    security_contact = Column(String(255), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Descrição
    description = Column(Text, nullable=True)
    
    # Relationships
    products = relationship('Product', back_populates='vendor', cascade='all, delete-orphan')
    assets = relationship('Asset', back_populates='vendor')
    
    def __init__(self, name, **kwargs):
        """Inicializa vendor com nome normalizado."""
        super().__init__(**kwargs)
        self.name = name
        self.normalized_name = self.normalize_name(name)
    
    @staticmethod
    def normalize_name(name):
        """Normaliza nome para matching."""
        if not name:
            return None
        return name.lower().strip().replace(' ', '_').replace('-', '_')
    
    @property
    def product_count(self):
        """Retorna contagem de produtos."""
        return len(self.products)
    
    @property
    def asset_count(self):
        """Retorna contagem de ativos."""
        return len(self.assets)
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'name': self.name,
            'normalized_name': self.normalized_name,
            'website': self.website,
            'support_url': self.support_url,
            'is_active': self.is_active,
            'product_count': self.product_count,
            'asset_count': self.asset_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def get_by_name(cls, name):
        """Busca vendor por nome (normalizado)."""
        normalized = cls.normalize_name(name)
        return cls.query.filter(
            (cls.name.ilike(name)) | (cls.normalized_name == normalized)
        ).first()
    
    @classmethod
    def get_or_create(cls, name):
        """Busca ou cria vendor."""
        vendor = cls.get_by_name(name)
        if vendor:
            return vendor, False
        
        vendor = cls(name=name)
        db.session.add(vendor)
        db.session.commit()
        return vendor, True
    
    @classmethod
    def get_with_vulnerabilities(cls, limit=20):
        """Retorna vendors com mais vulnerabilidades associadas."""
        # Implementação simplificada - idealmente seria uma query otimizada
        from sqlalchemy import func
        from app.models.nvd.vulnerability import Vulnerability
        
        result = db.session.query(
            cls.name,
            func.count().label('vuln_count')
        ).join(
            Vulnerability,
            Vulnerability.nvd_vendors_data.contains([cls.normalized_name])
        ).group_by(cls.name).order_by(
            func.count().desc()
        ).limit(limit).all()
        
        return result
    
    def __repr__(self):
        return f"<Vendor(id={self.id}, name='{self.name}')>"


class Product(CoreModel):
    """
    Model de produto.
    
    Representa produtos de software/hardware que podem ter vulnerabilidades.
    """
    __tablename__ = 'products'
    
    # Identificação
    name = Column(String(255), nullable=False, index=True)
    normalized_name = Column(String(255), nullable=True, index=True)
    
    # Vendor
    vendor_id = Column(
        Integer,
        ForeignKey('vendors.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Versões
    version = Column(String(100), nullable=True)
    version_start = Column(String(100), nullable=True)  # Versão inicial afetada
    version_end = Column(String(100), nullable=True)  # Versão final afetada
    
    # CPE
    cpe_string = Column(String(500), nullable=True)  # cpe:2.3:a:vendor:product:version:...
    
    # Tipo
    product_type = Column(String(50), nullable=True)  # application, os, hardware, firmware
    
    # Status
    is_active = Column(Boolean, default=True)
    end_of_life = Column(db.Date, nullable=True)
    
    # Descrição
    description = Column(Text(), nullable=True)
    
    # Relationships
    vendor = relationship('Vendor', back_populates='products')
    assets = relationship('Asset', back_populates='product')
    
    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('vendor_id', 'name', 'version', name='uq_vendor_product_version'),
    )
    
    def __init__(self, name, vendor_id, **kwargs):
        """Inicializa produto com nome normalizado."""
        super().__init__(**kwargs)
        self.name = name
        self.vendor_id = vendor_id
        self.normalized_name = Vendor.normalize_name(name)
    
    @property
    def full_name(self):
        """Retorna nome completo com vendor."""
        vendor_name = self.vendor.name if self.vendor else 'Unknown'
        return f"{vendor_name} {self.name}"
    
    @property
    def asset_count(self):
        """Retorna contagem de ativos."""
        return len(self.assets)
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'name': self.name,
            'full_name': self.full_name,
            'vendor_id': self.vendor_id,
            'vendor_name': self.vendor.name if self.vendor else None,
            'version': self.version,
            'cpe_string': self.cpe_string,
            'product_type': self.product_type,
            'is_active': self.is_active,
            'end_of_life': self.end_of_life.isoformat() if self.end_of_life else None,
            'asset_count': self.asset_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def get_by_name(cls, name, vendor_id=None):
        """Busca produto por nome."""
        query = cls.query.filter(cls.name.ilike(name))
        if vendor_id:
            query = query.filter_by(vendor_id=vendor_id)
        return query.first()
    
    @classmethod
    def get_or_create(cls, name, vendor_id, version=None):
        """Busca ou cria produto."""
        product = cls.query.filter_by(
            vendor_id=vendor_id,
            name=name,
            version=version
        ).first()
        
        if product:
            return product, False
        
        product = cls(name=name, vendor_id=vendor_id, version=version)
        db.session.add(product)
        db.session.commit()
        return product, True
    
    def __repr__(self):
        return f"<Product(id={self.id}, name='{self.name}', vendor_id={self.vendor_id})>"
