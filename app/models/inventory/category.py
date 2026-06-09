"""
SOC360 Asset Category Model
Model para categorias customizáveis de ativos.
"""
from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel


class AssetCategory(CoreModel):
    """
    Categoria customizada para ativos.
    
    Permite agrupar ativos em categorias como 'Servidores Críticos', 
    'Equipamentos de Borda', 'Estações de Trabalho Cliente A', etc.
    """
    __tablename__ = 'asset_categories'
    
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text(), nullable=True)
    is_organization = Column(db.Boolean, default=False, nullable=False)
    
    # Hierarquia de categorias (opcional)
    parent_id = Column(
        Integer,
        ForeignKey('asset_categories.id', ondelete='SET NULL'),
        nullable=True
    )
    
    # Relationships
    parent = relationship('AssetCategory', remote_side='AssetCategory.id', backref='children')
    category_assets = relationship('Asset', foreign_keys='Asset.category_id', back_populates='category')
    org_assets = relationship('Asset', foreign_keys='Asset.organization_id', back_populates='organization')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_organization': self.is_organization,
            'parent_id': self.parent_id,
            'parent_name': self.parent.name if self.parent else None
        }

    def __repr__(self):
        return f"<AssetCategory(name='{self.name}')>"
