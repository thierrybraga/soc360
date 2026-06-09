"""
SOC360 Role Model
Model de roles para RBAC.
"""
from sqlalchemy import Column, String, Text
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel
from app.models.auth.user_role import UserRole


class Role(CoreModel):
    """
    Model de role do sistema.
    
    Roles padrão:
    - ADMIN: Acesso total
    - ANALYST: Análise de vulnerabilidades, criação de relatórios
    - VIEWER: Apenas visualização
    - API_USER: Acesso via API
    """
    __tablename__ = 'roles'
    
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text(), nullable=True)
    permissions = Column(Text(), nullable=True)  # JSON string de permissões
    
    # Relationships
    users = relationship(
        'User',
        secondary=UserRole.__table__,
        primaryjoin="Role.id==UserRole.role_id",
        secondaryjoin="UserRole.user_id==User.id",
        back_populates='roles',
        lazy='dynamic'
    )
    
    # Constantes para roles padrão
    ADMIN = 'ADMIN'
    ANALYST = 'ANALYST'
    VIEWER = 'VIEWER'
    API_USER = 'API_USER'
    
    DEFAULT_ROLES = {
        ADMIN: {
            'description': 'Administrador com acesso total ao sistema',
            'permissions': ['*']
        },
        ANALYST: {
            'description': 'Analista de segurança com acesso a vulnerabilidades e relatórios',
            'permissions': [
                'vulnerabilities:read',
                'vulnerabilities:update',
                'assets:read',
                'assets:create',
                'assets:update',
                'reports:read',
                'reports:create',
                'analytics:read'
            ]
        },
        VIEWER: {
            'description': 'Usuário com acesso apenas para visualização',
            'permissions': [
                'vulnerabilities:read',
                'assets:read',
                'reports:read',
                'analytics:read'
            ]
        },
        API_USER: {
            'description': 'Usuário para acesso via API',
            'permissions': [
                'api:access',
                'vulnerabilities:read',
                'assets:read'
            ]
        }
    }
    
    def __init__(self, name, description=None, permissions=None):
        """Inicializa role."""
        self.name = name.upper()
        self.description = description
        if permissions:
            import json
            self.permissions = json.dumps(permissions) if isinstance(permissions, list) else permissions
    
    @property
    def permission_list(self):
        """Retorna lista de permissões."""
        if not self.permissions:
            return []
        import json
        try:
            return json.loads(self.permissions)
        except (json.JSONDecodeError, TypeError):
            return []
    
    def has_permission(self, permission):
        """Verifica se role tem uma permissão específica."""
        permissions = self.permission_list
        if '*' in permissions:
            return True
        return permission in permissions
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': self.permission_list,
            'user_count': self.users.count()
        }
    
    @classmethod
    def get_by_name(cls, name):
        """Busca role por nome."""
        return cls.query.filter_by(name=name.upper()).first()
    
    @classmethod
    def create_default_roles(cls):
        """Cria roles padrão do sistema."""
        created = []
        for name, data in cls.DEFAULT_ROLES.items():
            existing = cls.get_by_name(name)
            if not existing:
                import json
                role = cls(
                    name=name,
                    description=data['description'],
                    permissions=json.dumps(data['permissions'])
                )
                db.session.add(role)
                created.append(name)
        
        if created:
            db.session.commit()
        
        return created
    
    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}')>"
