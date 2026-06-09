"""
SOC360 UserRole Model
Tabela de associação many-to-many entre User e Role.
"""
from sqlalchemy import Column, Integer, ForeignKey, DateTime
from datetime import datetime
from app.extensions.db import db


class UserRole(db.Model):
    """
    Tabela de associação entre User e Role.
    
    Permite metadados adicionais como:
    - Data de atribuição da role
    - Quem atribuiu a role
    """
    __tablename__ = 'user_roles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    role_id = Column(
        Integer,
        ForeignKey('roles.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    assigned_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Unique constraint para evitar duplicatas
    __table_args__ = (
        db.UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
    )
    
    @classmethod
    def assign_role(cls, user_id, role_id, assigned_by_id=None):
        """Atribui uma role a um usuário."""
        existing = cls.query.filter_by(user_id=user_id, role_id=role_id).first()
        if existing:
            return existing
        
        user_role = cls(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by_id
        )
        db.session.add(user_role)
        db.session.commit()
        return user_role
    
    @classmethod
    def remove_role(cls, user_id, role_id):
        """Remove uma role de um usuário."""
        user_role = cls.query.filter_by(user_id=user_id, role_id=role_id).first()
        if user_role:
            db.session.delete(user_role)
            db.session.commit()
            return True
        return False
    
    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"
