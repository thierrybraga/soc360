"""
SOC360 Base Model
Model base com campos e métodos comuns a todos os models.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.ext.declarative import declared_attr
from app.extensions.db import db


def utcnow_naive():
    """Return UTC now as naive datetime for existing DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class BaseModel(db.Model):
    """
    Model base abstrato que fornece campos e métodos comuns.
    
    Campos incluídos:
    - id: Primary key auto-increment
    - created_at: Timestamp de criação
    - updated_at: Timestamp de atualização (auto-update)
    """
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(
        DateTime,
        default=utcnow_naive,
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime,
        default=utcnow_naive,
        onupdate=utcnow_naive,
        nullable=False
    )
    
    def save(self):
        """Salva o objeto no banco de dados."""
        db.session.add(self)
        db.session.commit()
        return self
    
    def delete(self):
        """Remove o objeto do banco de dados."""
        db.session.delete(self)
        db.session.commit()
    
    def update(self, **kwargs):
        """Atualiza campos do objeto."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = utcnow_naive()
        db.session.commit()
        return self
    
    @classmethod
    def get_by_id(cls, id):
        """Busca registro por ID."""
        return db.session.get(cls, id)
    
    @classmethod
    def get_all(cls):
        """Retorna todos os registros."""
        return cls.query.all()
    
    @classmethod
    def create(cls, **kwargs):
        """Cria e salva um novo registro."""
        instance = cls(**kwargs)
        return instance.save()
    
    @classmethod
    def get_or_create(cls, defaults=None, **kwargs):
        """
        Busca ou cria um registro.
        
        Returns:
            tuple: (instance, created) onde created é bool
        """
        instance = cls.query.filter_by(**kwargs).first()
        if instance:
            return instance, False
        
        params = {**kwargs, **(defaults or {})}
        instance = cls(**params)
        instance.save()
        return instance, True
    
    def to_dict(self, include_timestamps=True):
        """
        Converte o objeto para dicionário.
        Override nos models filhos para customização.
        """
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        
        if not include_timestamps:
            result.pop('created_at', None)
            result.pop('updated_at', None)
        
        return result
    
    def __repr__(self):
        """Representação string do objeto."""
        return f"<{self.__class__.__name__}(id={self.id})>"


class CoreModel(BaseModel):
    """Model base para tabelas no banco CORE."""
    __abstract__ = True


class PublicModel(BaseModel):
    """Model base para tabelas no banco PUBLIC."""
    __abstract__ = True
    __bind_key__ = 'public'
