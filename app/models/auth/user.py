"""
SOC360 User Model
Model de usuário com autenticação e perfil.
"""
from datetime import datetime, timedelta, timezone
import secrets
import bcrypt
from flask_login import UserMixin
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel
from app.models.auth.user_role import UserRole


class User(CoreModel, UserMixin):
    """
    Model de usuário do sistema.
    
    Implementa UserMixin do Flask-Login para gerenciamento de sessão.
    """
    __tablename__ = 'users'
    
    # Autenticação
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Status
    is_admin = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    email_confirmed = Column(Boolean, default=False, nullable=False)
    email_confirmed_at = Column(DateTime, nullable=True)
    force_password_reset = Column(Boolean, default=False, nullable=False)
    
    # Password Reset
    password_reset_token = Column(String(255), nullable=True, unique=True)
    password_reset_token_expires = Column(DateTime, nullable=True)
    
    # API Key
    api_key = Column(String(64), nullable=True, unique=True, index=True)
    api_key_created_at = Column(DateTime, nullable=True)
    
    # Profile
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    department = Column(String(100), nullable=True)
    job_title = Column(String(100), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    timezone = Column(String(50), default='UTC')
    
    # Preferences (JSON)
    preferences = Column(Text(), nullable=True)  # JSON string
    
    # Tracking
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    login_count = Column(Integer, default=0)
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # Relationships
    roles = relationship(
        'Role',
        secondary=UserRole.__table__,
        primaryjoin="User.id==UserRole.user_id",
        secondaryjoin="UserRole.role_id==Role.id",
        back_populates='users',
        lazy='dynamic'
    )
    assets = relationship('Asset', back_populates='owner', lazy='dynamic')
    monitoring_rules = relationship('MonitoringRule', back_populates='user', lazy='dynamic')
    reports = relationship('Report', back_populates='user', lazy='dynamic')
    
    def __init__(self, username, email, password=None, **kwargs):
        """Inicializa usuário com senha hasheada."""
        # Se is_admin vier no kwargs, removemos para evitar conflito com CoreModel
        is_admin = kwargs.pop('is_admin', False)
        super().__init__(**kwargs)
        self.username = username
        self.email = email.lower()
        self.is_admin = is_admin
        if password:
            self.set_password(password)
    
    def set_password(self, password):
        """Define senha com hash bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            salt
        ).decode('utf-8')
    
    def check_password(self, password):
        """Verifica se a senha está correta."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    def generate_password_reset_token(self, expiry_hours=24):
        """Gera token para reset de senha."""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_token_expires = datetime.utcnow() + timedelta(hours=expiry_hours)
        db.session.commit()
        return self.password_reset_token
    
    def verify_password_reset_token(self, token):
        """Verifica se o token de reset é válido."""
        if not self.password_reset_token:
            return False
        if self.password_reset_token != token:
            return False
        if datetime.utcnow() > self.password_reset_token_expires:
            return False
        return True
    
    def clear_password_reset_token(self):
        """Limpa token de reset."""
        self.password_reset_token = None
        self.password_reset_token_expires = None
        db.session.commit()
    
    def generate_api_key(self):
        """Gera nova API key."""
        self.api_key = secrets.token_urlsafe(48)
        self.api_key_created_at = datetime.utcnow()
        db.session.commit()
        return self.api_key
    
    def revoke_api_key(self):
        """Revoga API key atual."""
        self.api_key = None
        self.api_key_created_at = None
        db.session.commit()
    
    def has_role(self, role_name):
        """Verifica se usuário tem uma role específica."""
        return self.roles.filter_by(name=role_name).first() is not None
    
    def add_role(self, role):
        """Adiciona role ao usuário."""
        if not self.has_role(role.name):
            self.roles.append(role)
            db.session.commit()
    
    def remove_role(self, role):
        """Remove role do usuário."""
        if self.has_role(role.name):
            self.roles.remove(role)
            db.session.commit()
    
    def record_login(self, ip_address=None):
        """Registra login bem-sucedido."""
        self.last_login_at = datetime.now(timezone.utc)
        self.last_login_ip = ip_address
        self.login_count = (self.login_count or 0) + 1
        self.failed_login_count = 0
        self.locked_until = None
        db.session.commit()

    def record_failed_login(self, max_attempts=5, lockout_minutes=15):
        """Registra tentativa de login falha."""
        self.failed_login_count = (self.failed_login_count or 0) + 1
        if self.failed_login_count >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.session.commit()

    def is_locked(self):
        """Verifica se conta está bloqueada."""
        if self.locked_until:
            locked_until = self.locked_until
            # Make timezone-aware if stored as naive UTC
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > datetime.now(timezone.utc):
                return True
        return False
    
    @property
    def full_name(self):
        """Retorna nome completo do usuário."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        return self.username

    @property
    def role_names(self):
        """Retorna lista de nomes das roles."""
        return [role.name for role in self.roles.all()]
    
    def to_dict(self, include_sensitive=False):
        """Converte para dicionário."""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'email_confirmed': self.email_confirmed,
            'roles': self.role_names,
            'department': self.department,
            'job_title': self.job_title,
            'timezone': self.timezone,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_sensitive:
            data['api_key'] = self.api_key
            data['has_api_key'] = bool(self.api_key)
        
        return data
    
    @classmethod
    def get_by_username(cls, username):
        """Busca usuário por username."""
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def get_by_email(cls, email):
        """Busca usuário por email."""
        return cls.query.filter_by(email=email.lower()).first()
    
    @classmethod
    def get_by_api_key(cls, api_key):
        """Busca usuário por API key."""
        return cls.query.filter_by(api_key=api_key, is_active=True).first()
    
    @classmethod
    def get_active_users(cls):
        """Retorna todos os usuários ativos."""
        return cls.query.filter_by(is_active=True).all()
    
    @classmethod
    def get_admins(cls):
        """Retorna todos os administradores."""
        return cls.query.filter_by(is_admin=True, is_active=True).all()
    
    @classmethod
    def has_active_users(cls):
        """Verifica se existem usuários ativos no sistema."""
        return cls.query.filter_by(is_active=True).first() is not None
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"
