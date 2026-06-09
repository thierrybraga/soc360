"""
SOC360 Report Model
Model para relatórios gerados pelo sistema.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, ForeignKey, DateTime
from app.extensions.db_types import JSONB
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel
from app.models.system.enums import ReportType, ReportStatus


class Report(CoreModel):
    """
    Model de relatório.
    
    Armazena relatórios executivos e técnicos, incluindo:
    - Dados agregados (snapshot imutável)
    - Resumo gerado por IA
    - Recomendações
    - Arquivo PDF gerado
    """
    __tablename__ = 'reports'
    
    # Identificação
    title = Column(String(500), nullable=False)
    description = Column(Text(), nullable=True)
    
    # Owner
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    
    # Tipo e Status
    report_type = Column(String(50), default=ReportType.EXECUTIVE.value, nullable=False)
    status = Column(String(50), default=ReportStatus.PENDING.value, nullable=False)
    
    # Filtros aplicados
    filters = Column(JSONB, nullable=True)
    """
    Estrutura:
    {
        "date_range": {"start": "2024-01-01", "end": "2024-01-31"},
        "severities": ["CRITICAL", "HIGH"],
        "vendors": ["microsoft"],
        "asset_ids": [1, 2, 3]
    }
    """
    
    # Dados agregados (snapshot)
    data = Column(JSONB, nullable=True)
    """
    Estrutura:
    {
        "summary": {
            "total_vulnerabilities": 1234,
            "critical_count": 45,
            "high_count": 123,
            ...
        },
        "severity_distribution": {"CRITICAL": 45, "HIGH": 123, ...},
        "top_vendors": [{"name": "microsoft", "count": 200}, ...],
        "top_cwes": [{"cwe_id": "CWE-79", "count": 50}, ...],
        "recent_critical": [...],
        "assets_at_risk": [...]
    }
    """
    
    # AI-Generated Content
    ai_summary = Column(Text(), nullable=True)
    ai_recommendations = Column(JSONB, nullable=True)
    """
    Estrutura:
    [
        {
            "priority": "HIGH",
            "title": "Patch Critical Vulnerabilities",
            "description": "...",
            "affected_count": 45
        },
        ...
    ]
    """
    ai_risk_analysis = Column(Text(), nullable=True)
    ai_generated_at = Column(DateTime, nullable=True)
    ai_model_used = Column(String(100), nullable=True)
    
    # PDF Output
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)  # bytes
    
    # Timing
    generation_started_at = Column(DateTime, nullable=True)
    generation_completed_at = Column(DateTime, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Sharing
    is_public = Column(db.Boolean, default=False)
    share_token = Column(String(64), nullable=True, unique=True)
    share_expires_at = Column(DateTime, nullable=True)  # None = sem expiração
    
    # Relationships
    user = relationship('User', back_populates='reports')
    
    def __init__(self, title, user_id, report_type=ReportType.EXECUTIVE.value, **kwargs):
        """Inicializa relatório."""
        super().__init__(**kwargs)
        self.title = title
        self.user_id = user_id
        self.report_type = report_type
        self.status = ReportStatus.PENDING.value
    
    @property
    def generation_time_seconds(self):
        """Retorna tempo de geração em segundos."""
        if self.generation_started_at and self.generation_completed_at:
            delta = self.generation_completed_at - self.generation_started_at
            return delta.total_seconds()
        return None
    
    @property
    def has_ai_content(self):
        """Verifica se tem conteúdo de IA."""
        return bool(self.ai_summary or self.ai_recommendations)
    
    @property
    def has_pdf(self):
        """Verifica se PDF foi gerado."""
        return bool(self.file_path)
    
    def start_generation(self):
        """Marca início da geração."""
        self.status = ReportStatus.GENERATING.value
        self.generation_started_at = datetime.utcnow()
        db.session.commit()
    
    def complete_generation(self, file_path=None, file_size=None):
        """Marca fim da geração com sucesso."""
        self.status = ReportStatus.COMPLETED.value
        self.generation_completed_at = datetime.utcnow()
        if file_path:
            self.file_path = file_path
        if file_size:
            self.file_size = file_size
        db.session.commit()
    
    def fail_generation(self, error_message):
        """Marca falha na geração."""
        self.status = ReportStatus.FAILED.value
        self.error_message = error_message
        self.generation_completed_at = datetime.utcnow()
        db.session.commit()
    
    def set_ai_content(self, summary, recommendations=None, risk_analysis=None, model_used=None):
        """Define conteúdo gerado por IA."""
        self.ai_summary = summary
        if recommendations:
            self.ai_recommendations = recommendations
        if risk_analysis:
            self.ai_risk_analysis = risk_analysis
        self.ai_generated_at = datetime.utcnow()
        self.ai_model_used = model_used
        db.session.commit()
    
    def generate_share_token(self, expires_hours: int = None):
        """Gera token para compartilhamento.

        Args:
            expires_hours: Horas até o link expirar. None = sem expiração.
        """
        import secrets
        from datetime import timedelta
        self.share_token = secrets.token_urlsafe(48)
        self.is_public = True
        if expires_hours:
            self.share_expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
        else:
            self.share_expires_at = None
        db.session.commit()
        return self.share_token
    
    def revoke_share(self):
        """Revoga compartilhamento."""
        self.share_token = None
        self.is_public = False
        db.session.commit()
    
    def to_dict(self, include_data=False, include_ai=True):
        """Converte para dicionário."""
        result = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'user_id': self.user_id,
            'report_type': self.report_type,
            'status': self.status,
            'error_message': self.error_message,
            'filters': self.filters,
            'ai_status': (self.data or {}).get('ai_status') if isinstance(self.data, dict) else None,
            'has_ai_content': self.has_ai_content,
            'has_pdf': self.has_pdf,
            'file_size': self.file_size,
            'generation_time_seconds': self.generation_time_seconds,
            'is_public': self.is_public,
            'share_expires_at': self.share_expires_at.isoformat() if self.share_expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'generation_completed_at': self.generation_completed_at.isoformat() if self.generation_completed_at else None
        }
        
        if include_data:
            result['data'] = self.data
        
        if include_ai:
            result['ai_summary'] = self.ai_summary
            result['ai_recommendations'] = self.ai_recommendations
            result['ai_risk_analysis'] = self.ai_risk_analysis
            result['ai_model_used'] = self.ai_model_used
        
        return result
    
    @classmethod
    def get_by_user(cls, user_id, limit=20):
        """Retorna relatórios de um usuário."""
        return cls.query.filter_by(user_id=user_id).order_by(
            cls.created_at.desc()
        ).limit(limit).all()
    
    @classmethod
    def get_by_share_token(cls, token):
        """Busca relatório por token de compartilhamento."""
        return cls.query.filter_by(share_token=token, is_public=True).first()
    
    @classmethod
    def get_recent(cls, limit=10):
        """Retorna relatórios recentes."""
        return cls.query.filter_by(status=ReportStatus.COMPLETED.value).order_by(
            cls.created_at.desc()
        ).limit(limit).all()
    
    def __repr__(self):
        return f"<Report(id={self.id}, title='{self.title}', type='{self.report_type}', status='{self.status}')>"


class RiskAssessment(CoreModel):
    """
    Model de avaliação de risco.
    
    Armazena avaliações de risco pontuais para ativos ou grupos de ativos.
    """
    __tablename__ = 'risk_assessments'
    
    # Identificação
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Owner
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True
    )
    
    # Escopo
    scope = Column(String(50), nullable=False)  # ASSET, ASSET_GROUP, ORGANIZATION
    asset_ids = Column(JSONB, nullable=True)  # Lista de IDs de ativos
    
    # Scores calculados
    overall_risk_score = Column(db.Float, nullable=True)  # 0-10
    vulnerability_score = Column(db.Float, nullable=True)
    exposure_score = Column(db.Float, nullable=True)
    impact_score = Column(db.Float, nullable=True)
    
    # Detalhamento
    risk_breakdown = Column(JSONB, nullable=True)
    """
    {
        "critical_vulns": 5,
        "high_vulns": 20,
        "exposed_assets": 10,
        "cisa_kev_count": 2,
        "factors": [
            {"name": "High-value assets exposed", "impact": 0.8},
            ...
        ]
    }
    """
    
    # Recomendações
    recommendations = Column(JSONB, nullable=True)
    
    # Status
    status = Column(String(50), default='CURRENT')  # CURRENT, HISTORICAL, SUPERSEDED
    
    # Timestamps
    assessed_at = Column(DateTime, default=datetime.utcnow)
    valid_until = Column(DateTime, nullable=True)
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'scope': self.scope,
            'asset_ids': self.asset_ids,
            'overall_risk_score': self.overall_risk_score,
            'vulnerability_score': self.vulnerability_score,
            'exposure_score': self.exposure_score,
            'impact_score': self.impact_score,
            'risk_breakdown': self.risk_breakdown,
            'recommendations': self.recommendations,
            'status': self.status,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }
    
    def __repr__(self):
        return f"<RiskAssessment(id={self.id}, name='{self.name}', score={self.overall_risk_score})>"
