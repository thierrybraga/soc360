"""
SOC360 Alert Model
Model para alertas gerados por regras de monitoramento.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, ForeignKey, DateTime, Boolean
from app.extensions.db_types import JSONB
from sqlalchemy.orm import relationship
from app.models.system.base_model import CoreModel
from app.models.system.enums import AlertStatus, Severity

class Alert(CoreModel):
    """
    Model de alerta gerado pelo sistema.
    """
    __tablename__ = 'alerts'

    # Identificação
    title = Column(String(255), nullable=False)
    description = Column(Text(), nullable=True)
    
    # Relacionamentos
    rule_id = Column(Integer, ForeignKey('monitoring_rules.id'), nullable=True)
    cve_id = Column(String(20), index=True, nullable=True)  # Referência opcional à CVE
    
    # Status e Severidade
    status = Column(String(50), default=AlertStatus.NEW.value, nullable=False)
    severity = Column(String(50), default=Severity.MEDIUM.value, nullable=False)
    
    # Dados adicionais
    details = Column(JSONB, nullable=True)
    
    # Ações
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Relationships
    rule = relationship('MonitoringRule', backref='alerts')
    acknowledged_by = relationship('User', foreign_keys=[acknowledged_by_id])
    resolved_by = relationship('User', foreign_keys=[resolved_by_id])

    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'rule_id': self.rule_id,
            'rule_name': self.rule.name if self.rule else None,
            'cve_id': self.cve_id,
            'status': self.status,
            'severity': self.severity,
            'details': self.details,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'acknowledged_by_name': self.acknowledged_by.username if self.acknowledged_by else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by_name': self.resolved_by.username if self.resolved_by else None
        }

    def mark_as_acknowledged(self, user_id):
        self.status = AlertStatus.ACKNOWLEDGED.value
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by_id = user_id

    def mark_as_resolved(self, user_id):
        self.status = AlertStatus.RESOLVED.value
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by_id = user_id

    def mark_as_dismissed(self, user_id):
        self.status = AlertStatus.DISMISSED.value
        # Dismissed is effectively resolved but ignored
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by_id = user_id
