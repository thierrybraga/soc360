"""
SOC360 MonitoringRule Model
Model para regras de monitoramento e alertas.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, ForeignKey, Boolean, DateTime
from app.extensions.db_types import JSONB
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import CoreModel
from app.models.system.enums import MonitoringRuleType, AlertChannel


class MonitoringRule(CoreModel):
    """
    Model de regra de monitoramento.
    
    Define condições para disparo de alertas quando novas CVEs
    são descobertas ou quando condições específicas são atendidas.
    """
    __tablename__ = 'monitoring_rules'
    
    # Identificação
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Owner
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Tipo e Status
    rule_type = Column(String(50), default=MonitoringRuleType.NEW_CVE.value, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Critérios (JSON)
    parameters = Column(JSONB, nullable=False, default=dict)
    """
    Estrutura de parameters por tipo:
    
    NEW_CVE:
    {
        "severity_threshold": ["CRITICAL", "HIGH"],
        "vendor_filter": ["microsoft", "cisco"],
        "product_filter": ["windows", "ios"],
        "keywords": ["remote code execution", "authentication bypass"]
    }
    
    SEVERITY_THRESHOLD:
    {
        "min_cvss_score": 7.0,
        "severity_levels": ["CRITICAL", "HIGH"]
    }
    
    VENDOR_SPECIFIC:
    {
        "vendors": ["microsoft", "cisco"],
        "include_all_severities": false
    }
    
    CISA_KEV:
    {
        "notify_on_add": true,
        "notify_before_due": 7  # dias antes do prazo
    }
    
    ASSET_EXPOSURE:
    {
        "asset_ids": [1, 2, 3],
        "criticality_levels": ["CRITICAL", "HIGH"]
    }
    """
    
    # Canais de alerta
    alert_channels = Column(JSONB, nullable=False, default=list)
    """
    Estrutura:
    [
        {"type": "EMAIL", "config": {"recipients": ["user@example.com"]}},
        {"type": "WEBHOOK", "config": {"url": "https://..."}}
    ]
    """
    
    # Throttling
    cooldown_minutes = Column(Integer, default=60)  # Tempo mínimo entre alertas
    max_alerts_per_day = Column(Integer, default=10)
    
    # Tracking
    last_triggered_at = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Scheduling (para verificações periódicas)
    schedule_cron = Column(String(100), nullable=True)  # Cron expression
    
    # Relationships
    user = relationship('User', back_populates='monitoring_rules')
    
    def __init__(self, name, user_id, rule_type=MonitoringRuleType.NEW_CVE.value, **kwargs):
        """Inicializa regra."""
        super().__init__(**kwargs)
        self.name = name
        self.user_id = user_id
        self.rule_type = rule_type
        if 'parameters' not in kwargs:
            self.parameters = {}
        if 'alert_channels' not in kwargs:
            self.alert_channels = []
    
    def matches_vulnerability(self, vulnerability):
        """
        Verifica se uma vulnerabilidade atende aos critérios da regra.
        
        Args:
            vulnerability: Objeto Vulnerability
        
        Returns:
            bool: True se a vulnerabilidade atende aos critérios
        """
        params = self.parameters or {}

        # Verificar severidade
        severity_threshold = [
            str(severity).upper()
            for severity in params.get('severity_threshold', [])
            if severity
        ]
        vulnerability_severity = str(getattr(vulnerability, 'base_severity', '') or '').upper()
        min_score = params.get('min_cvss_score')
        try:
            min_score = float(min_score) if min_score is not None else None
        except (TypeError, ValueError):
            min_score = None
        cvss_score = getattr(vulnerability, 'cvss_score', None)
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        if severity_threshold and vulnerability_severity not in severity_threshold:
            if min_score is None or cvss_score is None or cvss_score < float(min_score):
                return False
        elif min_score is not None and (cvss_score is None or cvss_score < float(min_score)):
            return False

        severity_levels = [
            str(severity).upper()
            for severity in params.get('severity_levels', [])
            if severity
        ]
        if severity_levels and vulnerability_severity not in severity_levels:
            if min_score is None or cvss_score is None or cvss_score < float(min_score):
                return False

        # Verificar vendor
        vendor_filter = params.get('vendor_filter', [])
        if vendor_filter:
            vuln_vendors = [v.lower() for v in (vulnerability.vendors or [])]
            if not any(
                vf.lower() == vendor or vf.lower() in vendor or vendor in vf.lower()
                for vf in vendor_filter
                for vendor in vuln_vendors
            ):
                return False

        # Verificar product
        product_filter = params.get('product_filter', [])
        if product_filter:
            vuln_products = [p.lower() for p in (vulnerability.products or [])]
            if not any(
                pf.lower() == product or pf.lower() in product or product in pf.lower()
                for pf in product_filter
                for product in vuln_products
            ):
                return False

        # Verificar keywords
        keywords = params.get('keywords', [])
        if keywords:
            if not vulnerability.description:
                return False
            desc_lower = vulnerability.description.lower()
            if not any(kw.lower() in desc_lower for kw in keywords):
                return False

        # Verificar CISA KEV
        if self.rule_type == MonitoringRuleType.CISA_KEV.value:
            if not vulnerability.is_in_cisa_kev:
                return False
        
        return True
    
    def can_trigger(self):
        """Verifica se a regra pode disparar (cooldown, limite diário)."""
        if not self.enabled:
            return False
        
        # Verificar cooldown
        if self.last_triggered_at:
            from datetime import timedelta
            cooldown_end = self.last_triggered_at + timedelta(minutes=self.cooldown_minutes)
            if datetime.utcnow() < cooldown_end:
                return False
        
        # Verificar limite diário
        # (Implementação simplificada - idealmente contaria triggers do dia)
        
        return True
    
    def record_trigger(self, success=True, error=None):
        """Registra disparo da regra."""
        self.last_triggered_at = datetime.utcnow()
        self.trigger_count = (self.trigger_count or 0) + 1
        if error:
            self.last_error = str(error)
        db.session.commit()
    
    def add_email_channel(self, recipients):
        """Adiciona canal de email."""
        if not self.alert_channels:
            self.alert_channels = []
        
        self.alert_channels.append({
            'type': AlertChannel.EMAIL.value,
            'config': {'recipients': recipients}
        })
        db.session.commit()
    
    def add_webhook_channel(self, url, headers=None):
        """Adiciona canal de webhook."""
        if not self.alert_channels:
            self.alert_channels = []
        
        config = {'url': url}
        if headers:
            config['headers'] = headers
        
        self.alert_channels.append({
            'type': AlertChannel.WEBHOOK.value,
            'config': config
        })
        db.session.commit()
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id,
            'rule_type': self.rule_type,
            'enabled': self.enabled,
            'parameters': self.parameters,
            'alert_channels': self.alert_channels,
            'cooldown_minutes': self.cooldown_minutes,
            'max_alerts_per_day': self.max_alerts_per_day,
            'last_triggered_at': self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            'trigger_count': self.trigger_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def get_active_rules(cls):
        """Retorna todas as regras ativas."""
        return cls.query.filter_by(enabled=True).all()
    
    @classmethod
    def get_by_user(cls, user_id):
        """Retorna regras de um usuário."""
        return cls.query.filter_by(user_id=user_id).order_by(cls.name).all()
    
    def __repr__(self):
        return f"<MonitoringRule(id={self.id}, name='{self.name}', type='{self.rule_type}')>"
