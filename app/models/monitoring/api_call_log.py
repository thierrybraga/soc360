"""
SOC360 ApiCallLog Model
Model para log de chamadas de API (auditoria).
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, Float
from app.extensions.db_types import JSONB, INET
from app.extensions.db import db
from app.models.system.base_model import CoreModel


class ApiCallLog(CoreModel):
    """
    Log de chamadas de API para auditoria e análise.
    """
    __tablename__ = 'api_call_logs'
    
    # Request info
    method = Column(String(10), nullable=False)  # GET, POST, etc
    endpoint = Column(String(500), nullable=False, index=True)
    path = Column(String(500), nullable=True)
    query_params = Column(JSONB, nullable=True)
    
    # User info
    user_id = Column(Integer, nullable=True, index=True)
    api_key_used = Column(db.Boolean, default=False)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Response info
    status_code = Column(Integer, nullable=True, index=True)
    response_time_ms = Column(Float, nullable=True)
    
    # Error info
    error_message = Column(Text(), nullable=True)
    error_type = Column(String(100), nullable=True)
    
    # Request body (opcional, pode conter dados sensíveis)
    request_body_hash = Column(String(64), nullable=True)  # SHA256 do body
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    @classmethod
    def log_request(cls, method, endpoint, user_id=None, ip_address=None, 
                    user_agent=None, api_key_used=False, path=None, query_params=None):
        """Cria log de request (antes da resposta)."""
        log = cls(
            method=method,
            endpoint=endpoint,
            path=path,
            query_params=query_params,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
            api_key_used=api_key_used
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def complete(self, status_code, response_time_ms=None, error_message=None, error_type=None):
        """Completa log com dados da resposta."""
        self.status_code = status_code
        self.response_time_ms = response_time_ms
        if error_message:
            self.error_message = error_message
            self.error_type = error_type
        db.session.commit()
    
    @classmethod
    def get_recent(cls, limit=100, user_id=None, endpoint_filter=None):
        """Retorna logs recentes."""
        query = cls.query.order_by(cls.timestamp.desc())
        if user_id:
            query = query.filter_by(user_id=user_id)
        if endpoint_filter:
            query = query.filter(cls.endpoint.ilike(f'%{endpoint_filter}%'))
        return query.limit(limit).all()
    
    @classmethod
    def get_error_logs(cls, limit=100, hours=24):
        """Retorna logs de erro recentes."""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return cls.query.filter(
            cls.timestamp >= cutoff,
            cls.status_code >= 400
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_stats(cls, hours=24):
        """Retorna estatísticas de uso."""
        from sqlalchemy import func
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        total = cls.query.filter(cls.timestamp >= cutoff).count()
        errors = cls.query.filter(
            cls.timestamp >= cutoff,
            cls.status_code >= 400
        ).count()
        
        avg_response_time = db.session.query(
            func.avg(cls.response_time_ms)
        ).filter(
            cls.timestamp >= cutoff,
            cls.response_time_ms.isnot(None)
        ).scalar()
        
        return {
            'total_requests': total,
            'error_count': errors,
            'error_rate': (errors / total * 100) if total > 0 else 0,
            'avg_response_time_ms': round(avg_response_time or 0, 2),
            'period_hours': hours
        }
    
    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'method': self.method,
            'endpoint': self.endpoint,
            'path': self.path,
            'user_id': self.user_id,
            'api_key_used': self.api_key_used,
            'ip_address': str(self.ip_address) if self.ip_address else None,
            'status_code': self.status_code,
            'response_time_ms': self.response_time_ms,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __repr__(self):
        return f"<ApiCallLog(id={self.id}, {self.method} {self.endpoint}, status={self.status_code})>"
