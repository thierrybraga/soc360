"""
MITRE D3FEND Tactic Model
Táticas defensivas do framework D3FEND
"""
from app.extensions.db import db
from datetime import datetime


class D3fendTactic(db.Model):
    """
    Tática defensiva do MITRE D3FEND.
    
    Agrupa técnicas defensivas por objetivo estratégico.
    """
    __tablename__ = 'd3fend_tactics'
    __bind_key__ = 'public'
    
    id = db.Column(db.String(50), primary_key=True)  # e.g., "detect"
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500))
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sync = db.Column(db.DateTime)
    
    # Relacionamentos
    techniques = db.relationship('D3fendTechnique', back_populates='tactic', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'technique_count': self.techniques.count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<D3fendTactic(id='{self.id}', name='{self.name}')>"
