"""
MITRE D3FEND Artifact Model
Artefatos defensivos (firewalls, IDS, EDR, etc.)
"""
from app.extensions.db import db
from datetime import datetime


class D3fendArtifact(db.Model):
    """
    Artefato defensivo do MITRE D3FEND.
    
    Representa componentes de segurança como firewalls, IDS, EDR, etc.
    """
    __tablename__ = 'd3fend_artifacts'
    __bind_key__ = 'public'
    
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500))
    
    # Categorização
    artifact_type = db.Column(db.String(100))  # Software, Hardware, Service
    category = db.Column(db.String(100))  # Firewall, IDS, EDR, etc.
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sync = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'artifact_type': self.artifact_type,
            'category': self.category,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<D3fendArtifact(id='{self.id}', name='{self.name}')>"
