"""
MITRE D3FEND Technique Model
Técnicas defensivas do framework D3FEND
"""
from app.extensions.db import db
from datetime import datetime


class D3fendTechnique(db.Model):
    """
    Técnica defensiva do MITRE D3FEND.
    
    Relacionamentos:
    - Pertence a uma Tática (d3fend_tactic)
    - Mapeia para ATT&CK Techniques (via D3fendOffensiveMapping)
    - Implementa Artefatos (d3fend_artifacts)
    """
    __tablename__ = 'd3fend_techniques'
    __bind_key__ = 'public'
    
    id = db.Column(db.String(50), primary_key=True)  # e.g., "D3-DA"
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500))
    
    # Categorização
    tactic_id = db.Column(db.String(50), db.ForeignKey('d3fend_tactics.id'), nullable=True)
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sync = db.Column(db.DateTime)
    
    # Relacionamentos
    tactic = db.relationship('D3fendTactic', back_populates='techniques')
    offensive_mappings = db.relationship('D3fendOffensiveMapping', back_populates='d3fend_technique')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'tactic_id': self.tactic_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f"<D3fendTechnique(id='{self.id}', name='{self.name}')>"
