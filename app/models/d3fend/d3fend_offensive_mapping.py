"""
MITRE D3FEND Offensive Mapping Model
Mapeamento entre D3FEND (defensivo) e ATT&CK (ofensivo)
"""
from app.extensions.db import db
from datetime import datetime


class D3fendOffensiveMapping(db.Model):
    """
    Mapeamento entre técnicas D3FEND e ATT&CK.
    
    Relaciona contramedidas defensivas com técnicas ofensivas.
    """
    __tablename__ = 'd3fend_offensive_mappings'
    __bind_key__ = 'public'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # D3FEND Technique
    d3fend_technique_id = db.Column(db.String(50), db.ForeignKey('d3fend_techniques.id'), nullable=False)
    
    # ATT&CK Technique (referência externa - string pois pode vir de outra tabela)
    attack_technique_id = db.Column(db.String(50), nullable=False)  # ex: T1190
    
    # Tipo de relação
    mapping_type = db.Column(db.String(50))  # detects, hardens, isolates, etc.
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    d3fend_technique = db.relationship('D3fendTechnique', back_populates='offensive_mappings')
    
    def to_dict(self):
        return {
            'id': self.id,
            'd3fend_technique_id': self.d3fend_technique_id,
            'attack_technique_id': self.attack_technique_id,
            'mapping_type': self.mapping_type,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<D3fendOffensiveMapping(d3fend='{self.d3fend_technique_id}', attack='{self.attack_technique_id}')>"
