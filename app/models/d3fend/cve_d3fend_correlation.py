"""
CVE D3FEND Correlation Model
Correlação entre CVE e contramedidas D3FEND
"""
from app.extensions.db import db
from datetime import datetime


class CveD3fendCorrelation(db.Model):
    """
    Correlação entre uma CVE e técnicas D3FEND aplicáveis.
    
    Permite recomendar contramedidas defensivas para vulnerabilidades.
    """
    __tablename__ = 'cve_d3fend_correlations'
    __bind_key__ = 'public'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # CVE
    cve_id = db.Column(db.String(50), db.ForeignKey('vulnerabilities.cve_id'), nullable=False)
    
    # D3FEND Technique que mitiga
    d3fend_technique_id = db.Column(db.String(50), db.ForeignKey('d3fend_techniques.id'), nullable=False)
    
    # Relevância da correlação
    confidence = db.Column(db.Float, default=0.0)  # 0.0 a 1.0
    
    # Caminho de correlação: CVE → CWE → ATT&CK → D3FEND
    correlation_path = db.Column(db.JSON)  # ['CWE-79', 'T1190', 'D3-DA']
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'd3fend_technique_id': self.d3fend_technique_id,
            'confidence': self.confidence,
            'correlation_path': self.correlation_path,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<CveD3fendCorrelation(cve='{self.cve_id}', d3fend='{self.d3fend_technique_id}')>"
