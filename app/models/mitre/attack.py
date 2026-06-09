"""
SOC360 MITRE ATT&CK Models
Modelos para Táticas, Técnicas e Mitigações do framework MITRE ATT&CK.
"""
from sqlalchemy import Column, String, Integer, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.extensions.db import db
from app.models.system.base_model import PublicModel

# Tabelas de associação (sem bind_key → metadata default).
# IMPORTANTE: estas M2M são referenciadas por primaryjoin em STRING nas
# relationships abaixo (ex.: "Tactic.id == mitre_technique_tactics.c.tactic_id").
# A resolução de nome de tabela por string do SQLAlchemy procura no metadata
# default — não nas metadatas por-bind. Mantê-las no default é obrigatório para
# a configuração dos mappers funcionar. Como core e public usam o MESMO banco
# físico (relações cross-bind exigem isso), ficam no banco correto de qualquer
# forma. NÃO usar bind_key aqui.
technique_tactic_association = db.Table(
    'mitre_technique_tactics',
    Column('technique_id', Integer, primary_key=True),
    Column('tactic_id', Integer, primary_key=True),
)

# Tabela de associação entre Técnicas e Mitigações
technique_mitigation_association = db.Table(
    'mitre_technique_mitigations',
    Column('technique_id', Integer, primary_key=True),
    Column('mitigation_id', Integer, primary_key=True),
)

class Tactic(PublicModel):
    """
    Representa uma Tática do MITRE ATT&CK (ex: Initial Access, Persistence).
    """
    __tablename__ = 'mitre_tactics'
    __bind_key__ = 'public'
    
    stix_id = Column(String(100), unique=True, nullable=False, index=True)
    external_id = Column(String(20), unique=True, nullable=False, index=True) # TA0001
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=True)
    
    # Relationships
    techniques = relationship(
        'Technique',
        secondary=technique_tactic_association,
        primaryjoin="Tactic.id == mitre_technique_tactics.c.tactic_id",
        secondaryjoin="Technique.id == mitre_technique_tactics.c.technique_id",
        back_populates='tactics',
        viewonly=True # Para evitar problemas de gravação sem FKs explícitas no metadata
    )

    def to_dict(self):
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'external_id': self.external_id,
            'name': self.name,
            'description': self.description,
            'url': self.url
        }

class Technique(PublicModel):
    """
    Representa uma Técnica ou Sub-técnica do MITRE ATT&CK (ex: Phishing, DLL Side-Loading).
    """
    __tablename__ = 'mitre_techniques'
    __bind_key__ = 'public'
    
    stix_id = Column(String(100), unique=True, nullable=False, index=True)
    external_id = Column(String(20), unique=True, nullable=False, index=True) # T1001 or T1001.001
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=True)
    is_subtechnique = Column(Boolean, default=False)
    
    # Hierarquia (Sub-técnicas)
    parent_id = Column(Integer, nullable=True)
    
    # Relationships
    tactics = relationship(
        'Tactic',
        secondary=technique_tactic_association,
        primaryjoin="Technique.id == mitre_technique_tactics.c.technique_id",
        secondaryjoin="Tactic.id == mitre_technique_tactics.c.tactic_id",
        back_populates='techniques',
        viewonly=True
    )
    
    mitigations = relationship(
        'AttackMitigation',
        secondary=technique_mitigation_association,
        primaryjoin="Technique.id == mitre_technique_mitigations.c.technique_id",
        secondaryjoin="AttackMitigation.id == mitre_technique_mitigations.c.mitigation_id",
        back_populates='techniques',
        viewonly=True
    )

    def to_dict(self):
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'external_id': self.external_id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'is_subtechnique': self.is_subtechnique,
            'parent_id': self.parent_id,
            'tactics': [t.external_id for t in self.tactics]
        }

class AttackMitigation(PublicModel):
    """
    Representa uma Mitigação do MITRE ATT&CK (ex: Antivirus, Data Backup).
    """
    __tablename__ = 'mitre_attack_mitigations'
    __bind_key__ = 'public'
    
    stix_id = Column(String(100), unique=True, nullable=False, index=True)
    external_id = Column(String(20), unique=True, nullable=False, index=True) # M1001
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=True)
    
    # Relationships
    techniques = relationship(
        'Technique',
        secondary=technique_mitigation_association,
        primaryjoin="AttackMitigation.id == mitre_technique_mitigations.c.mitigation_id",
        secondaryjoin="Technique.id == mitre_technique_mitigations.c.technique_id",
        back_populates='mitigations',
        viewonly=True
    )

    def to_dict(self):
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'external_id': self.external_id,
            'name': self.name,
            'description': self.description,
            'url': self.url
        }
