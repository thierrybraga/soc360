"""
Wazuh Alert model.

Local mirror of alerts ingested from the Wazuh Indexer (``wazuh-alerts-*``
indices). The full raw ``_source`` is persisted in :attr:`raw` for forensic
reference; the flat columns exist for fast dashboard queries.

SOC treatment workflow fields (status, assigned_to, resolution, AI summary)
are maintained locally and never written back to Wazuh.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship

from app.extensions.db_types import JSONB
from app.models.system.base_model import CoreModel


# Treatment workflow statuses
WAZUH_ALERT_STATUSES = (
    'NEW',            # just ingested
    'TRIAGED',        # analyst has looked at it
    'IN_PROGRESS',    # actively being investigated
    'RESOLVED',       # real incident, handled
    'FALSE_POSITIVE', # not a real issue
    'DISMISSED',      # intentionally ignored (noise)
    'ESCALATED',      # handed to another team/tier
)

# Severity tiers derived from ``rule.level`` (Wazuh scale 0–15)
WAZUH_SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')


def severity_from_level(level) -> str:
    """Map Wazuh rule.level (0–15) to a SOC severity tier.

    0–6 → LOW, 7–11 → MEDIUM, 12–13 → HIGH, 14–15 → CRITICAL. Invalid
    values default to LOW (safer than losing the alert).
    """
    try:
        n = int(level)
    except (TypeError, ValueError):
        return 'LOW'
    if n >= 14:
        return 'CRITICAL'
    if n >= 12:
        return 'HIGH'
    if n >= 7:
        return 'MEDIUM'
    return 'LOW'


class WazuhAlert(CoreModel):
    __tablename__ = 'wazuh_alerts'

    # ── Wazuh identity ──────────────────────────────────────────────────
    # Composite uid "<index>:<_id>" guarantees idempotent upserts across
    # rolling daily indices (wazuh-alerts-4.x-YYYY.MM.DD) where the same
    # _id can theoretically repeat after index rollover.
    alert_uid = Column(String(160), unique=True, index=True, nullable=False)
    wazuh_id = Column(String(80), index=True, nullable=False)
    wazuh_index = Column(String(128))

    # ── Alert core ──────────────────────────────────────────────────────
    timestamp = Column(DateTime, nullable=False, index=True)

    rule_id = Column(String(32), index=True)
    rule_level = Column(Integer, index=True)
    rule_description = Column(Text)
    rule_groups = Column(JSONB)                 # list[str]
    rule_mitre_ids = Column(JSONB)              # list[str]
    rule_mitre_tactics = Column(JSONB)          # list[str]
    rule_mitre_techniques = Column(JSONB)       # list[str]

    agent_id = Column(String(32), index=True)
    agent_name = Column(String(255), index=True)
    agent_ip = Column(String(64))
    manager_name = Column(String(255))

    decoder_name = Column(String(128))
    location = Column(Text)
    full_log = Column(Text)
    src_ip = Column(String(64), index=True)
    dst_ip = Column(String(64))

    severity = Column(String(20), index=True)   # LOW | MEDIUM | HIGH | CRITICAL
    raw = Column(JSONB)                         # full _source blob

    # ── SOC treatment workflow ──────────────────────────────────────────
    status = Column(String(30), default='NEW', nullable=False, index=True)
    assigned_to_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    triaged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution = Column(Text)                   # closing comment

    # ── Cached AI analysis ─────────────────────────────────────────────
    ai_summary = Column(Text)
    ai_recommendations = Column(JSONB)          # list[str]
    ai_analysis_at = Column(DateTime, nullable=True)

    # Relationships
    assigned_to = relationship('User', foreign_keys=[assigned_to_id])

    __table_args__ = (
        Index('ix_wazuh_alerts_sev_status', 'severity', 'status'),
        Index('ix_wazuh_alerts_ts_sev', 'timestamp', 'severity'),
    )

    # ── Serialization ──────────────────────────────────────────────────
    def to_dict(self, *, include_raw: bool = False):
        return {
            'id': self.id,
            'alert_uid': self.alert_uid,
            'wazuh_id': self.wazuh_id,
            'wazuh_index': self.wazuh_index,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'rule_id': self.rule_id,
            'rule_level': self.rule_level,
            'rule_description': self.rule_description,
            'rule_groups': self.rule_groups or [],
            'rule_mitre_ids': self.rule_mitre_ids or [],
            'rule_mitre_tactics': self.rule_mitre_tactics or [],
            'rule_mitre_techniques': self.rule_mitre_techniques or [],
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'agent_ip': self.agent_ip,
            'manager_name': self.manager_name,
            'decoder_name': self.decoder_name,
            'location': self.location,
            'full_log': self.full_log,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'severity': self.severity,
            'status': self.status,
            'assigned_to_id': self.assigned_to_id,
            'assigned_to_name': self.assigned_to.username if self.assigned_to else None,
            'triaged_at': self.triaged_at.isoformat() if self.triaged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution': self.resolution,
            'ai_summary': self.ai_summary,
            'ai_recommendations': self.ai_recommendations or [],
            'ai_analysis_at': self.ai_analysis_at.isoformat() if self.ai_analysis_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            **({'raw': self.raw} if include_raw else {}),
        }

    # ── Convenience mutators (used by controller) ──────────────────────
    def mark_triaged(self, user_id):
        self.status = 'TRIAGED'
        self.triaged_at = datetime.now(timezone.utc)
        if not self.assigned_to_id:
            self.assigned_to_id = user_id

    def mark_resolved(self, user_id, resolution: str = '', *,
                      status: str = 'RESOLVED'):
        if status not in ('RESOLVED', 'FALSE_POSITIVE', 'DISMISSED'):
            raise ValueError(f'Unsupported resolution status: {status}')
        self.status = status
        self.resolved_at = datetime.now(timezone.utc)
        if resolution:
            self.resolution = resolution
        if not self.assigned_to_id:
            self.assigned_to_id = user_id
