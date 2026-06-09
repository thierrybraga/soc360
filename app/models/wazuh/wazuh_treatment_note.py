"""
Wazuh Alert treatment audit trail.

Every workflow mutation on a :class:`WazuhAlert` (status change, assignment,
analyst comment, AI analysis run) appends a row here. The dashboard timeline
reads this table to show who did what and when.
"""
from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.extensions.db_types import JSONB
from app.models.system.base_model import CoreModel


TREATMENT_ACTIONS = (
    'COMMENT',         # free-form analyst note
    'STATUS_CHANGE',   # status field mutated
    'ASSIGN',          # assignee mutated
    'AI_ANALYSIS',     # AI summary generated
    'INGESTED',        # initial sync row (optional, not always written)
)


class WazuhTreatmentNote(CoreModel):
    __tablename__ = 'wazuh_treatment_notes'

    alert_id = Column(
        Integer,
        ForeignKey('wazuh_alerts.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(32), nullable=False)
    note = Column(Text)
    extra = Column(JSONB)  # e.g. {'from': 'NEW', 'to': 'TRIAGED'}

    alert = relationship('WazuhAlert', backref='treatment_notes')
    user = relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else 'system',
            'action': self.action,
            'note': self.note,
            'extra': self.extra or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
