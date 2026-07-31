"""
SOC360 System Models
Models de sistema e infraestrutura.
"""
from app.models.system.base_model import BaseModel, CoreModel, PublicModel
from app.models.system.enums import (
    Severity,
    AssetType,
    AssetStatus,
    VulnerabilityStatus,
    ReportType,
    ReportStatus,
    MonitoringRuleType,
    AlertChannel,
    AlertStatus,
    SyncStatus,
    RoleType,
    CvssVersion,
    ReferenceType,
)
from app.models.system.sync_metadata import SyncMetadata
from app.models.system.chat import ChatSession, ChatMessage


__all__ = [
    'BaseModel',
    'CoreModel',
    'PublicModel',
    'Severity',
    'AssetType',
    'AssetStatus',
    'VulnerabilityStatus',
    'ReportType',
    'ReportStatus',
    'MonitoringRuleType',
    'AlertChannel',
    'AlertStatus',
    'SyncStatus',
    'RoleType',
    'CvssVersion',
    'ReferenceType',
    'SyncMetadata',
    'ChatSession',
    'ChatMessage',
]
