"""
SOC360 Models
Exportação centralizada de todos os models.
"""
# System Models
from app.models.system import (
    BaseModel,
    CoreModel,
    PublicModel,
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
    SyncMetadata,
    ChatSession,
    ChatMessage,
)

# Auth Models
from app.models.auth import User, Role, UserRole

# MITRE ATT&CK Models
from app.models.mitre import (
    Tactic,
    Technique,
    AttackMitigation
)

# NVD Models
from app.models.nvd import (
    Vulnerability,
    CvssMetric,
    Weakness,
    Reference,
    Mitigation,
    Credit,
    AffectedProduct,
    CVEProduct,
    CVEVendor,
    ReferenceTypeModel,
    VersionReference,
)

# D3FEND Models
from app.models.d3fend import (
    D3fendTechnique,
    D3fendArtifact,
    D3fendTactic,
    D3fendOffensiveMapping,
    CveD3fendCorrelation,
)

# Inventory Models
from app.models.inventory import (
    Asset,
    AssetVulnerability,
    Vendor,
    Product,
    AssetCategory
)

# Monitoring Models
from app.models.monitoring import (
    MonitoringRule,
    Alert,
    Report,
    RiskAssessment,
    ApiCallLog
)

# Wazuh SIEM Models
from app.models.wazuh import (
    WazuhAlert,
    WazuhTreatmentNote,
)

# Cisco Umbrella Models
from app.models.umbrella import (
    UmbrellaOrganization,
    UmbrellaNetwork,
    UmbrellaRoamingComputer,
    UmbrellaVirtualAppliance,
    UmbrellaReportData,
    UmbrellaGeneratedReport,
)


__all__ = [
    # System
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

    # Auth
    'User',
    'Role',
    'UserRole',

    # NVD
    'Vulnerability',
    'CvssMetric',
    'Weakness',
    'Reference',
    'Mitigation',
    'Credit',
    'AffectedProduct',
    'CVEProduct',
    'CVEVendor',
    'ReferenceTypeModel',
    'VersionReference',

    # D3FEND
    'D3fendTechnique',
    'D3fendArtifact',
    'D3fendTactic',
    'D3fendOffensiveMapping',
    'CveD3fendCorrelation',

    # Inventory
    'Asset',
    'AssetVulnerability',
    'Vendor',
    'Product',
    
    # MITRE
    'Tactic',
    'Technique',
    'AttackMitigation',
    
    # Monitoring
    'MonitoringRule',
    'Alert',
    'Report',
    'RiskAssessment',
    'ApiCallLog',

    # Wazuh SIEM
    'WazuhAlert',
    'WazuhTreatmentNote',

    # Cisco Umbrella
    'UmbrellaOrganization',
    'UmbrellaNetwork',
    'UmbrellaRoamingComputer',
    'UmbrellaVirtualAppliance',
    'UmbrellaReportData',
    'UmbrellaGeneratedReport',
]
