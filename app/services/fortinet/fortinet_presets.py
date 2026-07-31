"""
SOC360 Fortinet Presets
Configurações e CPEs pré-definidos para produtos Fortinet.
"""
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class FortinetProductType(str, Enum):
    """Tipos de produtos Fortinet."""
    FIREWALL = 'FIREWALL'
    OS = 'OS'
    MANAGEMENT = 'MANAGEMENT'
    ENDPOINT = 'ENDPOINT'
    NETWORK = 'NETWORK'
    SECURITY = 'SECURITY'
    CLOUD = 'CLOUD'


@dataclass
class FortinetProduct:
    """Definição de produto Fortinet."""
    name: str
    cpe_product: str
    cpe_part: str  # a (application), o (os), h (hardware)
    product_type: FortinetProductType
    description: str
    common_models: List[str] = None

    @property
    def cpe_prefix(self) -> str:
        """Retorna prefixo CPE para este produto."""
        return f"cpe:2.3:{self.cpe_part}:fortinet:{self.cpe_product}"

    def build_cpe(self, version: str = '*', update: str = '*') -> str:
        """Constrói CPE completo com versão."""
        return f"{self.cpe_prefix}:{version}:{update}:*:*:*:*:*:*"


# ============================================================================
# CATÁLOGO DE PRODUTOS FORTINET
# ============================================================================

FORTINET_PRODUCTS: Dict[str, FortinetProduct] = {
    # ========== FIREWALLS E NGFW ==========
    'fortigate': FortinetProduct(
        name='FortiGate',
        cpe_product='fortigate',
        cpe_part='h',
        product_type=FortinetProductType.FIREWALL,
        description='Next-Generation Firewall',
        common_models=[
            'FG-40F', 'FG-60F', 'FG-70F', 'FG-80F', 'FG-90G',
            'FG-100F', 'FG-200F', 'FG-400F', 'FG-600F',
            'FG-900G', 'FG-1000F', 'FG-1800F', 'FG-2600F',
            'FG-3000F', 'FG-3500F', 'FG-3700F', 'FG-4200F', 'FG-4400F',
            'FG-6000F', 'FG-7000F',
            'FG-VM01', 'FG-VM02', 'FG-VM04', 'FG-VM08', 'FG-VM16', 'FG-VM32',
            'FGR-60F', 'FGR-70F',
        ]
    ),

    'fortios': FortinetProduct(
        name='FortiOS',
        cpe_product='fortios',
        cpe_part='o',
        product_type=FortinetProductType.OS,
        description='Fortinet Operating System for FortiGate',
        common_models=[]
    ),

    # ========== GESTÃO CENTRALIZADA ==========
    'fortimanager': FortinetProduct(
        name='FortiManager',
        cpe_product='fortimanager',
        cpe_part='a',
        product_type=FortinetProductType.MANAGEMENT,
        description='Centralized Security Management',
        common_models=['FMG-200G', 'FMG-300G', 'FMG-400G', 'FMG-VM']
    ),

    'fortianalyzer': FortinetProduct(
        name='FortiAnalyzer',
        cpe_product='fortianalyzer',
        cpe_part='a',
        product_type=FortinetProductType.MANAGEMENT,
        description='Centralized Logging and Analytics',
        common_models=['FAZ-200G', 'FAZ-300G', 'FAZ-400G', 'FAZ-VM']
    ),

    'fortiportal': FortinetProduct(
        name='FortiPortal',
        cpe_product='fortiportal',
        cpe_part='a',
        product_type=FortinetProductType.MANAGEMENT,
        description='Advanced Tier Management Portal',
        common_models=[]
    ),

    # ========== ENDPOINT SECURITY ==========
    'forticlient': FortinetProduct(
        name='FortiClient',
        cpe_product='forticlient',
        cpe_part='a',
        product_type=FortinetProductType.ENDPOINT,
        description='Endpoint Protection Agent',
        common_models=[]
    ),

    'forticlient_ems': FortinetProduct(
        name='FortiClient EMS',
        cpe_product='forticlient_enterprise_management_server',
        cpe_part='a',
        product_type=FortinetProductType.MANAGEMENT,
        description='FortiClient Enterprise Management Server',
        common_models=[]
    ),

    'fortiedr': FortinetProduct(
        name='FortiEDR',
        cpe_product='fortiedr',
        cpe_part='a',
        product_type=FortinetProductType.ENDPOINT,
        description='Endpoint Detection and Response',
        common_models=[]
    ),

    # ========== NETWORK INFRASTRUCTURE ==========
    'fortiswitch': FortinetProduct(
        name='FortiSwitch',
        cpe_product='fortiswitch',
        cpe_part='h',
        product_type=FortinetProductType.NETWORK,
        description='Secure Network Switches',
        common_models=[
            'FS-108F', 'FS-124F', 'FS-148F',
            'FS-224F', 'FS-248F', 'FS-424F', 'FS-448F',
            'FS-524D', 'FS-548D',
        ]
    ),

    'fortiswitchos': FortinetProduct(
        name='FortiSwitchOS',
        cpe_product='fortiswitchos',
        cpe_part='o',
        product_type=FortinetProductType.OS,
        description='FortiSwitch Operating System',
        common_models=[]
    ),

    'fortiap': FortinetProduct(
        name='FortiAP',
        cpe_product='fortiap',
        cpe_part='h',
        product_type=FortinetProductType.NETWORK,
        description='Wireless Access Points',
        common_models=[
            'FAP-231F', 'FAP-431F', 'FAP-432F', 'FAP-433F',
            'FAP-U231F', 'FAP-U431F', 'FAP-U432F',
        ]
    ),

    'fortiextender': FortinetProduct(
        name='FortiExtender',
        cpe_product='fortiextender',
        cpe_part='h',
        product_type=FortinetProductType.NETWORK,
        description='LTE/5G WAN Extender',
        common_models=['FEX-100', 'FEX-200F', 'FEX-400F']
    ),

    # ========== WEB/EMAIL/APPLICATION SECURITY ==========
    'fortiweb': FortinetProduct(
        name='FortiWeb',
        cpe_product='fortiweb',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Web Application Firewall',
        common_models=['FWB-100E', 'FWB-400E', 'FWB-1000F', 'FWB-2000F', 'FWB-VM']
    ),

    'fortimail': FortinetProduct(
        name='FortiMail',
        cpe_product='fortimail',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Secure Email Gateway',
        common_models=['FML-200F', 'FML-400F', 'FML-900F', 'FML-2000F', 'FML-VM']
    ),

    'fortiadc': FortinetProduct(
        name='FortiADC',
        cpe_product='fortiadc',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Application Delivery Controller',
        common_models=['FAD-200F', 'FAD-400F', 'FAD-1000F', 'FAD-2000F', 'FAD-VM']
    ),

    'fortiproxy': FortinetProduct(
        name='FortiProxy',
        cpe_product='fortiproxy',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Secure Web Gateway',
        common_models=['FPX-400F', 'FPX-1000F', 'FPX-2000F', 'FPX-VM']
    ),

    # ========== SANDBOX E ANÁLISE ==========
    'fortisandbox': FortinetProduct(
        name='FortiSandbox',
        cpe_product='fortisandbox',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Advanced Threat Protection Sandbox',
        common_models=['FSA-500F', 'FSA-1000F', 'FSA-2000F', 'FSA-3000F', 'FSA-VM']
    ),

    'fortideceptor': FortinetProduct(
        name='FortiDeceptor',
        cpe_product='fortideceptor',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Deception Technology Platform',
        common_models=[]
    ),

    # ========== CLOUD E SASE ==========
    'fortisase': FortinetProduct(
        name='FortiSASE',
        cpe_product='fortisase',
        cpe_part='a',
        product_type=FortinetProductType.CLOUD,
        description='Secure Access Service Edge',
        common_models=[]
    ),

    'forticasb': FortinetProduct(
        name='FortiCASB',
        cpe_product='forticasb',
        cpe_part='a',
        product_type=FortinetProductType.CLOUD,
        description='Cloud Access Security Broker',
        common_models=[]
    ),

    'forticnp': FortinetProduct(
        name='FortiCNP',
        cpe_product='forticnp',
        cpe_part='a',
        product_type=FortinetProductType.CLOUD,
        description='Cloud Native Protection',
        common_models=[]
    ),

    # ========== AUTENTICAÇÃO E ACESSO ==========
    'fortiauthenticator': FortinetProduct(
        name='FortiAuthenticator',
        cpe_product='fortiauthenticator',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='User Identity Management',
        common_models=['FAC-200F', 'FAC-400F', 'FAC-1000F', 'FAC-VM']
    ),

    'fortitoken': FortinetProduct(
        name='FortiToken',
        cpe_product='fortitoken',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Two-Factor Authentication Token',
        common_models=[]
    ),

    'fortipam': FortinetProduct(
        name='FortiPAM',
        cpe_product='fortipam',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Privileged Access Management',
        common_models=[]
    ),

    # ========== SD-WAN E VPN ==========
    'fortiwan': FortinetProduct(
        name='FortiWAN',
        cpe_product='fortiwan',
        cpe_part='a',
        product_type=FortinetProductType.NETWORK,
        description='SD-WAN Appliance (Legacy)',
        common_models=[]
    ),

    # ========== MONITORING E SIEM ==========
    'fortisiem': FortinetProduct(
        name='FortiSIEM',
        cpe_product='fortisiem',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Security Information and Event Management',
        common_models=['FSM-500F', 'FSM-2000F', 'FSM-VM']
    ),

    'fortisoar': FortinetProduct(
        name='FortiSOAR',
        cpe_product='fortisoar',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Security Orchestration and Response',
        common_models=[]
    ),

    # ========== VOICE E VIDEO ==========
    'fortivoice': FortinetProduct(
        name='FortiVoice',
        cpe_product='fortivoice',
        cpe_part='a',
        product_type=FortinetProductType.NETWORK,
        description='Voice over IP System',
        common_models=['FVC-200G', 'FVC-500F']
    ),

    'fortirecorder': FortinetProduct(
        name='FortiRecorder',
        cpe_product='fortirecorder',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Video Surveillance Recorder',
        common_models=[]
    ),

    'forticamera': FortinetProduct(
        name='FortiCamera',
        cpe_product='forticamera',
        cpe_part='h',
        product_type=FortinetProductType.SECURITY,
        description='Security Cameras',
        common_models=[]
    ),

    # ========== OT/IOT ==========
    'fortinac': FortinetProduct(
        name='FortiNAC',
        cpe_product='fortinac',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='Network Access Control',
        common_models=['FNC-CAX', 'FNC-VM']
    ),

    'fortiiot': FortinetProduct(
        name='FortiNAC-F',
        cpe_product='fortinac-f',
        cpe_part='a',
        product_type=FortinetProductType.SECURITY,
        description='IoT/OT Security',
        common_models=[]
    ),
}


# ============================================================================
# VERSÕES FORTIOS CONHECIDAS
# ============================================================================

FORTIOS_VERSIONS = {
    # Branch 7.6 (Latest)
    '7.6': ['7.6.0', '7.6.1'],

    # Branch 7.4 (Stable)
    '7.4': ['7.4.0', '7.4.1', '7.4.2', '7.4.3', '7.4.4', '7.4.5', '7.4.6'],

    # Branch 7.2 (LTS)
    '7.2': ['7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5', '7.2.6', '7.2.7', '7.2.8', '7.2.9', '7.2.10'],

    # Branch 7.0 (LTS)
    '7.0': ['7.0.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8',
            '7.0.9', '7.0.10', '7.0.11', '7.0.12', '7.0.13', '7.0.14', '7.0.15', '7.0.16'],

    # Branch 6.4 (Extended Support)
    '6.4': ['6.4.0', '6.4.1', '6.4.2', '6.4.3', '6.4.4', '6.4.5', '6.4.6', '6.4.7', '6.4.8',
            '6.4.9', '6.4.10', '6.4.11', '6.4.12', '6.4.13', '6.4.14', '6.4.15', '6.4.16'],

    # Branch 6.2 (EOL)
    '6.2': ['6.2.0', '6.2.1', '6.2.2', '6.2.3', '6.2.4', '6.2.5', '6.2.6', '6.2.7', '6.2.8',
            '6.2.9', '6.2.10', '6.2.11', '6.2.12', '6.2.13', '6.2.14', '6.2.15', '6.2.16'],

    # Branch 6.0 (EOL)
    '6.0': ['6.0.0', '6.0.1', '6.0.2', '6.0.3', '6.0.4', '6.0.5', '6.0.6', '6.0.7', '6.0.8',
            '6.0.9', '6.0.10', '6.0.11', '6.0.12', '6.0.13', '6.0.14', '6.0.15', '6.0.16', '6.0.17', '6.0.18'],
}

# Branches atualmente suportadas
SUPPORTED_FORTIOS_BRANCHES = ['7.6', '7.4', '7.2', '7.0', '6.4']

# Branches EOL (End of Life)
EOL_FORTIOS_BRANCHES = ['6.2', '6.0', '5.6', '5.4', '5.2']


# ============================================================================
# CVEs CRÍTICAS CONHECIDAS
# ============================================================================

CRITICAL_FORTINET_CVES = {
    'CVE-2024-21762': {
        'cvss': 9.8,
        'products': ['fortios'],
        'affected_versions': '7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14, 6.2.0-6.2.16',
        'fixed_versions': '7.4.3, 7.2.7, 7.0.14, 6.4.15',
        'cisa_kev': True,
        'description': 'Out-of-bounds write vulnerability in SSL VPN'
    },

    'CVE-2023-27997': {
        'cvss': 9.8,
        'products': ['fortios'],
        'affected_versions': '7.2.0-7.2.4, 7.0.0-7.0.11, 6.4.0-6.4.12, 6.2.0-6.2.13, 6.0.0-6.0.16',
        'fixed_versions': '7.2.5, 7.0.12, 6.4.13, 6.2.14',
        'cisa_kev': True,
        'description': 'Heap-based buffer overflow in SSL-VPN'
    },

    'CVE-2022-42475': {
        'cvss': 9.8,
        'products': ['fortios'],
        'affected_versions': '7.2.0-7.2.2, 7.0.0-7.0.8, 6.4.0-6.4.10, 6.2.0-6.2.11',
        'fixed_versions': '7.2.3, 7.0.9, 6.4.11, 6.2.12',
        'cisa_kev': True,
        'description': 'SSL-VPN pre-authentication heap-based buffer overflow'
    },

    'CVE-2022-40684': {
        'cvss': 9.8,
        'products': ['fortios', 'fortiproxy', 'fortiswitchmanager'],
        'affected_versions': 'FortiOS 7.2.0-7.2.1, 7.0.0-7.0.6; FortiProxy 7.2.0, 7.0.0-7.0.6',
        'fixed_versions': 'FortiOS 7.2.2, 7.0.7; FortiProxy 7.2.1, 7.0.7',
        'cisa_kev': True,
        'description': 'Authentication bypass using alternate path or channel'
    },

    'CVE-2023-36553': {
        'cvss': 9.8,
        'products': ['fortimanager', 'fortianalyzer'],
        'affected_versions': 'FortiManager 7.2.0-7.2.2; FortiAnalyzer 7.2.0-7.2.2',
        'fixed_versions': 'FortiManager 7.2.3; FortiAnalyzer 7.2.3',
        'cisa_kev': False,
        'description': 'SQL Injection vulnerability in FortiManager/FortiAnalyzer'
    },

    'CVE-2024-23113': {
        'cvss': 9.8,
        'products': ['fortios'],
        'affected_versions': '7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13',
        'fixed_versions': '7.4.3, 7.2.7, 7.0.14',
        'cisa_kev': True,
        'description': 'Format string vulnerability in fgfmd daemon'
    },
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_version_supported(version: str) -> bool:
    """Verifica se versão FortiOS está em branch suportada."""
    if not version:
        return False
    branch = '.'.join(version.split('.')[:2])
    return branch in SUPPORTED_FORTIOS_BRANCHES


def is_version_eol(version: str) -> bool:
    """Verifica se versão FortiOS está em EOL."""
    if not version:
        return True
    branch = '.'.join(version.split('.')[:2])
    return branch in EOL_FORTIOS_BRANCHES


def parse_fortios_version(version: str) -> dict:
    """
    Parse versão FortiOS.

    Args:
        version: String como "7.4.3" ou "7.4.3-build0489"

    Returns:
        Dict com major, minor, patch, build
    """
    if not version:
        return None

    # Remove prefixo "v" se houver
    version = version.lstrip('vV')

    # Separa build se presente
    build = None
    if '-build' in version:
        version, build_str = version.split('-build')
        build = int(build_str)

    parts = version.split('.')

    return {
        'major': int(parts[0]) if len(parts) > 0 else 0,
        'minor': int(parts[1]) if len(parts) > 1 else 0,
        'patch': int(parts[2]) if len(parts) > 2 else 0,
        'build': build,
        'branch': f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else None,
        'full': version
    }


def compare_versions(v1: str, v2: str) -> int:
    """
    Compara duas versões FortiOS.

    Returns:
        -1 se v1 < v2
         0 se v1 == v2
         1 se v1 > v2
    """
    p1 = parse_fortios_version(v1)
    p2 = parse_fortios_version(v2)

    if not p1 or not p2:
        return 0

    for key in ['major', 'minor', 'patch']:
        if p1[key] < p2[key]:
            return -1
        if p1[key] > p2[key]:
            return 1

    # Se builds disponíveis, comparar
    if p1['build'] and p2['build']:
        if p1['build'] < p2['build']:
            return -1
        if p1['build'] > p2['build']:
            return 1

    return 0


