import re
from datetime import datetime
from typing import Dict, List, Set

from app.extensions import db
from app.models.inventory import Asset, AssetVulnerability, Vendor, Product
from app.models.nvd import Vulnerability, Weakness
from app.models.system import VulnerabilityStatus


class AssetCorrelationService:
    def __init__(self):
        self.vendor_profiles = {
            'fortinet': {
                'label': 'Fortinet',
                'vendor_name': 'Fortinet',
                'vendor_aliases': ['fortinet', 'fortigate', 'forti'],
                'product_aliases': {
                    'fortigate': ['fortigate', 'fg'],
                    'fortios': ['fortios', 'forti os', 'fortigate os'],
                    'fortimanager': ['fortimanager', 'fmg'],
                    'fortianalyzer': ['fortianalyzer', 'faz'],
                    'forticlient': ['forticlient'],
                    'fortiswitch': ['fortiswitch', 'fsw'],
                    'fortiap': ['fortiap', 'fap'],
                    'fortimail': ['fortimail', 'fml'],
                    'fortiweb': ['fortiweb', 'fwb'],
                    'fortisandbox': ['fortisandbox', 'fsb']
                }
            },
            'cisco_meraki': {
                'label': 'Cisco (Meraki)',
                'vendor_name': 'Cisco',
                'vendor_aliases': ['cisco', 'meraki', 'cisco_meraki'],
                'product_aliases': {
                    'meraki_mx': ['mx', 'meraki mx', 'mx appliance'],
                    'meraki_mr': ['mr', 'meraki mr', 'mr access point'],
                    'meraki_ms': ['ms', 'meraki ms', 'ms switch'],
                    'meraki_mv': ['mv', 'meraki mv', 'mv camera'],
                    'meraki_dashboard': ['dashboard', 'meraki dashboard'],
                    'meraki_firmware': ['meraki firmware', 'meraki os']
                }
            },
            'sophos': {
                'label': 'Sophos',
                'vendor_name': 'Sophos',
                'vendor_aliases': ['sophos'],
                'product_aliases': {
                    'xg_firewall': ['xg', 'sfos', 'xg firewall'],
                    'sophos_central': ['central', 'sophos central'],
                    'intercept_x': ['intercept x', 'endpoint', 'hitmanpro'],
                    'sophos_os': ['sophos os', 'sfos']
                }
            },
            'wazuh': {
                'label': 'Wazuh',
                'vendor_name': 'Wazuh',
                'vendor_aliases': ['wazuh'],
                'product_aliases': {
                    'wazuh_manager': ['manager', 'wazuh manager'],
                    'wazuh_agent': ['agent', 'wazuh agent'],
                    'wazuh_dashboard': ['dashboard', 'wazuh dashboard']
                }
            },
            'umbrella': {
                'label': 'Cisco Umbrella',
                'vendor_name': 'Cisco',
                'vendor_aliases': ['cisco', 'umbrella', 'opendns'],
                'product_aliases': {
                    'umbrella_roaming_client': ['roaming client', 'umbrella client'],
                    'umbrella_va': ['virtual appliance', 'va'],
                    'umbrella_dashboard': ['umbrella dashboard']
                }
            },
            'zabbix': {
                'label': 'Zabbix',
                'vendor_name': 'Zabbix',
                'vendor_aliases': ['zabbix'],
                'product_aliases': {
                    'zabbix_server': ['server', 'zabbix server'],
                    'zabbix_agent': ['agent', 'zabbix agent'],
                    'zabbix_proxy': ['proxy', 'zabbix proxy']
                }
            },
            # ── Enterprise firewall / NGFW vendors ──────────────────────────
            # product_aliases keys MUST equal the normalized NVD CPE product
            # name; vendor_aliases MUST include the exact NVD CPE vendor token.
            'palo_alto': {
                'label': 'Palo Alto Networks',
                'vendor_name': 'Palo Alto Networks',
                'vendor_aliases': ['paloaltonetworks', 'palo alto networks', 'palo_alto', 'palo alto'],
                'product_aliases': {
                    'pan_os': ['pan-os', 'panos', 'pan os', 'pa-', 'pa series'],
                    'globalprotect': ['globalprotect', 'global protect'],
                    'prisma_access': ['prisma access', 'prisma'],
                    'expedition': ['expedition'],
                }
            },
            'cisco_secure': {
                'label': 'Cisco (Firewall/Router)',
                'vendor_name': 'Cisco',
                'vendor_aliases': ['cisco'],
                # Order matters: specific keys before generic 'ios' so model
                # inference (substring match) doesn't misclassify ios-xe as ios.
                'product_aliases': {
                    'ios_xe': ['ios xe', 'ios-xe', 'iosxe'],
                    'ios_xr': ['ios xr', 'ios-xr', 'iosxr'],
                    'nx_os': ['nx-os', 'nxos', 'nexus'],
                    'adaptive_security_appliance': ['asa', 'adaptive security appliance'],
                    'firepower_threat_defense': ['ftd', 'firepower threat defense', 'firepower'],
                    'ios': ['cisco ios', ' ios'],
                }
            },
            'check_point': {
                'label': 'Check Point',
                'vendor_name': 'Check Point',
                'vendor_aliases': ['checkpoint', 'check point', 'check_point'],
                'product_aliases': {
                    'gaia_os': ['gaia os', 'gaia-os'],
                    'gaia': ['gaia'],
                    'quantum_security_gateway': ['quantum', 'quantum security gateway', 'security gateway'],
                }
            },
            'juniper': {
                'label': 'Juniper Networks',
                'vendor_name': 'Juniper',
                'vendor_aliases': ['juniper'],
                'product_aliases': {
                    'junos_os_evolved': ['junos evolved', 'junos os evolved', 'evolved'],
                    'junos': ['junos', 'junos os', 'srx', 'qfx', ' ex', ' mx'],
                }
            },
            'sonicwall': {
                'label': 'SonicWall',
                'vendor_name': 'SonicWall',
                'vendor_aliases': ['sonicwall'],
                'product_aliases': {
                    'sonicos': ['sonicos', 'sonic os', 'tz', 'nsa', 'nsv', 'soho'],
                    'global_management_system': ['gms', 'global management system'],
                }
            },
            'watchguard': {
                'label': 'WatchGuard',
                'vendor_name': 'WatchGuard',
                'vendor_aliases': ['watchguard'],
                'product_aliases': {
                    'fireware': ['fireware', 'fireware os', 'firebox'],
                }
            },
            'barracuda': {
                'label': 'Barracuda Networks',
                'vendor_name': 'Barracuda',
                'vendor_aliases': ['barracuda'],
                'product_aliases': {
                    'cloudgen_firewall': ['cloudgen firewall', 'cloudgen', 'cgf'],
                    'cloudgen_wan': ['cloudgen wan'],
                    'web_application_firewall': ['web application firewall', 'waf'],
                }
            },
            'forcepoint': {
                'label': 'Forcepoint',
                'vendor_name': 'Forcepoint',
                'vendor_aliases': ['forcepoint'],
                'product_aliases': {
                    'next_generation_firewall': ['ngfw', 'next generation firewall'],
                    'ngfw_security_management_center': ['smc', 'security management center'],
                }
            },
            'pfsense': {
                'label': 'pfSense / Netgate',
                'vendor_name': 'Netgate',
                'vendor_aliases': ['netgate', 'pfsense', 'rubicon_communications', 'rubicon communications'],
                'product_aliases': {
                    'pfsense_plus': ['pfsense plus', 'plus'],
                    'pfsense': ['pfsense', 'pf sense'],
                }
            },
            # ── Router / switching / SD-WAN vendors ─────────────────────────
            'mikrotik': {
                'label': 'MikroTik',
                'vendor_name': 'MikroTik',
                'vendor_aliases': ['mikrotik'],
                'product_aliases': {
                    'routeros': ['routeros', 'router os', 'ccr', 'crs', 'hap', 'rb'],
                }
            },
            'ubiquiti': {
                'label': 'Ubiquiti',
                'vendor_name': 'Ubiquiti',
                'vendor_aliases': ['ui', 'ubiquiti', 'ubnt'],
                'product_aliases': {
                    'edgeos': ['edgeos', 'edge os', 'edgerouter', 'er-'],
                    'unifi': ['unifi', 'udm', 'usg', 'dream machine'],
                    'airos': ['airos', 'air os'],
                    'unifi_os': ['unifi os'],
                }
            },
            'arista': {
                'label': 'Arista Networks',
                'vendor_name': 'Arista',
                'vendor_aliases': ['arista'],
                'product_aliases': {
                    'eos': ['eos', 'arista eos'],
                    'cloudvision': ['cloudvision', 'cvp'],
                }
            },
            'aruba': {
                'label': 'Aruba (HPE)',
                'vendor_name': 'Aruba Networks',
                'vendor_aliases': ['arubanetworks', 'aruba', 'hpe', 'hewlett packard enterprise'],
                'product_aliases': {
                    'arubaos_cx': ['arubaos-cx', 'arubaos cx', 'aoscx'],
                    'instant': ['instant', 'iap'],
                    'clearpass_policy_manager': ['clearpass', 'cppm'],
                    'arubaos': ['arubaos', 'aruba os'],
                }
            },
            'huawei': {
                'label': 'Huawei',
                'vendor_name': 'Huawei',
                'vendor_aliases': ['huawei'],
                'product_aliases': {
                    'vrp': ['vrp', 'versatile routing platform'],
                    'usg': ['usg', 'usg6000'],
                }
            },
            # ── Consumer / SOHO router & firewall brands ────────────────────
            # NVD names their hardware OS as "<model>_firmware"; the model field
            # plus the _firmware variant added in _extract_candidates enables
            # exact correlation per device model.
            'zyxel': {
                'label': 'Zyxel',
                'vendor_name': 'Zyxel',
                'vendor_aliases': ['zyxel'],
                'product_aliases': {
                    'zld': ['zld', 'zld firmware'],
                    'usg_flex': ['usg flex', 'usgflex'],
                    'atp': ['atp'],
                }
            },
            'netgear': {
                'label': 'Netgear',
                'vendor_name': 'Netgear',
                'vendor_aliases': ['netgear'],
                'product_aliases': {
                    'nighthawk': ['nighthawk', 'rax', 'r7000', 'r8000'],
                    'prosafe': ['prosafe', 'fvs'],
                }
            },
            'tp_link': {
                'label': 'TP-Link',
                'vendor_name': 'TP-Link',
                'vendor_aliases': ['tp-link', 'tp_link', 'tplink'],
                'product_aliases': {
                    'archer': ['archer', 'ax', 'c'],
                    'omada': ['omada', 'er', 'tl'],
                }
            },
            'dlink': {
                'label': 'D-Link',
                'vendor_name': 'D-Link',
                'vendor_aliases': ['d-link', 'dlink', 'd_link'],
                'product_aliases': {
                    'dir': ['dir-', 'dir'],
                    'dsr': ['dsr-', 'dsr'],
                }
            },
            'asus': {
                'label': 'ASUS',
                'vendor_name': 'ASUS',
                'vendor_aliases': ['asus', 'asustek'],
                'product_aliases': {
                    'asuswrt': ['asuswrt', 'merlin'],
                    'rt': ['rt-', 'rt_'],
                }
            }
        }

    def normalize(self, value: str) -> str:
        if not value:
            return ''
        normalized = re.sub(r'[^a-z0-9]+', '_', value.strip().lower())
        return normalized.strip('_')

    def parse_version(self, value: str) -> List[int]:
        if not value:
            return []
        numbers = re.findall(r'\d+', value)
        return [int(n) for n in numbers[:6]]

    def compare_versions(self, left: str, right: str) -> int:
        left_parts = self.parse_version(left)
        right_parts = self.parse_version(right)
        max_len = max(len(left_parts), len(right_parts))
        left_parts.extend([0] * (max_len - len(left_parts)))
        right_parts.extend([0] * (max_len - len(right_parts)))
        for idx in range(max_len):
            if left_parts[idx] > right_parts[idx]:
                return 1
            if left_parts[idx] < right_parts[idx]:
                return -1
        return 0

    def get_vendor_profile_payload(self) -> Dict:
        return {
            'profiles': [
                {
                    'key': key,
                    'label': profile['label'],
                    'vendor_name': profile['vendor_name'],
                    'products': [
                        {
                            'key': product_key,
                            'label': product_key.replace('_', ' ').title()
                        }
                        for product_key in profile['product_aliases'].keys()
                    ]
                }
                for key, profile in self.vendor_profiles.items()
            ]
        }

    def resolve_vendor_and_product(self, payload: Dict) -> Dict:
        profile_key = payload.get('vendor_profile')
        model = payload.get('model')
        vendor_name = payload.get('vendor_name')
        product_name = payload.get('product_name')
        if profile_key in self.vendor_profiles:
            profile = self.vendor_profiles[profile_key]
            vendor_name = profile['vendor_name']
            if not product_name:
                product_name = self.infer_product_from_model(model=model, profile_key=profile_key)
        return {
            'vendor_profile': profile_key,
            'vendor_name': vendor_name,
            'product_name': product_name,
            'model': model
        }

    def infer_product_from_model(self, model: str, profile_key: str) -> str:
        if not model or profile_key not in self.vendor_profiles:
            return ''
        value = self.normalize(model)
        aliases = self.vendor_profiles[profile_key]['product_aliases']
        for product_key, tokens in aliases.items():
            for token in tokens:
                token_norm = self.normalize(token)
                if token_norm and token_norm in value:
                    return product_key
        return ''

    def ensure_vendor_product(self, vendor_name: str, product_name: str) -> Dict:
        vendor = None
        product = None
        if vendor_name:
            vendor = Vendor.get_by_name(vendor_name)
            if not vendor:
                vendor = Vendor(name=vendor_name)
                db.session.add(vendor)
                db.session.flush()
        if product_name and vendor:
            product = Product.get_by_name(product_name, vendor_id=vendor.id)
            if not product:
                product = Product(name=product_name, vendor_id=vendor.id)
                db.session.add(product)
                db.session.flush()
        return {'vendor': vendor, 'product': product}

    def _extract_candidates(self, asset: Asset) -> Dict:
        vendors: Set[str] = set()
        products: Set[str] = set()
        versions: Set[str] = set()
        os_tokens: Set[str] = set()
        if asset.vendor:
            vendors.add(self.normalize(asset.vendor.name))
            if asset.vendor.normalized_name:
                vendors.add(self.normalize(asset.vendor.normalized_name))
        if asset.product:
            products.add(self.normalize(asset.product.name))
            if asset.product.normalized_name:
                products.add(self.normalize(asset.product.normalized_name))
        if asset.version:
            versions.add(asset.version)
        if asset.os_family:
            os_tokens.add(self.normalize(asset.os_family))
        if asset.os_name:
            os_tokens.add(self.normalize(asset.os_name))
            products.add(self.normalize(asset.os_name))
        if asset.os_version:
            versions.add(asset.os_version)
        custom_fields = asset.custom_fields or {}
        model = custom_fields.get('model')
        if model:
            model_norm = self.normalize(model)
            if model_norm:
                products.add(model_norm)
                # NVD names consumer/SOHO router & firewall hardware OS as
                # "<model>_firmware" (e.g. rt-ax88u_firmware, r7000_firmware).
                # Adding the variant lets exact matching hit per-model CPEs.
                products.add(f'{model_norm}_firmware')
        for sw in asset.installed_software or []:
            if not isinstance(sw, dict):
                continue
            if sw.get('vendor'):
                vendors.add(self.normalize(sw.get('vendor')))
            if sw.get('product'):
                products.add(self.normalize(sw.get('product')))
            if sw.get('version'):
                versions.add(sw.get('version'))
        profile = custom_fields.get('vendor_profile')
        if profile in self.vendor_profiles:
            profile_data = self.vendor_profiles[profile]
            vendors.update(self.normalize(alias) for alias in profile_data['vendor_aliases'])
            inferred = self.infer_product_from_model(model=model, profile_key=profile)
            if inferred:
                products.add(self.normalize(inferred))
        if any('forti' in p for p in products):
            products.add('fortios')
            products.add('fortigate')
            vendors.add('fortinet')
        if any(p.startswith('meraki') or p in {'mx', 'mr', 'ms', 'mv'} for p in products):
            vendors.add('cisco')
            vendors.add('meraki')
            products.add('meraki_firmware')
        if any('sophos' in p for p in products) or any('sfos' in p for p in products):
            vendors.add('sophos')
            products.add('sfos')
        if any('wazuh' in p for p in products):
            vendors.add('wazuh')
        if any('umbrella' in p for p in products):
            vendors.add('cisco')
            vendors.add('umbrella')
        if any('zabbix' in p for p in products):
            vendors.add('zabbix')
        return {
            'vendors': {v for v in vendors if v},
            'products': {p for p in products if p},
            'versions': {v for v in versions if v},
            'os_tokens': {o for o in os_tokens if o}
        }

    @staticmethod
    def _escape_like(value: str) -> str:
        """Escape LIKE wildcards.

        ``normalize()`` joins words with ``_``, which is a single-char
        wildcard in SQL LIKE/ILIKE. Without escaping, ``cisco_meraki`` would
        also match ``ciscoXmeraki``. Escapes ``\\``, ``%`` and ``_``.
        """
        return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

    def _norm_set(self, items) -> Set[str]:
        """Normalize an iterable of CVE vendor/product entries into a token set.

        Skips non-string elements (NVD data is occasionally a list of dicts)
        so a malformed row can never raise — it simply yields no token.
        """
        out: Set[str] = set()
        for item in items or []:
            if isinstance(item, str):
                token = self.normalize(item)
                if token:
                    out.add(token)
        return out

    def _vendor_match(self, vulnerability: Vulnerability, vendors: Set[str]) -> bool:
        """Precise vendor confirmation via structured set intersection.

        The DB pre-filter already did the broad "mentions this token" pass;
        this is the exact post-filter. A substring/word-token fallback is
        deliberately NOT used — it cannot distinguish e.g. asset ``linux``
        from CVE product ``linux_kernel`` and produces mass false positives.
        """
        if not vendors:
            return False
        return bool(self._norm_set(vulnerability.vendors) & vendors)

    def _product_match(self, vulnerability: Vulnerability, products: Set[str], os_tokens: Set[str]) -> bool:
        """Precise product confirmation via structured set intersection.

        ``Vulnerability.products`` already flattens both list- and dict-shaped
        NVD data, so exact intersection is comprehensive for well-formed rows.
        """
        candidates = set(products) | set(os_tokens)
        if not candidates:
            return False
        return bool(self._norm_set(vulnerability.products) & candidates)

    def _version_match(self, vulnerability: Vulnerability, versions: Set[str],
                       product_candidates: Set[str]) -> str:
        """Return ``'verified'`` | ``'unverified'`` | ``'none'``.

        - ``verified``   — asset version confirmed inside a CPE range/value
                           that belongs to the asset's product.
        - ``unverified`` — could not confirm (no asset version, no CPE data,
                           or CVE has no CPE entry for this product) but the
                           asset is not contradicted either.
        - ``none``       — the asset's product IS covered by CPE entries, but
                           the asset version falls outside every range → real
                           non-match.
        """
        if not versions:
            # No asset version to compare — accept but flag as unverified.
            return 'unverified'

        configs = vulnerability.cpe_configurations
        if not configs:
            # No structured CPE data: weak description fallback, never rejects.
            return 'unverified'

        if not isinstance(configs, list):
            configs = [configs]

        saw_applicable_match = False
        for config in configs:
            if not isinstance(config, dict):
                continue
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if not match.get('vulnerable'):
                        continue
                    parts = (match.get('criteria') or '').split(':')
                    cpe_product = self.normalize(parts[4]) if len(parts) > 4 else ''
                    # Only evaluate ranges belonging to the asset's product —
                    # a version hit on an unrelated product in the same CVE is
                    # a false positive (C3).
                    if product_candidates and cpe_product and cpe_product not in product_candidates:
                        continue
                    saw_applicable_match = True

                    start_incl = match.get('versionStartIncluding')
                    start_excl = match.get('versionStartExcluding')
                    end_incl = match.get('versionEndIncluding')
                    end_excl = match.get('versionEndExcluding')
                    cpe_version = parts[5] if len(parts) > 5 else ''

                    for version in versions:
                        if any([start_incl, start_excl, end_incl, end_excl]):
                            valid = True
                            if start_incl:
                                valid = valid and self.compare_versions(version, start_incl) >= 0
                            if start_excl:
                                valid = valid and self.compare_versions(version, start_excl) > 0
                            if end_incl:
                                valid = valid and self.compare_versions(version, end_incl) <= 0
                            if end_excl:
                                valid = valid and self.compare_versions(version, end_excl) < 0
                            if valid:
                                return 'verified'
                        elif cpe_version and cpe_version not in ('*', '-'):
                            if self.compare_versions(version, cpe_version) == 0:
                                return 'verified'
                        else:
                            # Wildcard / all-versions vulnerable for this product.
                            return 'verified'

        # CPE entries for the asset's product existed but the asset version
        # was outside every range → genuine non-match. If no applicable entry
        # was found, we cannot verify (don't reject).
        return 'none' if saw_applicable_match else 'unverified'

    def correlate_asset(self, asset: Asset, auto_associate: bool = True) -> Dict:
        candidates = self._extract_candidates(asset)
        if not candidates['vendors'] and not candidates['products']:
            return {'matches': [], 'new_associations': 0, 'existing_associations': 0}

        # Build separate vendor and product filter groups.
        # Use AND when both sets are non-empty so the DB pre-filters more tightly,
        # drastically reducing the candidate set compared to a flat OR.
        vendor_filters = [
            db.cast(Vulnerability.nvd_vendors_data, db.Text).ilike(
                f'%{self._escape_like(vendor)}%', escape='\\'
            )
            for vendor in candidates['vendors']
        ]
        product_filters = [
            db.cast(Vulnerability.nvd_products_data, db.Text).ilike(
                f'%{self._escape_like(product)}%', escape='\\'
            )
            for product in candidates['products']
        ]
        query = Vulnerability.query
        if vendor_filters and product_filters:
            query = query.filter(
                db.or_(*vendor_filters),
                db.or_(*product_filters),
            )
        elif vendor_filters:
            query = query.filter(db.or_(*vendor_filters))
        elif product_filters:
            query = query.filter(db.or_(*product_filters))

        # With the tighter AND pre-filter the result set is small enough to
        # remove the arbitrary 1500 cap that silently dropped low-CVSS matches.
        potential = query.order_by(Vulnerability.cvss_score.desc().nulls_last()).all()

        # Product token set used to correlate CPE version ranges to the asset's
        # actual product (covers both products and OS-derived tokens).
        version_product_scope = candidates['products'] | candidates['os_tokens']

        matches = []
        for vuln in potential:
            if not self._vendor_match(vuln, candidates['vendors']):
                continue
            if not self._product_match(vuln, candidates['products'], candidates['os_tokens']):
                continue
            version_state = self._version_match(vuln, candidates['versions'], version_product_scope)
            if version_state == 'none':
                continue

            # Vendor and product are always exact-confirmed at this point, so
            # confidence hinges on whether the asset version was actually
            # verified against a CPE range for that product. Unverifiable
            # version (no asset version / no applicable CPE entry) => MEDIUM.
            confidence = 'HIGH' if version_state == 'verified' else 'MEDIUM'

            matches.append({
                'cve_id': vuln.cve_id,
                'cvss_score': vuln.cvss_score,
                'severity': vuln.base_severity,
                'is_cisa_kev': vuln.is_in_cisa_kev,
                'confidence': confidence
            })

        cve_ids = [m['cve_id'] for m in matches]

        weakness_map = {}
        if cve_ids:
            weaknesses = Weakness.query.filter(Weakness.cve_id.in_(cve_ids)).all()
            for weakness in weaknesses:
                weakness_map.setdefault(weakness.cve_id, []).append(weakness.cwe_id)

        new_associations = 0
        existing_associations = 0
        if auto_associate and cve_ids:
            # Single query to fetch all already-associated CVE IDs for this asset
            # — avoids an individual SELECT per match (was up to N queries).
            existing_cve_ids: Set[str] = {
                row.cve_id
                for row in db.session.query(AssetVulnerability.cve_id)
                .filter_by(asset_id=asset.id)
                .filter(AssetVulnerability.cve_id.in_(cve_ids))
                .all()
            }
            for match in matches:
                if match['cve_id'] in existing_cve_ids:
                    existing_associations += 1
                    continue
                association = AssetVulnerability(
                    asset_id=asset.id,
                    cve_id=match['cve_id'],
                    status=VulnerabilityStatus.OPEN.value,
                    discovered_at=datetime.utcnow(),
                    detection_method='asset_correlation',
                    detected_by='AssetCorrelationService',
                    notes=f"Confidence={match['confidence']}"
                )
                association.contextual_risk_score = asset.calculate_risk_score(match['cvss_score'] or 0)
                db.session.add(association)
                new_associations += 1

        for match in matches:
            match['cwes'] = weakness_map.get(match['cve_id'], [])
        return {
            'matches': matches,
            'new_associations': new_associations,
            'existing_associations': existing_associations
        }


_service_instance = None


def get_asset_correlation_service() -> AssetCorrelationService:
    global _service_instance
    if _service_instance is None:
        _service_instance = AssetCorrelationService()
    return _service_instance
