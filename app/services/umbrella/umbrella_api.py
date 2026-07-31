"""
Umbrella API Client Module
Handles all API interactions with Cisco Umbrella
"""
import time
from datetime import datetime, timedelta
import random
import importlib


class UmbrellaAPIClient:
    BASE_URL = "https://api.umbrella.com"

    def __init__(self, api_key=None, api_secret=None, use_mock=True):
        self.api_key = api_key
        self.api_secret = api_secret
        self.use_mock = use_mock
        self.token = None
        self.token_expires = None
        self.current_org_id = None

    def authenticate(self):
        if self.use_mock:
            self.token = "mock_token_12345"
            return True
        requests = importlib.import_module('requests')
        from requests.auth import HTTPBasicAuth
        token_url = f"{self.BASE_URL}/auth/v2/token"
        response = requests.post(token_url, auth=HTTPBasicAuth(self.api_key, self.api_secret), data={'grant_type': 'client_credentials'})
        if response.status_code == 200:
            data = response.json()
            self.token = data['access_token']
            self.token_expires = datetime.now() + timedelta(seconds=data.get('expires_in', 3600))
            return True
        return False

    def _get_headers(self):
        headers = {'Authorization': f'Bearer {self.token}'}
        if self.current_org_id:
            headers['X-Umbrella-OrgId'] = str(self.current_org_id)
        return headers

    def set_organization(self, org_id):
        self.current_org_id = org_id

    def get_organizations(self, admin_email=None):
        if self.use_mock:
            return self._mock_organizations()
        requests = importlib.import_module('requests')
        url = f"{self.BASE_URL}/admin/v2/organizations"
        if admin_email:
            url += f"?email={admin_email}"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else []

    def get_networks(self):
        if self.use_mock:
            return self._mock_networks()
        requests = importlib.import_module('requests')
        url = f"{self.BASE_URL}/deployments/v2/networks"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else []

    def get_roaming_computers(self):
        if self.use_mock:
            return self._mock_roaming_computers()
        requests = importlib.import_module('requests')
        url = f"{self.BASE_URL}/deployments/v2/roamingcomputers"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else []

    def get_virtual_appliances(self):
        if self.use_mock:
            return self._mock_virtual_appliances()
        requests = importlib.import_module('requests')
        url = f"{self.BASE_URL}/deployments/v2/virtualappliances"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else []

    def get_activity_summary(self, from_date, to_date):
        if self.use_mock:
            return self._mock_activity_summary(from_date, to_date)
        requests = importlib.import_module('requests')
        from_ts = int(from_date.timestamp())
        to_ts = int(to_date.timestamp())
        url = f"{self.BASE_URL}/reports/v2/activity/dns?from={from_ts}&to={to_ts}"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else {}

    def get_security_categories(self, from_date, to_date):
        if self.use_mock:
            return self._mock_security_categories(from_date, to_date)
        requests = importlib.import_module('requests')
        from_ts = int(from_date.timestamp())
        to_ts = int(to_date.timestamp())
        url = f"{self.BASE_URL}/reports/v2/activity/security?from={from_ts}&to={to_ts}"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else {}

    def get_app_discovery(self, from_date, to_date):
        if self.use_mock:
            return self._mock_app_discovery(from_date, to_date)
        requests = importlib.import_module('requests')
        from_ts = int(from_date.timestamp())
        to_ts = int(to_date.timestamp())
        url = f"{self.BASE_URL}/reports/v2/appdiscovery/applications?from={from_ts}&to={to_ts}"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else {}

    def get_security_requests_by_identity(self, from_date, to_date):
        if self.use_mock:
            return self._mock_security_requests(from_date, to_date)
        requests = importlib.import_module('requests')
        from_ts = int(from_date.timestamp())
        to_ts = int(to_date.timestamp())
        url = f"{self.BASE_URL}/reports/v2/activity/security/identities?from={from_ts}&to={to_ts}"
        response = requests.get(url, headers=self._get_headers())
        return response.json() if response.status_code == 200 else {}

    def collect_all_report_data(self, from_date, to_date):
        return {
            'deployment': {
                'networks': self.get_networks(),
                'roaming_computers': self.get_roaming_computers(),
                'virtual_appliances': self.get_virtual_appliances()
            },
            'activity': self.get_activity_summary(from_date, to_date),
            'security_categories': self.get_security_categories(from_date, to_date),
            'app_discovery': self.get_app_discovery(from_date, to_date),
            'security_requests': self.get_security_requests_by_identity(from_date, to_date)
        }

    def _mock_organizations(self):
        return [
            {"organizationId": 1001, "organizationName": "Empresa ABC Tecnologia", "status": "active"},
            {"organizationId": 1002, "organizationName": "Indústria XYZ Ltda", "status": "active"},
            {"organizationId": 1003, "organizationName": "Banco Financeiro SA", "status": "active"},
            {"organizationId": 1004, "organizationName": "Hospital Central", "status": "active"},
            {"organizationId": 1005, "organizationName": "Varejo Global", "status": "active"},
        ]

    def _mock_networks(self):
        networks_map = {
            1001: [
                {"networkId": 101, "name": "Rede Matriz", "ipAddress": "192.168.1.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 102, "name": "Rede Filial SP", "ipAddress": "10.0.1.0/29", "status": "active", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 103, "name": "Rede Filial RJ", "ipAddress": "10.0.2.0/29", "status": "inactive", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 104, "name": "Rede DR", "ipAddress": "172.16.0.0/24", "status": "inactive", "isDynamic": False, "primaryPolicy": "Default Policy"},
            ],
            1002: [
                {"networkId": 201, "name": "Produção", "ipAddress": "192.168.10.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 202, "name": "Administrativo", "ipAddress": "192.168.20.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
            ],
            1003: [
                {"networkId": 301, "name": "Data Center Principal", "ipAddress": "10.10.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "Strict Policy"},
                {"networkId": 302, "name": "Agências", "ipAddress": "10.20.0.0/16", "status": "active", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 303, "name": "ATMs", "ipAddress": "10.30.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "ATM Policy"},
            ],
            1004: [
                {"networkId": 401, "name": "Rede Administrativa", "ipAddress": "192.168.50.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 402, "name": "Rede Médica", "ipAddress": "192.168.100.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Healthcare Policy"},
            ],
            1005: [
                {"networkId": 501, "name": "Sede", "ipAddress": "10.100.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 502, "name": "Lojas", "ipAddress": "10.200.0.0/16", "status": "active", "isDynamic": True, "primaryPolicy": "Retail Policy"},
                {"networkId": 503, "name": "E-commerce", "ipAddress": "10.150.0.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Web Policy"},
            ],
        }
        return networks_map.get(self.current_org_id, [])

    def _mock_roaming_computers(self):
        roaming_map = {
            1001: [
                {"deviceId": "dev001", "name": "LAPTOP-EXEC-01", "status": "active", "lastSync": "2025-04-10T08:00:00Z", "osVersion": "Windows 11"},
                {"deviceId": "dev002", "name": "LAPTOP-DEV-02", "status": "active", "lastSync": "2025-04-10T09:30:00Z", "osVersion": "Windows 11"},
                {"deviceId": "dev003", "name": "MACBOOK-DESIGN", "status": "inactive", "lastSync": "2025-03-01T10:00:00Z", "osVersion": "macOS 14"},
                {"deviceId": "dev004", "name": "LAPTOP-HR-01", "status": "active", "lastSync": "2025-04-10T07:00:00Z", "osVersion": "Windows 10"},
            ],
            1002: [],
            1003: [
                {"deviceId": "bank001", "name": "NOTEBOOK-GERENTE", "status": "active", "lastSync": "2025-04-11T07:00:00Z", "osVersion": "Windows 11"},
                {"deviceId": "bank002", "name": "NOTEBOOK-DIRETOR", "status": "active", "lastSync": "2025-04-11T08:00:00Z", "osVersion": "Windows 11"},
            ],
            1004: [
                {"deviceId": "hosp001", "name": "LAPTOP-MEDICO-01", "status": "active", "lastSync": "2025-04-10T06:00:00Z", "osVersion": "Windows 10"},
                {"deviceId": "hosp002", "name": "LAPTOP-MEDICO-02", "status": "active", "lastSync": "2025-04-10T07:00:00Z", "osVersion": "Windows 10"},
                {"deviceId": "hosp003", "name": "LAPTOP-ENFERMAGEM", "status": "inactive", "lastSync": "2025-03-15T10:00:00Z", "osVersion": "Windows 10"},
            ],
            1005: [
                {"deviceId": "var001", "name": "TABLET-VENDEDOR", "status": "active", "lastSync": "2025-04-10T08:00:00Z", "osVersion": "Windows 11"},
            ],
        }
        return roaming_map.get(self.current_org_id, [])

    def _mock_virtual_appliances(self):
        va_map = {
            1001: [
                {"vaId": "va-001", "name": "VA-Primary", "status": "active", "ipAddress": "192.168.1.10"},
                {"vaId": "va-002", "name": "VA-Secondary", "status": "inactive", "ipAddress": "192.168.1.11"},
            ],
            1002: [
                {"vaId": "va-ind-01", "name": "VA-Producao", "status": "active", "ipAddress": "192.168.10.10"},
            ],
            1003: [
                {"vaId": "va-bank-01", "name": "VA-DC-Primary", "status": "active", "ipAddress": "10.10.0.10"},
                {"vaId": "va-bank-02", "name": "VA-DC-Secondary", "status": "active", "ipAddress": "10.10.0.11"},
            ],
            1004: [],
            1005: [
                {"vaId": "va-var-01", "name": "VA-Sede", "status": "active", "ipAddress": "10.100.0.10"},
            ],
        }
        return va_map.get(self.current_org_id, [])

    def _mock_activity_summary(self, from_date, to_date):
        base_requests = random.randint(15000000, 30000000)
        base_blocks = int(base_requests * random.uniform(0.05, 0.10))
        security_blocks = int(base_blocks * random.uniform(0.10, 0.20))
        days = (to_date - from_date).days
        daily_data = []
        for i in range(days):
            day = from_date + timedelta(days=i)
            daily_requests = base_requests // days + random.randint(-50000, 50000)
            daily_blocks = base_blocks // days + random.randint(-5000, 5000)
            daily_security = security_blocks // days + random.randint(-1000, 1000)
            daily_data.append({
                "date": day.strftime("%Y-%m-%d"),
                "requests": max(0, daily_requests),
                "blocks": max(0, daily_blocks),
                "securityBlocks": max(0, daily_security)
            })
        return {
            "summary": {
                "totalRequests": base_requests,
                "totalBlocks": base_blocks,
                "securityBlocks": security_blocks,
                "percentChange": {
                    "requests": round(random.uniform(-5, 5), 1),
                    "blocks": round(random.uniform(-15, 15), 1),
                    "securityBlocks": round(random.uniform(-50, 200), 1)
                }
            },
            "dailyData": daily_data
        }

    def _mock_security_categories(self, from_date, to_date):
        malware = random.randint(3000, 8000)
        phishing = random.randint(150000, 250000)
        c2 = random.randint(0, 50)
        cryptomining = random.randint(0, 100)
        days = (to_date - from_date).days

        def generate_daily(total, days):
            daily = []
            remaining = total
            for i in range(days):
                day = from_date + timedelta(days=i)
                if i == days - 1:
                    value = remaining
                else:
                    value = random.randint(0, remaining // (days - i) * 2)
                    remaining -= value
                daily.append({"date": day.strftime("%Y-%m-%d"), "count": max(0, value)})
            return daily

        return {
            "categories": {
                "malware": {
                    "total": malware,
                    "percentChange": round(random.uniform(-50, 50), 1),
                    "dailyData": generate_daily(malware, days)
                },
                "phishing": {
                    "total": phishing,
                    "percentChange": round(random.uniform(-50, 200), 1),
                    "dailyData": generate_daily(phishing, days)
                },
                "command_and_control": {
                    "total": c2,
                    "percentChange": 0,
                    "dailyData": generate_daily(c2, days)
                },
                "cryptomining": {
                    "total": cryptomining,
                    "percentChange": 0,
                    "dailyData": generate_daily(cryptomining, days)
                }
            }
        }

    def _mock_app_discovery(self, from_date, to_date):
        total_apps = random.randint(3000, 5000)
        risky_apps = random.randint(50, 100)
        flagged_apps = [
            {"name": "PDFFiller", "category": "Document Management", "riskScore": 9, "riskLevel": "Very High", "flagged": True},
            {"name": "Discord", "category": "Messaging", "riskScore": 8, "riskLevel": "Very High", "flagged": True},
            {"name": "Voxox Office", "category": "Communication", "riskScore": 7, "riskLevel": "High", "flagged": True},
            {"name": "PhantomPDF", "category": "Document Management", "riskScore": 7, "riskLevel": "High", "flagged": True},
            {"name": "Mega", "category": "Cloud Storage", "riskScore": 6, "riskLevel": "Medium", "flagged": True},
            {"name": "Telegram", "category": "Messaging", "riskScore": 6, "riskLevel": "Medium", "flagged": True},
        ]
        selected_apps = random.sample(flagged_apps, random.randint(3, len(flagged_apps)))
        return {
            "totalApps": total_apps,
            "riskyApps": risky_apps,
            "applications": selected_apps,
            "flaggedCategories": [
                {"name": "Anonymizer", "reviewed": 0, "total": random.randint(5, 15)},
                {"name": "P2P", "reviewed": 0, "total": random.randint(8, 20)},
                {"name": "Games", "reviewed": 0, "total": random.randint(50, 100)},
                {"name": "Cloud Storage", "reviewed": 0, "total": random.randint(60, 120)},
            ]
        }

    def _mock_security_requests(self, from_date, to_date):
        identities = [
            {"name": f"Network_{random.choice(['CLARO', 'VIVO', 'OI', 'TIM'])}_{random.randint(100,999)}MB", "type": "network"},
            {"name": f"Link_{random.choice(['Principal', 'Backup', 'Filial'])}_{random.randint(100,500)}", "type": "network"},
            {"name": f"Link_{random.choice(['Cap', 'Interior', 'Metro'])}", "type": "network"},
            {"name": f"VA_{random.choice(['Primary', 'Secondary', 'DR'])}", "type": "virtual_appliance"},
        ]
        result = []
        total_blocks = random.randint(200000, 300000)
        remaining = total_blocks
        for i, identity in enumerate(identities):
            if i == len(identities) - 1:
                blocks = remaining
            else:
                blocks = random.randint(1, remaining // 2)
                remaining -= blocks
            result.append({
                "name": identity["name"],
                "type": identity["type"],
                "blockedRequests": max(0, blocks)
            })
        result.sort(key=lambda x: x["blockedRequests"], reverse=True)
        return {"identities": result}
