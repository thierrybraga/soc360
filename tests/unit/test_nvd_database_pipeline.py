"""
Database and NVD persistence pipeline checks.
"""
import inspect


def test_d3fend_models_share_public_bind_with_vulnerabilities():
    from app.models.d3fend import (
        CveD3fendCorrelation,
        D3fendArtifact,
        D3fendOffensiveMapping,
        D3fendTactic,
        D3fendTechnique,
    )
    from app.models.nvd import Vulnerability

    models = [
        Vulnerability,
        CveD3fendCorrelation,
        D3fendArtifact,
        D3fendOffensiveMapping,
        D3fendTactic,
        D3fendTechnique,
    ]

    assert {model.__bind_key__ for model in models} == {'public'}


def test_d3fend_correlation_uses_normalized_weakness_table():
    from app.services.d3fend.d3fend_service import D3FENDService

    source = inspect.getsource(D3FENDService.correlate_cves)

    assert 'Vulnerability.cwe_ids' not in source
    assert 'Weakness.cve_id == Vulnerability.cve_id' in source


def test_nvd_bulk_process_persists_normalized_children(db):
    from app.models.nvd import AffectedProduct, Credit, CvssMetric, Reference, Vulnerability, Weakness
    from app.services.nvd.bulk_database_service import BulkDatabaseService

    payload = [
        {
            'cve': {
                'id': 'CVE-2026-0001',
                'descriptions': [{'lang': 'en', 'value': 'Example test vulnerability'}],
                'published': '2026-01-01T00:00:00.000',
                'lastModified': '2026-01-02T00:00:00.000',
                'vulnStatus': 'Analyzed',
                'metrics': {
                    'cvssMetricV31': [
                        {
                            'source': 'nvd@nist.gov',
                            'type': 'Primary',
                            'cvssData': {
                                'version': '3.1',
                                'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                'baseScore': 9.8,
                                'baseSeverity': 'CRITICAL',
                                'attackVector': 'NETWORK',
                                'attackComplexity': 'LOW',
                                'privilegesRequired': 'NONE',
                                'userInteraction': 'NONE',
                                'scope': 'UNCHANGED',
                                'confidentialityImpact': 'HIGH',
                                'integrityImpact': 'HIGH',
                                'availabilityImpact': 'HIGH',
                            },
                        }
                    ]
                },
                'weaknesses': [
                    {
                        'source': 'nvd@nist.gov',
                        'type': 'Primary',
                        'description': [{'lang': 'en', 'value': 'CWE-79'}],
                    }
                ],
                'references': [
                    {
                        'url': 'https://example.com/advisory',
                        'source': 'example',
                        'tags': ['Patch'],
                    }
                ],
                'credits': [
                    {'value': 'Researcher A', 'user': 'ra', 'type': 'finder'},
                    {'value': 'Researcher A', 'user': 'ra', 'type': 'finder'},
                ],
                'configurations': [
                    {
                        'nodes': [
                            {
                                'cpeMatch': [
                                    {
                                        'vulnerable': True,
                                        'criteria': 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
                                    },
                                    {
                                        'vulnerable': False,
                                        'criteria': 'cpe:2.3:a:vendor:runtime:1.0:*:*:*:*:*:*:*',
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        },
        # Duplicate CVE in same batch exercises dedupe/upsert safety.
        {
            'cve': {
                'id': 'CVE-2026-0001',
                'descriptions': [{'lang': 'en', 'value': 'Example test vulnerability updated'}],
                'published': '2026-01-01T00:00:00.000',
                'lastModified': '2026-01-03T00:00:00.000',
                'vulnStatus': 'Modified',
                'metrics': {},
                'weaknesses': [],
                'references': [],
                'credits': [],
                'configurations': [],
            }
        },
    ]

    service = BulkDatabaseService()
    stats = service.process_vulnerabilities(payload)

    vuln = Vulnerability.query.filter_by(cve_id='CVE-2026-0001').one()
    assert vuln.description == 'Example test vulnerability updated'
    assert vuln.vuln_status == 'Modified'
    assert CvssMetric.query.filter_by(cve_id=vuln.cve_id).count() == 1
    assert Weakness.query.filter_by(cve_id=vuln.cve_id).count() == 1
    assert Reference.query.filter_by(cve_id=vuln.cve_id).count() == 1
    assert Credit.query.filter_by(cve_id=vuln.cve_id).count() == 1
    assert AffectedProduct.query.filter_by(cve_id=vuln.cve_id).count() == 1
    assert stats['inserted'] == 1
    assert stats['updated'] == 0
