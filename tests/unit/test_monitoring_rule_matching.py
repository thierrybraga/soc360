from types import SimpleNamespace

from app.models.monitoring.monitoring_rule import MonitoringRule


def _vulnerability(**overrides):
    data = {
        'base_severity': 'LOW',
        'cvss_score': 3.1,
        'vendors': ['microsoft'],
        'products': ['windows server'],
        'description': 'Privilege escalation in affected builds.',
        'is_in_cisa_kev': False,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_severity_threshold_without_min_score_rejects_mismatch():
    rule = MonitoringRule(
        name='critical only',
        user_id=1,
        parameters={'severity_threshold': ['CRITICAL']},
    )

    assert rule.matches_vulnerability(_vulnerability(base_severity='LOW')) is False


def test_keyword_filter_rejects_missing_description():
    rule = MonitoringRule(
        name='keyword',
        user_id=1,
        parameters={'keywords': ['remote code execution']},
    )

    assert rule.matches_vulnerability(_vulnerability(description=None)) is False


def test_vendor_and_product_filters_allow_partial_matches():
    rule = MonitoringRule(
        name='asset stack',
        user_id=1,
        parameters={
            'vendor_filter': ['micro'],
            'product_filter': ['server'],
            'keywords': ['privilege'],
        },
    )

    assert rule.matches_vulnerability(_vulnerability()) is True
