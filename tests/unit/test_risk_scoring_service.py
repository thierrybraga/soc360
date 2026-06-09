from app.services.risk import RiskScoringService


class DummyAsset:
    bia_score = 90
    criticality = 'CRITICAL'
    environment = 'DMZ'
    exposure = 'EXTERNAL'


def test_contextual_risk_is_clamped_to_ten():
    score = RiskScoringService.calculate_asset_risk(DummyAsset(), 9.8)

    assert score == 10.0


def test_bia_score_accepts_zero_values():
    score = RiskScoringService.calculate_bia_score(
        rto_hours=0,
        rpo_hours=0,
        operational_cost_per_hour=0,
    )

    assert score == 70


def test_asset_matrix_score_uses_zero_to_ten_scale():
    score = RiskScoringService.calculate_asset_matrix_score(
        criticality='CRITICAL',
        severity_counts={
            'CRITICAL': 10,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
        },
    )

    assert score == 10.0
