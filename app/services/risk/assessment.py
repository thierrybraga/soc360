"""
SOC360 Risk Assessment Service
Service for managing risk assessments.
"""
from typing import List, Optional

from app.extensions import db
from app.models.monitoring.report import RiskAssessment


class RiskAssessmentService:
    """Service for managing risk assessments."""

    @staticmethod
    def create_assessment(
        user_id: int,
        asset_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
        risk_score: Optional[float] = None,
        recommendation_id: Optional[int] = None,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        scope: Optional[str] = None,
        asset_ids: Optional[List[int]] = None,
        overall_risk_score: Optional[float] = None,
        vulnerability_score: Optional[float] = None,
        exposure_score: Optional[float] = None,
        impact_score: Optional[float] = None,
        risk_breakdown: Optional[dict] = None,
        recommendations: Optional[List[dict]] = None,
        valid_until=None,
    ) -> RiskAssessment:
        """Create a new risk assessment."""
        normalized_asset_ids = list(asset_ids or [])
        if asset_id is not None and asset_id not in normalized_asset_ids:
            normalized_asset_ids.append(asset_id)

        final_score = overall_risk_score if overall_risk_score is not None else risk_score
        breakdown = dict(risk_breakdown or {})
        if vulnerability_id is not None:
            breakdown.setdefault('vulnerability_id', vulnerability_id)
        if recommendation_id is not None:
            breakdown.setdefault('recommendation_id', recommendation_id)

        assessment = RiskAssessment(
            name=name or RiskAssessmentService._default_name(normalized_asset_ids),
            description=description,
            user_id=user_id,
            scope=scope or ('ASSET' if normalized_asset_ids else 'ORGANIZATION'),
            asset_ids=normalized_asset_ids,
            overall_risk_score=final_score,
            vulnerability_score=vulnerability_score,
            exposure_score=exposure_score,
            impact_score=impact_score,
            risk_breakdown=breakdown,
            recommendations=recommendations or [],
            valid_until=valid_until,
        )
        db.session.add(assessment)
        db.session.commit()
        return assessment

    @staticmethod
    def list_assessments_for_asset(asset_id: int) -> List[RiskAssessment]:
        """Return all risk assessments for a specific asset."""
        assessments = RiskAssessment.query.filter(RiskAssessment.asset_ids.isnot(None)).all()
        return [
            assessment for assessment in assessments
            if asset_id in (assessment.asset_ids or [])
        ]

    @staticmethod
    def list_assessments_for_user(user_id: int) -> List[RiskAssessment]:
        """Return all risk assessments created by a specific user."""
        return RiskAssessment.query.filter_by(user_id=user_id).all()

    @staticmethod
    def get_assessment(assessment_id: int) -> RiskAssessment:
        """Get a risk assessment by ID."""
        assessment = db.session.get(RiskAssessment, assessment_id)
        if not assessment:
            raise ValueError(f"Risk assessment {assessment_id} not found.")
        return assessment

    @staticmethod
    def update_assessment(assessment_id: int, **kwargs) -> RiskAssessment:
        """Update fields of a risk assessment."""
        assessment = RiskAssessmentService.get_assessment(assessment_id)
        allowed_fields = {
            'name',
            'description',
            'scope',
            'asset_ids',
            'overall_risk_score',
            'vulnerability_score',
            'exposure_score',
            'impact_score',
            'risk_breakdown',
            'recommendations',
            'status',
            'valid_until',
        }
        for key, value in kwargs.items():
            if key in allowed_fields and hasattr(assessment, key):
                setattr(assessment, key, value)
        db.session.commit()
        return assessment

    @staticmethod
    def delete_assessment(assessment_id: int) -> None:
        """Delete a risk assessment."""
        assessment = RiskAssessmentService.get_assessment(assessment_id)
        db.session.delete(assessment)
        db.session.commit()

    @staticmethod
    def _default_name(asset_ids: List[int]) -> str:
        if len(asset_ids) == 1:
            return f'Risk assessment for asset {asset_ids[0]}'
        if len(asset_ids) > 1:
            return f'Risk assessment for {len(asset_ids)} assets'
        return 'Risk assessment'
