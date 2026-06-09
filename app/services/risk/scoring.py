"""
SOC360 Risk Scoring Service
Centraliza formulas de BIA e risco contextual.
"""


class RiskScoringService:
    """Calcula scores de risco sem depender de estado de banco."""

    CRITICALITY_MULTIPLIERS = {
        'LOW': 0.8,
        'MEDIUM': 1.0,
        'HIGH': 1.1,
        'CRITICAL': 1.2,
    }
    ENVIRONMENT_MULTIPLIERS = {
        'PRODUCTION': 1.1,
        'STAGING': 1.0,
        'DEV': 0.9,
        'DMZ': 1.1,
    }
    EXPOSURE_MULTIPLIERS = {
        'INTERNAL': 1.0,
        'CLOUD': 1.1,
        'EXTERNAL': 1.2,
    }
    SEVERITY_WEIGHTS = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 1,
        'UNKNOWN': 0,
    }

    @staticmethod
    def _normalize(value, default):
        if value is None:
            return default
        return str(value).strip().upper() or default

    @staticmethod
    def _to_float(value, default=0.0):
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def calculate_bia_score(cls, rto_hours=None, rpo_hours=None, operational_cost_per_hour=None):
        """
        Calcula score BIA de 0 a 100.

        RTO e RPO baixos aumentam criticidade; custo operacional alto aumenta impacto.
        """
        score = 0
        rto = cls._to_float(rto_hours, None)
        rpo = cls._to_float(rpo_hours, None)
        cost = cls._to_float(operational_cost_per_hour, None)

        if rto is not None:
            if rto <= 1:
                score += 40
            elif rto <= 4:
                score += 30
            elif rto <= 24:
                score += 20
            else:
                score += 10

        if rpo is not None:
            if rpo <= 0.25:
                score += 30
            elif rpo <= 1:
                score += 25
            elif rpo <= 4:
                score += 15
            else:
                score += 5

        if cost is not None:
            if cost >= 10000:
                score += 30
            elif cost >= 1000:
                score += 20
            elif cost >= 100:
                score += 10

        return min(score, 100)

    @classmethod
    def calculate_contextual_risk(
        cls,
        cvss_score,
        bia_score=0,
        criticality='MEDIUM',
        environment='PRODUCTION',
        exposure='INTERNAL',
    ):
        """Calcula risco contextual de 0 a 10 a partir de CVSS, BIA e contexto."""
        cvss = cls._to_float(cvss_score)
        if cvss <= 0:
            return 0.0

        bia = max(0.0, min(cls._to_float(bia_score), 100.0))
        bia_multiplier = 1.0 + (bia / 200)

        criticality_key = cls._normalize(criticality, 'MEDIUM')
        environment_key = cls._normalize(environment, 'PRODUCTION')
        exposure_key = cls._normalize(exposure, 'INTERNAL')

        context_multiplier = (
            cls.CRITICALITY_MULTIPLIERS.get(criticality_key, 1.0)
            * cls.ENVIRONMENT_MULTIPLIERS.get(environment_key, 1.0)
            * cls.EXPOSURE_MULTIPLIERS.get(exposure_key, 1.0)
        )
        return min(round(cvss * bia_multiplier * context_multiplier, 1), 10.0)

    @classmethod
    def calculate_asset_risk(cls, asset, cvss_score):
        """Calcula risco contextual usando atributos de um Asset."""
        return cls.calculate_contextual_risk(
            cvss_score=cvss_score,
            bia_score=getattr(asset, 'bia_score', 0) or 0,
            criticality=getattr(asset, 'criticality', None),
            environment=getattr(asset, 'environment', None),
            exposure=getattr(asset, 'exposure', None),
        )

    @classmethod
    def calculate_asset_matrix_score(cls, criticality, severity_counts):
        """
        Calcula score compacto para matriz de risco por ativo.

        A entrada usa contagens por severidade e retorna uma escala 0-10 para
        ficar consistente com os demais scores de risco da aplicação.
        """
        weighted_sum = sum(
            cls.SEVERITY_WEIGHTS.get(cls._normalize(severity, 'UNKNOWN'), 0) * count
            for severity, count in (severity_counts or {}).items()
        )
        exposure_score = min(weighted_sum / 10, 10)
        criticality_multiplier = cls.CRITICALITY_MULTIPLIERS.get(
            cls._normalize(criticality, 'MEDIUM'),
            1.0,
        )
        return min(round(exposure_score * criticality_multiplier, 1), 10.0)

    @staticmethod
    def risk_level(score):
        """Retorna o nivel textual para um score 0-10."""
        value = RiskScoringService._to_float(score)
        if value >= 9:
            return 'CRITICAL'
        if value >= 7:
            return 'HIGH'
        if value >= 4:
            return 'MEDIUM'
        if value > 0:
            return 'LOW'
        return 'UNKNOWN'
