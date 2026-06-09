"""
SOC360 API Controller
Endpoints REST: /api/v1/cves, /api/v1/assets, /api/v1/analytics, /api/v1/sync
"""
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from sqlalchemy import func, desc, or_

from app.extensions import db
from app.models.nvd import Vulnerability, CvssMetric, Weakness
from app.models.inventory import Asset, AssetVulnerability, Vendor, Product
from app.models.monitoring import MonitoringRule, Report
from app.models.system import SyncMetadata, Severity
from app.utils.security import rate_limit, admin_required, api_key_required


api_bp = Blueprint('api', __name__)


# =============================================================================
# CSRF TOKEN REFRESH
# =============================================================================

@api_bp.route('/csrf-token', methods=['GET'])
def csrf_token_refresh():
    """Retorna um CSRF token fresco (atrelado à sessão atual).

    Endpoint utilizado pelo cliente JS quando um POST falha com ``CSRF_ERROR``
    — evita que o usuário tenha que recarregar a página inteira só porque
    a sessão renovou ou o token antigo ficou defasado. O GET não muta estado,
    então é exempt de CSRF pelo Flask-WTF (aplicável só a POST/PUT/PATCH/DELETE).
    """
    from flask_wtf.csrf import generate_csrf
    return jsonify({'csrf_token': generate_csrf()})


# =============================================================================
# VULNERABILITIES (CVEs)
# =============================================================================

@api_bp.route('/cves', methods=['GET'])
@login_required
@rate_limit(max_requests=100, window_seconds=60)
def list_cves():
    """
    Listar vulnerabilidades com paginação e filtros.
    
    Query params:
        page: Página (default 1)
        per_page: Items por página (default 50, max 100)
        severity: Filtrar por severidade (CRITICAL, HIGH, MEDIUM, LOW)
        vendor: Filtrar por vendor (busca em nvd_vendors_data JSON)
        product: Filtrar por produto
        date_from: Data inicial (YYYY-MM-DD)
        date_to: Data final (YYYY-MM-DD)
        search: Busca em cve_id e description
        sort: Campo de ordenação (published_date, cvss_score)
        order: asc ou desc
    """
    # Paginação
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    # Query base
    query = Vulnerability.query
    
    # Filtro por severidade
    severity = request.args.get('severity')
    if severity:
        try:
            sev_enum = Severity[severity.upper()]
            query = query.filter(Vulnerability.base_severity == sev_enum)
        except KeyError:
            pass
    
    # Filtro por vendor (JSON array de strings)
    vendor = request.args.get('vendor')
    if vendor:
        query = query.filter(
            db.cast(Vulnerability.nvd_vendors_data, db.Text).ilike(f'%{vendor}%')
        )
    
    # Filtro por data
    date_from = request.args.get('date_from')
    if date_from:
        try:
            dt = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Vulnerability.published_date >= dt)
        except ValueError:
            pass
    
    date_to = request.args.get('date_to')
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(Vulnerability.published_date <= dt)
        except ValueError:
            pass
    
    # Busca textual
    search = request.args.get('search')
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            or_(
                Vulnerability.cve_id.ilike(search_term),
                Vulnerability.description.ilike(search_term)
            )
        )
    
    # Filtro CISA KEV
    kev_only = request.args.get('kev_only', 'false').lower() == 'true'
    if kev_only:
        query = query.filter(Vulnerability.is_in_cisa_kev == True)
    
    # Ordenação
    sort_field = request.args.get('sort', 'published_date')
    order = request.args.get('order', 'desc')
    
    if sort_field == 'cvss_score':
        sort_col = Vulnerability.cvss_score
    else:
        sort_col = Vulnerability.published_date
    
    if order == 'asc':
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())
    
    # Paginação
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'items': [vuln.to_dict() for vuln in pagination.items],
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    })


@api_bp.route('/cves/<cve_id>', methods=['GET'])
@login_required
def get_cve(cve_id):
    """Obter detalhes de uma vulnerabilidade específica."""
    vuln = Vulnerability.query.filter_by(cve_id=cve_id.upper()).first()
    
    if not vuln:
        return jsonify({'error': 'Not Found', 'message': f'CVE {cve_id} not found'}), 404
    
    # Dados completos
    result = vuln.to_dict()
    
    # Métricas CVSS
    metrics = CvssMetric.query.filter_by(cve_id=vuln.cve_id).all()
    result['cvss_metrics'] = [m.to_dict() for m in metrics]
    
    # Weaknesses (CWEs)
    weaknesses = Weakness.query.filter_by(cve_id=vuln.cve_id).all()
    result['weaknesses'] = [w.to_dict() for w in weaknesses]
    
    # Assets afetados (do usuário atual)
    affected_assets = AssetVulnerability.query.join(Asset).filter(
        AssetVulnerability.cve_id == vuln.cve_id,
        Asset.owner_id == current_user.id
    ).all()
    result['affected_assets'] = [
        {
            'asset_id': av.asset_id,
            'asset_name': av.asset.name,
            'status': av.status,
            'discovered_at': av.discovered_at.isoformat() if av.discovered_at else None
        }
        for av in affected_assets
    ]
    
    return jsonify(result)


@api_bp.route('/cves/stats', methods=['GET'])
@login_required
def cve_stats():
    """Estatísticas gerais de CVEs."""
    stats = {
        'total': Vulnerability.query.count(),
        'by_severity': {},
        'by_year': {},
        'recent_24h': 0,
        'recent_7d': 0,
        'cisa_kev_count': 0
    }
    
    # Por severidade
    for sev in Severity:
        count = Vulnerability.query.filter_by(base_severity=sev).count()
        stats['by_severity'][sev.value] = count
    
    # Por ano (últimos 5 anos)
    current_year = datetime.now().year
    for year in range(current_year - 4, current_year + 1):
        count = Vulnerability.query.filter(
            func.extract('year', Vulnerability.published_date) == year
        ).count()
        stats['by_year'][str(year)] = count
    
    # Recentes
    now = datetime.now(timezone.utc)
    stats['recent_24h'] = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(hours=24)
    ).count()
    
    stats['recent_7d'] = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(days=7)
    ).count()
    
    # CISA KEV
    stats['cisa_kev_count'] = Vulnerability.query.filter_by(is_in_cisa_kev=True).count()
    
    return jsonify(stats)


# =============================================================================
# ASSETS
# =============================================================================

@api_bp.route('/assets', methods=['GET'])
@login_required
def list_assets():
    """Listar assets do usuário atual."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    # Filtro por tipo
    asset_type = request.args.get('type')
    
    query = Asset.query.filter_by(owner_id=current_user.id)
    
    if asset_type:
        query = query.filter_by(asset_type=asset_type)
    
    # Busca
    search = request.args.get('search')
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            or_(
                Asset.name.ilike(search_term),
                Asset.ip_address.cast(db.String).ilike(search_term)
            )
        )
    
    pagination = query.order_by(Asset.name).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'items': [asset.to_dict() for asset in pagination.items],
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })


@api_bp.route('/assets', methods=['POST'])
@login_required
def create_asset():
    """Criar novo asset."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Bad Request', 'message': 'JSON body required'}), 400
    
    # Validação
    required_fields = ['name', 'ip_address']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': 'Bad Request', 'message': f'{field} is required'}), 400
    
    # Verificar unicidade (ip_address + owner)
    existing = Asset.query.filter_by(
        ip_address=data['ip_address'],
        owner_id=current_user.id
    ).first()
    
    if existing:
        return jsonify({
            'error': 'Conflict',
            'message': f'Asset with IP {data["ip_address"]} already exists'
        }), 409
    
    # Criar asset
    asset = Asset(
        name=data['name'],
        ip_address=data['ip_address'],
        owner_id=current_user.id,
        asset_type=data.get('asset_type', 'SERVER'),
        description=data.get('description'),
        rto_hours=data.get('rto_hours'),
        rpo_hours=data.get('rpo_hours'),
        operational_cost_per_hour=data.get('operational_cost_per_hour')
    )
    
    # Associar vendor se fornecido
    if data.get('vendor_name'):
        vendor = Vendor.query.filter_by(
            normalized_name=data['vendor_name'].lower()
        ).first()
        
        if not vendor:
            vendor = Vendor(
                name=data['vendor_name'],
                normalized_name=data['vendor_name'].lower()
            )
            db.session.add(vendor)
        
        asset.vendor = vendor
    
    db.session.add(asset)
    db.session.commit()
    
    current_app.logger.info(f'Asset created: {asset.name} by user {current_user.username}')
    
    return jsonify(asset.to_dict()), 201


@api_bp.route('/assets/<int:asset_id>', methods=['GET'])
@login_required
def get_asset(asset_id):
    """Obter asset específico."""
    asset = Asset.query.filter_by(id=asset_id, owner_id=current_user.id).first()
    
    if not asset:
        return jsonify({'error': 'Not Found', 'message': 'Asset not found'}), 404
    
    result = asset.to_dict()
    
    # Vulnerabilidades associadas
    vulns = AssetVulnerability.query.filter_by(asset_id=asset.id).all()
    result['vulnerabilities'] = [
        {
            'cve_id': av.cve_id,
            'status': av.status,
            'cvss_score': av.vulnerability.cvss_score if av.vulnerability else None,
            'severity': av.vulnerability.base_severity if av.vulnerability else None
        }
        for av in vulns
    ]
    
    # Risk score consolidado a partir das vulnerabilidades abertas do ativo.
    result['risk_score'] = asset.risk_score or 0
    
    return jsonify(result)


@api_bp.route('/assets/<int:asset_id>', methods=['PUT'])
@login_required
def update_asset(asset_id):
    """Atualizar asset."""
    asset = Asset.query.filter_by(id=asset_id, owner_id=current_user.id).first()
    
    if not asset:
        return jsonify({'error': 'Not Found', 'message': 'Asset not found'}), 404
    
    data = request.get_json()
    
    # Atualizar campos permitidos
    allowed_fields = [
        'name', 'description', 'asset_type',
        'rto_hours', 'rpo_hours', 'operational_cost_per_hour'
    ]
    
    for field in allowed_fields:
        if field in data:
            setattr(asset, field, data[field])
    
    db.session.commit()
    
    return jsonify(asset.to_dict())


@api_bp.route('/assets/<int:asset_id>', methods=['DELETE'])
@login_required
def delete_asset(asset_id):
    """Deletar asset."""
    asset = Asset.query.filter_by(id=asset_id, owner_id=current_user.id).first()
    
    if not asset:
        return jsonify({'error': 'Not Found', 'message': 'Asset not found'}), 404
    
    db.session.delete(asset)
    db.session.commit()
    
    current_app.logger.info(f'Asset deleted: {asset.name} by user {current_user.username}')
    
    return '', 204


# =============================================================================
# ANALYTICS
# =============================================================================

@api_bp.route('/analytics/overview', methods=['GET'])
@login_required
def analytics_overview():
    """
    Dashboard analytics com cache Redis.
    """
    from app.services.core import RedisCacheService
    
    cache = RedisCacheService()
    cache_key = f'analytics:overview:{current_user.id}'
    
    # Tentar cache
    cached = cache.get(cache_key)
    if cached:
        return jsonify(cached)
    
    # Calcular analytics
    analytics = {
        'severity_distribution': _get_severity_distribution(),
        'top_vendors': _get_top_vendors(),
        'top_cwes': _get_top_cwes(),
        'trend_data': _get_trend_data(),
        'user_assets_summary': _get_user_assets_summary(),
        'generated_at': datetime.now(timezone.utc).isoformat()
    }
    
    # Cache por 15 minutos
    cache.set(cache_key, analytics, ttl=900)
    
    return jsonify(analytics)


def _get_severity_distribution():
    """Distribuição de CVEs por severidade."""
    result = {}
    for sev in Severity:
        count = Vulnerability.query.filter_by(base_severity=sev).count()
        result[sev.value] = count
    return result


def _get_top_vendors():
    """Top 10 vendors com mais CVEs."""
    # Query complexa em JSONB - simplificada
    vendors = db.session.query(
        func.jsonb_array_elements(Vulnerability.nvd_vendors_data).op('->>')('vendor_name').label('vendor'),
        func.count().label('count')
    ).group_by('vendor').order_by(desc('count')).limit(10).all()
    
    return [{'vendor': v[0], 'count': v[1]} for v in vendors if v[0]]


def _get_top_cwes():
    """Top 10 CWEs mais frequentes."""
    cwes = db.session.query(
        Weakness.cwe_id,
        Weakness.description,
        func.count(Weakness.id).label('count')
    ).group_by(Weakness.cwe_id, Weakness.description).order_by(
        desc('count')
    ).limit(10).all()
    
    return [
        {'cwe_id': c[0], 'description': c[1], 'count': c[2]}
        for c in cwes
    ]


def _get_trend_data():
    """Tendência de CVEs nos últimos 30 dias."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=30)
    
    # Agrupar por dia
    daily = db.session.query(
        func.date(Vulnerability.published_date).label('date'),
        func.count().label('count')
    ).filter(
        Vulnerability.published_date >= start
    ).group_by('date').order_by('date').all()
    
    return [
        {'date': str(d[0]), 'count': d[1]}
        for d in daily
    ]


def _get_user_assets_summary():
    """Resumo dos assets do usuário."""
    total = Asset.query.filter_by(owner_id=current_user.id).count()
    
    affected = db.session.query(func.count(func.distinct(AssetVulnerability.asset_id))).join(
        Asset
    ).filter(Asset.owner_id == current_user.id).scalar() or 0
    
    return {
        'total_assets': total,
        'affected_assets': affected,
        'safe_assets': total - affected
    }


# =============================================================================
# SYNC
# =============================================================================

@api_bp.route('/sync/status', methods=['GET'])
@login_required
def sync_status():
    """Status atual da sincronização NVD."""
    from app.services.nvd import NVDSyncService

    progress = NVDSyncService().get_progress()
    current = int(progress.get('processed_cves') or progress.get('processed') or 0)
    total = int(progress.get('total_cves') or progress.get('total') or 0)

    status = {
        **progress,
        'current': current,
        'total': total,
        'last_sync': progress.get('last_sync') or SyncMetadata.get_value('nvd_last_sync_date'),
        'first_sync_completed': bool(progress.get('first_sync_completed')),
        'error': progress.get('error')
    }
    
    # Calcular porcentagem
    if total > 0:
        status['percentage'] = round((current / total) * 100, 1)
    else:
        status['percentage'] = 0
    
    return jsonify(status)


@api_bp.route('/sync/trigger', methods=['POST'])
@login_required
@admin_required
def trigger_sync():
    """Disparar sincronização NVD manualmente (admin only)."""
    data = request.get_json() or {}
    full_sync = data.get('full_sync', False)
    
    # Verificar se já está rodando
    current_status = SyncMetadata.get_value('nvd_sync_progress_status', 'idle')
    if current_status in ['running', 'starting']:
        return jsonify({
            'error': 'Conflict',
            'message': 'Sync already in progress'
        }), 409
    
    # Disparar sync
    from app.jobs import trigger_nvd_sync
    started = trigger_nvd_sync(full_sync=full_sync)
    if not started:
        return jsonify({
            'error': 'Conflict',
            'message': 'Sync already in progress'
        }), 409
    
    return jsonify({
        'message': 'Sync triggered',
        'full_sync': full_sync
    }), 202


@api_bp.route('/sync/progress', methods=['GET'])
@login_required
def sync_progress():
    """
    Polling endpoint para progresso do sync.
    Usado pela página de loading.
    """
    status = SyncMetadata.get_value('nvd_sync_progress_status', 'idle')
    current = int(
        SyncMetadata.get_value('nvd_sync_progress_processed_cves')
        or SyncMetadata.get_value('nvd_sync_progress_processed')
        or 0
    )
    total = int(
        SyncMetadata.get_value('nvd_sync_progress_total_cves')
        or SyncMetadata.get_value('nvd_sync_progress_total')
        or 0
    )
    
    percentage = 0
    if total > 0:
        percentage = round((current / total) * 100, 1)
    
    return jsonify({
        'status': status,
        'current': current,
        'total': total,
        'percentage': percentage,
        'completed': status == 'completed'
    })


# =============================================================================
# MONITORING RULES
# =============================================================================

@api_bp.route('/monitoring/rules', methods=['GET'])
@login_required
def list_monitoring_rules():
    """Listar regras de monitoramento do usuário."""
    rules = MonitoringRule.query.filter_by(user_id=current_user.id).all()
    return jsonify({'items': [r.to_dict() for r in rules]})


@api_bp.route('/monitoring/rules', methods=['POST'])
@login_required
def create_monitoring_rule():
    """Criar nova regra de monitoramento."""
    data = request.get_json()
    
    if not data or 'name' not in data:
        return jsonify({'error': 'Bad Request', 'message': 'name is required'}), 400
    
    channels = []
    for ch in data.get('notification_channels', ['EMAIL']):
        channels.append({'type': ch, 'config': {}})

    rule = MonitoringRule(
        user_id=current_user.id,
        name=data['name'],
        description=data.get('description'),
        rule_type=data.get('rule_type', 'NEW_CVE'),
        parameters=data.get('parameters', {}),
        alert_channels=channels,
        enabled=data.get('is_enabled', data.get('enabled', True))
    )
    
    db.session.add(rule)
    db.session.commit()
    
    return jsonify(rule.to_dict()), 201


# =============================================================================
# REPORTS
# =============================================================================

@api_bp.route('/reports', methods=['GET'])
@login_required
def list_reports():
    """Listar relatórios do usuário."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    
    pagination = Report.query.filter_by(
        user_id=current_user.id
    ).order_by(Report.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'items': [r.to_dict() for r in pagination.items],
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })


@api_bp.route('/reports', methods=['POST'])
@login_required
def create_report():
    """Criar novo relatório."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Bad Request', 'message': 'JSON body required'}), 400
    
    report = Report(
        user_id=current_user.id,
        title=data.get('title', f'Report {datetime.now().strftime("%Y-%m-%d %H:%M")}'),
        report_type=data.get('type', 'EXECUTIVE'),
        filters=data.get('filters', {})
    )
    
    db.session.add(report)
    db.session.commit()
    
    # Disparar geração em background
    report.start_generation()
    from app.jobs import trigger_report_generation
    trigger_report_generation(report.id)
    
    return jsonify(report.to_dict()), 202


@api_bp.route('/reports/<int:report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    """Obter relatório específico."""
    report = Report.query.filter_by(
        id=report_id,
        user_id=current_user.id
    ).first()
    
    if not report:
        return jsonify({'error': 'Not Found', 'message': 'Report not found'}), 404
    
    return jsonify(report.to_dict())


# =============================================================================
# VENDORS
# =============================================================================

@api_bp.route('/vendors', methods=['GET'])
@login_required
def list_vendors():
    """Listar vendors conhecidos (para autocomplete)."""
    search = request.args.get('q', '')
    limit = min(request.args.get('limit', 20, type=int), 50)
    
    query = Vendor.query
    
    if search:
        query = query.filter(Vendor.normalized_name.ilike(f'%{search.lower()}%'))
    
    vendors = query.order_by(Vendor.name).limit(limit).all()
    
    return jsonify({
        'items': [{'id': v.id, 'name': v.name} for v in vendors]
    })
