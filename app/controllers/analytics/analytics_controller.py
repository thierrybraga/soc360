"""
SOC360 Analytics Controller
Rotas para dashboards e análises avançadas.
"""
import logging
import csv
import io
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, redirect, url_for, Response, stream_with_context
from flask_login import login_required, current_user
from sqlalchemy import func, text, desc

from app.extensions import db
from app.extensions.db_types import USE_SQLITE
from app.models.nvd import Vulnerability
from app.models.inventory import Asset, AssetVulnerability
from app.models.monitoring import MonitoringRule, Report
from app.models.system import VulnerabilityStatus
from app.services.risk import RiskScoringService


logger = logging.getLogger(__name__)


analytics_bp = Blueprint('analytics', __name__)


@analytics_bp.route('/')
@login_required
def index():
    """Dashboard principal - Redireciona para o core dashboard."""
    return redirect(url_for('core.dashboard'))


@analytics_bp.route('/api/dashboard')
@login_required
def dashboard_data():
    """API: Dados para dashboard principal."""
    now = datetime.utcnow()
    last_30d = now - timedelta(days=30)
    previous_30d = last_30d - timedelta(days=30)
    
    def get_trend(query, date_field):
        """Calcula tendência baseada em contagem de 30 dias vs período anterior."""
        current_count = query.filter(date_field >= last_30d).count()
        previous_count = query.filter(date_field >= previous_30d, date_field < last_30d).count()
        
        change = current_count - previous_count
        percent = (change / previous_count * 100) if previous_count > 0 else (100 if current_count > 0 else 0)
        
        return {
            'value': current_count,
            'change': change,
            'percent': round(percent, 1),
            'direction': 'up' if change > 0 else ('down' if change < 0 else 'neutral')
        }

    # === Vulnerabilidades ===
    total_vulns = Vulnerability.query.count()
    
    # Trends
    vuln_trend = get_trend(Vulnerability.query, Vulnerability.published_date)
    
    critical_query = Vulnerability.query.filter(Vulnerability.base_severity == 'CRITICAL')
    critical_trend = get_trend(critical_query, Vulnerability.published_date)
    
    cisa_query = Vulnerability.query.filter(Vulnerability.is_in_cisa_kev == True)
    cisa_trend = get_trend(cisa_query, Vulnerability.cisa_exploit_add)

    vulns_24h = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(hours=24)
    ).count()
    
    vulns_7d = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(days=7)
    ).count()
    
    # Por severidade
    severity_counts = db.session.query(
        Vulnerability.base_severity,
        db.func.count(Vulnerability.cve_id)
    ).group_by(Vulnerability.base_severity).all()
    
    # CISA KEV
    cisa_kev_count = Vulnerability.query.filter(
        Vulnerability.is_in_cisa_kev == True
    ).count()
    
    # Top 10 mais recentes críticas
    critical_recent = Vulnerability.query.filter(
        Vulnerability.base_severity == 'CRITICAL'
    ).order_by(Vulnerability.published_date.desc()).limit(10).all()

    
    # === Ativos ===
    asset_query = Asset.query
    if not current_user.is_admin:
        asset_query = asset_query.filter(Asset.owner_id == current_user.id)
    
    total_assets = asset_query.count()
    asset_trend = get_trend(asset_query, Asset.created_at)
    
    # Ativos com vulnerabilidades abertas
    vuln_asset_query = db.session.query(
        db.func.count(db.distinct(AssetVulnerability.asset_id))
    ).filter(AssetVulnerability.status == VulnerabilityStatus.OPEN.value)
    
    if not current_user.is_admin:
        vuln_asset_query = vuln_asset_query.join(Asset).filter(Asset.owner_id == current_user.id)
    
    assets_with_vulns = vuln_asset_query.scalar() or 0
    
    # === Monitoramento ===
    rule_query = MonitoringRule.query
    if not current_user.is_admin:
        rule_query = rule_query.filter(MonitoringRule.user_id == current_user.id)

    active_rules = rule_query.filter(MonitoringRule.enabled == True).count()
    
    return jsonify({
        'vulnerabilities': {
            'total': total_vulns,
            'trend': vuln_trend,
            'last_24h': vulns_24h,
            'last_7d': vulns_7d,
            'by_severity': {row[0] or 'UNKNOWN': row[1] for row in severity_counts},
            'cisa_kev': cisa_kev_count,
            'cisa_trend': cisa_trend,
            'critical_trend': critical_trend,
            'critical_recent': [
                {
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'published': v.published_date.isoformat() if v.published_date else None,
                    'description': (v.description[:150] + '...') if v.description and len(v.description) > 150 else (v.description or '')
                }
                for v in critical_recent
            ]
        },
        'assets': {
            'total': total_assets,
            'trend': asset_trend,
            'with_vulnerabilities': assets_with_vulns,
            'without_vulnerabilities': total_assets - assets_with_vulns
        },
        'monitoring': {
            'active_rules': active_rules
        }
    })


@analytics_bp.route('/api/trends')
@login_required
def vulnerability_trends():
    """API: Tendências de vulnerabilidades."""
    days = request.args.get('days', 30, type=int)
    group_by = request.args.get('group_by', 'day')  # day, week, month
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Agrupar por período
    if USE_SQLITE:
        # SQLite implementation using strftime
        if group_by == 'week':
            # SQLite doesn't have simple 'week', use %Y-%W
            date_trunc = func.strftime('%Y-%W', Vulnerability.published_date)
        elif group_by == 'month':
            date_trunc = func.strftime('%Y-%m', Vulnerability.published_date)
        else:
            date_trunc = func.date(Vulnerability.published_date)
    else:
        # PostgreSQL implementation
        if group_by == 'week':
            date_trunc = func.date_trunc('week', Vulnerability.published_date)
        elif group_by == 'month':
            date_trunc = func.date_trunc('month', Vulnerability.published_date)
        else:
            date_trunc = func.date(Vulnerability.published_date)
    
    # Total por período
    timeline = db.session.query(
        date_trunc.label('period'),
        func.count(Vulnerability.cve_id).label('count')
    ).filter(
        Vulnerability.published_date >= start_date
    ).group_by(date_trunc).order_by(date_trunc).all()
    
    # Por severidade e período
    severity_timeline = db.session.query(
        date_trunc.label('period'),
        Vulnerability.base_severity,
        func.count(Vulnerability.cve_id).label('count')
    ).filter(
        Vulnerability.published_date >= start_date
    ).group_by(date_trunc, Vulnerability.base_severity).order_by(date_trunc).all()
    
    # Processar dados
    severity_data = {}
    for row in severity_timeline:
        severity = row[1] or 'UNKNOWN'
        if severity not in severity_data:
            severity_data[severity] = []
        severity_data[severity].append({
            'period': str(row[0]),
            'count': row[2]
        })
    
    return jsonify({
        'timeline': [
            {'period': str(row.period), 'count': row.count}
            for row in timeline
        ],
        'by_severity': severity_data
    })


@analytics_bp.route('/api/top-vendors')
@login_required
def top_vendors():
    """API: Top vendors por número de CVEs."""
    days = request.args.get('days', 30, type=int)
    limit = request.args.get('limit', 10, type=int)
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    if USE_SQLITE:
        # SQLite fallback: Fetch and process in Python
        # Note: This might be slow for large datasets, but safe for SQLite
        # Ideally, we should use json_each if enabled in SQLite
        
        # Fetch vendors data for the period
        results = db.session.query(Vulnerability.nvd_vendors_data).filter(
            Vulnerability.published_date >= start_date
        ).all()
        
        from collections import Counter
        vendor_counts = Counter()
        
        for row in results:
            vendors = row[0]
            if vendors and isinstance(vendors, list):
                for vendor in vendors:
                    if vendor:
                        vendor_counts[vendor] += 1
                        
        top_vendors_list = vendor_counts.most_common(limit)
        
        return jsonify({
            'vendors': [
                {'vendor': vendor, 'count': count}
                for vendor, count in top_vendors_list
            ]
        })
    else:
        # PostgreSQL optimized query
        query = db.session.execute(
            text("""
                SELECT vendor, COUNT(*) as count
                FROM vulnerabilities, jsonb_array_elements_text(nvd_vendors_data) as vendor
                WHERE published_date >= :start_date
                GROUP BY vendor
                ORDER BY count DESC
                LIMIT :limit
            """),
            {'start_date': start_date, 'limit': limit}
        ).fetchall()
        
        return jsonify({
            'vendors': [
                {'vendor': row[0], 'count': row[1]}
                for row in query
            ]
        })


@analytics_bp.route('/api/severity-distribution')
@login_required
def severity_distribution():
    """API: Distribuição de severidade."""
    days = request.args.get('days', 0, type=int)  # 0 = all time
    
    query = db.session.query(
        Vulnerability.base_severity,
        db.func.count(Vulnerability.cve_id),
        db.func.avg(Vulnerability.cvss_score)
    )
    
    if days > 0:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Vulnerability.published_date >= start_date)
    
    results = query.group_by(Vulnerability.base_severity).all()
    
    return jsonify({
        'distribution': [
            {
                'severity': row[0] or 'UNKNOWN',
                'count': row[1],
                'avg_cvss': round(float(row[2]) if row[2] else 0, 2)
            }
            for row in results
        ]
    })



@analytics_bp.route('/api/remediation-status')
@login_required
def remediation_status():
    """API: Status de remediação e SLA."""
    # Count by status
    status_counts = db.session.query(
        AssetVulnerability.status,
        func.count(AssetVulnerability.id)
    ).group_by(AssetVulnerability.status).all()
    
    # Inicializa todos os status definidos no enum VulnerabilityStatus
    by_status = {
        'OPEN': 0,
        'IN_PROGRESS': 0,
        'MITIGATED': 0,
        'RESOLVED': 0,
        'ACCEPTED': 0,
        'FALSE_POSITIVE': 0,
    }

    for status, count in status_counts:
        if status and status in by_status:
            by_status[status] = count
    
    # Overdue: OPEN com due_date preenchido e já vencido
    now = datetime.utcnow()
    overdue = AssetVulnerability.query.filter(
        AssetVulnerability.status == VulnerabilityStatus.OPEN.value,
        AssetVulnerability.due_date.isnot(None),
        AssetVulnerability.due_date < now
    ).count()

    # Upcoming due: OPEN com due_date preenchido e vencendo nos próximos 7 dias
    upcoming = AssetVulnerability.query.filter(
        AssetVulnerability.status == VulnerabilityStatus.OPEN.value,
        AssetVulnerability.due_date.isnot(None),
        AssetVulnerability.due_date >= now,
        AssetVulnerability.due_date < now + timedelta(days=7)
    ).count()
    
    return jsonify({
        'by_status': by_status,
        'overdue': overdue,
        'upcoming_due': upcoming
    })


@analytics_bp.route('/api/asset-risk-matrix')
@login_required
def asset_risk_matrix():
    """API: Matriz de risco de ativos."""
    # Buscar ativos com vulnerabilidades
    # Por simplicidade, vamos buscar todos e calcular em Python para poucos ativos,
    # ou fazer query otimizada para muitos.
    # Vamos de query otimizada agrupando.
    
    query = db.session.query(
        Asset.id,
        Asset.name,
        Asset.asset_type,
        Asset.criticality,
        Vulnerability.base_severity,
        func.count(AssetVulnerability.id)
    ).join(
        AssetVulnerability, Asset.id == AssetVulnerability.asset_id
    ).join(
        Vulnerability, AssetVulnerability.cve_id == Vulnerability.cve_id
    ).filter(
        AssetVulnerability.status == VulnerabilityStatus.OPEN.value
    )
    
    if not current_user.is_admin:
        query = query.filter(Asset.owner_id == current_user.id)
        
    results = query.group_by(
        Asset.id, Asset.name, Asset.asset_type, Asset.criticality, Vulnerability.base_severity
    ).all()
    
    # Processar em memória para montar objetos
    assets_risk = {}

    for row in results:
        asset_id = row[0]
        if asset_id not in assets_risk:
            assets_risk[asset_id] = {
                'asset_id': asset_id,
                'name': row[1],
                'type': row[2],
                'criticality': row[3],
                'vulnerabilities': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0},
                'risk_score': 0
            }

        # base_severity pode ser None — mapeia para 'UNKNOWN'
        severity = row[4] if row[4] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') else 'UNKNOWN'
        count = row[5]
        assets_risk[asset_id]['vulnerabilities'][severity] += count
            
    final_list = []
    for asset in assets_risk.values():
        asset['risk_score'] = RiskScoringService.calculate_asset_matrix_score(
            asset['criticality'],
            asset['vulnerabilities'],
        )
        final_list.append(asset)
        
    # Ordenar e pegar top 5
    final_list.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return jsonify({
        'matrix': final_list[:5]
    })


@analytics_bp.route('/api/cisa-kev-timeline')
@login_required
def cisa_kev_timeline():
    """API: Timeline de CVEs adicionados ao CISA KEV."""
    days = request.args.get('days', 90, type=int)
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    timeline = db.session.query(
        db.func.date(Vulnerability.cisa_exploit_add).label('date'),
        db.func.count(Vulnerability.cve_id).label('count')
    ).filter(
        Vulnerability.is_in_cisa_kev == True,
        Vulnerability.cisa_exploit_add >= start_date
    ).group_by(db.func.date(Vulnerability.cisa_exploit_add)).order_by('date').all()
    
    return jsonify({
        'timeline': [
            {'date': str(row.date), 'count': row.count}
            for row in timeline
        ]
    })


@analytics_bp.route('/api/cvss-histogram')
@login_required
def cvss_histogram():
    """API: Histograma de scores CVSS."""
    days = request.args.get('days', 0, type=int)
    
    query = db.session.query(
        db.func.floor(Vulnerability.cvss_score).label('score_range'),
        db.func.count(Vulnerability.cve_id).label('count')
    ).filter(Vulnerability.cvss_score.isnot(None))
    
    if days > 0:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Vulnerability.published_date >= start_date)
    
    results = query.group_by(db.func.floor(Vulnerability.cvss_score)).order_by('score_range').all()
    
    # Converter para ranges legíveis
    histogram = []
    for row in results:
        score = int(row[0]) if row[0] else 0
        histogram.append({
            'range': f'{score}.0-{score}.9',
            'count': row[1]
        })
    
    return jsonify({'histogram': histogram})


@analytics_bp.route('/api/export')
@login_required
def export_data():
    """API: Exportar dados de vulnerabilidades (CSV) com filtros."""
    fmt = request.args.get('format', 'csv')
    
    if fmt != 'csv':
        return jsonify({'error': 'Format not supported'}), 400

    # Filtros
    severity = request.args.get('severity')
    vendor = request.args.get('vendor')
    product = request.args.get('product')
    search = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    cisa_kev = request.args.get('cisa_kev')
    
    # Query base
    query = Vulnerability.query

    # Aplicar filtros
    if severity:
        query = query.filter(Vulnerability.base_severity == severity.upper())

    if vendor:
        query = query.filter(
            Vulnerability.nvd_vendors_data.contains([vendor.lower()])
        )

    if product:
        query = query.filter(
            db.cast(
                Vulnerability.nvd_products_data, db.Text
            ).ilike(f'%{product}%')
        )

    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Vulnerability.cve_id.ilike(search_term),
                Vulnerability.description.ilike(search_term)
            )
        )

    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            query = query.filter(Vulnerability.published_date >= from_date)
        except ValueError:
            pass

    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            query = query.filter(Vulnerability.published_date <= to_date)
        except ValueError:
            pass

    if cisa_kev == 'true':
        query = query.filter(Vulnerability.is_in_cisa_kev.is_(True))
    
    # Ordenação default
    query = query.order_by(Vulnerability.published_date.desc())
    
    # Executar query (pode ser pesado, mas é exportação)
    vulns = query.all()
    
    def generate():
        data = io.StringIO()
        w = csv.writer(data)
        
        # Header
        w.writerow((
            'CVE ID', 'Published Date', 'Severity', 'Score', 
            'Status', 'Description', 'CISA KEV', 'Vendors', 'Products'
        ))
        yield data.getvalue()
        data.seek(0)
        data.truncate(0)
        
        # Rows
        for v in vulns:
            vendors = ', '.join(v.vendors) if v.vendors else ''
            products = ', '.join(v.products) if v.products else ''
            
            w.writerow((
                v.cve_id,
                v.published_date.strftime('%Y-%m-%d') if v.published_date else '',
                v.base_severity,
                v.cvss_score,
                v.vuln_status,
                v.description,
                'Yes' if v.is_in_cisa_kev else 'No',
                vendors,
                products
            ))
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)
            
    response = Response(stream_with_context(generate()), mimetype='text/csv')
    response.headers.set('Content-Disposition', f'attachment; filename=vulnerabilities_export_{datetime.now().strftime("%Y%m%d")}.csv')
    return response
