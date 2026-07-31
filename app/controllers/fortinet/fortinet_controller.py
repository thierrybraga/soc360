"""
SOC360 Fortinet Controller
Rotas especializadas para dispositivos Fortinet.
"""
import logging
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.inventory import Asset, AssetVulnerability, Vendor, Product
from app.models.nvd import Vulnerability
from app.models.system import AssetType, VulnerabilityStatus
from app.utils.security import role_required
from app.services.fortinet import (
    get_fortinet_matching_service,
    FORTINET_PRODUCTS,
    FORTIOS_VERSIONS,
    SUPPORTED_FORTIOS_BRANCHES,
    is_version_supported,
    is_version_eol,
    CRITICAL_FORTINET_CVES
)

logger = logging.getLogger(__name__)

fortinet_bp = Blueprint('fortinet', __name__, url_prefix='/fortinet')


# ============================================================================
# PÁGINAS HTML
# ============================================================================

@fortinet_bp.route('/')
@fortinet_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard Fortinet."""
    return render_template('fortinet/dashboard.html')


@fortinet_bp.route('/assets')
@login_required
def assets_list():
    """Lista de assets Fortinet."""
    return render_template('fortinet/assets.html')


@fortinet_bp.route('/cves')
@login_required
def cves_list():
    """Lista de CVEs Fortinet."""
    return render_template('fortinet/cves.html')


# ============================================================================
# API - DASHBOARD STATS
# ============================================================================

@fortinet_bp.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """API: Estatísticas para dashboard Fortinet."""
    try:
        service = get_fortinet_matching_service()
        stats = service.get_fortinet_dashboard_stats()

        fortinet_assets = Asset.query.filter(
            db.or_(
                Asset.vendor.has(normalized_name='fortinet'),
                Asset.os_family.ilike('%forti%'),
                Asset.asset_type == 'FIREWALL'
            )
        )

        if not current_user.is_admin:
            fortinet_assets = fortinet_assets.filter_by(owner_id=current_user.id)

        stats['total_assets'] = fortinet_assets.count()

        assets_with_vulns = db.session.query(
            db.func.count(db.distinct(AssetVulnerability.asset_id))
        ).join(Asset).filter(
            db.or_(
                Asset.vendor.has(normalized_name='fortinet'),
                Asset.os_family.ilike('%forti%')
            ),
            AssetVulnerability.status.in_([
                VulnerabilityStatus.OPEN.value,
                VulnerabilityStatus.IN_PROGRESS.value
            ])
        ).scalar()

        stats['assets_with_open_vulns'] = assets_with_vulns or 0

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API - CVEs FORTINET
# ============================================================================

@fortinet_bp.route('/api/cves')
@login_required
def api_list_cves():
    """API: Lista CVEs Fortinet com filtros."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    product = request.args.get('product')
    severity = request.args.get('severity')
    cisa_kev = request.args.get('cisa_kev', 'false').lower() == 'true'
    search = request.args.get('search')

    try:
        query = Vulnerability.query.filter(
            Vulnerability.nvd_vendors_data.contains(['fortinet'])
        )

        if product:
            query = query.filter(
                Vulnerability.nvd_products_data.contains({'fortinet': [product.lower()]})
            )

        if severity:
            severities = [s.strip().upper() for s in severity.split(',')]
            query = query.filter(Vulnerability.base_severity.in_(severities))

        if cisa_kev:
            query = query.filter(Vulnerability.is_in_cisa_kev == True)  # noqa: E712

        if search:
            search_term = f'%{search}%'
            query = query.filter(
                db.or_(
                    Vulnerability.cve_id.ilike(search_term),
                    Vulnerability.description.ilike(search_term)
                )
            )

        query = query.order_by(
            Vulnerability.is_in_cisa_kev.desc(),
            Vulnerability.cvss_score.desc().nulls_last(),
            Vulnerability.published_date.desc()
        )

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'items': [v.to_list_dict() for v in pagination.items],
            'total': pagination.total,
            'pages': pagination.pages,
            'page': page,
            'per_page': per_page
        })

    except Exception as e:
        logger.error(f"Error listing Fortinet CVEs: {e}")
        return jsonify({'error': str(e)}), 500


@fortinet_bp.route('/api/cves/critical')
@login_required
def api_critical_cves():
    """API: CVEs críticas Fortinet (CISA KEV e CVSS >= 9.0)."""
    try:
        service = get_fortinet_matching_service()

        cves = service.get_all_fortinet_cves(
            severity_filter=['CRITICAL'],
            limit=50
        )

        kev_cves = service.get_all_fortinet_cves(
            cisa_kev_only=True,
            limit=50
        )

        cve_ids = set()
        result = []

        for cve in kev_cves + cves:
            if cve.cve_id not in cve_ids:
                cve_ids.add(cve.cve_id)
                result.append(cve.to_dict())

        result.sort(key=lambda x: (
            -int(x.get('is_in_cisa_kev', False)),
            -(x.get('cvss_score') or 0)
        ))

        return jsonify({
            'items': result[:50],
            'total': len(result)
        })

    except Exception as e:
        logger.error(f"Error getting critical CVEs: {e}")
        return jsonify({'error': str(e)}), 500


@fortinet_bp.route('/api/cves/by-product/<product>')
@login_required
def api_cves_by_product(product):
    """API: CVEs por produto Fortinet."""
    version = request.args.get('version')
    severity = request.args.get('severity')
    limit = request.args.get('limit', 100, type=int)

    try:
        service = get_fortinet_matching_service()

        severity_filter = None
        if severity:
            severity_filter = [s.strip().upper() for s in severity.split(',')]

        cves = service.get_cves_by_product(
            product=product,
            version=version,
            severity_filter=severity_filter,
            limit=limit
        )

        return jsonify({
            'product': product,
            'version': version,
            'items': [v.to_list_dict() for v in cves],
            'total': len(cves)
        })

    except Exception as e:
        logger.error(f"Error getting CVEs for product {product}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API - SCANNING
# ============================================================================

@fortinet_bp.route('/api/scan', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def api_scan_assets():
    """API: Executa scan de vulnerabilidades em assets Fortinet."""
    data = request.get_json() or {}

    asset_ids = data.get('asset_ids', [])
    scan_all = data.get('scan_all', False)
    create_associations = data.get('create_associations', True)

    try:
        service = get_fortinet_matching_service()

        if asset_ids:
            results = []
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue

                if not current_user.is_admin and asset.owner_id != current_user.id:
                    continue

                matches = service.match_asset(asset)

                if create_associations:
                    for match in matches:
                        existing = AssetVulnerability.query.filter_by(
                            asset_id=asset.id,
                            cve_id=match.cve_id
                        ).first()

                        if not existing:
                            av = AssetVulnerability(
                                asset_id=asset.id,
                                cve_id=match.cve_id,
                                status=VulnerabilityStatus.OPEN.value,
                                discovered_at=datetime.utcnow(),
                                detection_method='manual_scan',
                                detected_by='FortinetMatchingService',
                                notes=f"Confidence: {match.confidence}"
                            )
                            av.contextual_risk_score = asset.calculate_risk_score(match.cvss_score)
                            db.session.add(av)

                results.append({
                    'asset_id': asset.id,
                    'asset_name': asset.name,
                    'matches': len(matches),
                    'critical': len([m for m in matches if m.severity == 'CRITICAL']),
                    'cisa_kev': len([m for m in matches if m.is_cisa_kev])
                })

            if create_associations:
                db.session.commit()

            return jsonify({
                'results': results,
                'total_assets': len(results)
            })

        elif scan_all:
            owner_id = None if current_user.is_admin else current_user.id

            stats = service.scan_all_fortinet_assets(
                owner_id=owner_id,
                create_associations=create_associations
            )

            return jsonify(stats)

        else:
            return jsonify({'error': 'Specify asset_ids or scan_all=true'}), 400

    except Exception as e:
        logger.error(f"Error during Fortinet scan: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API - VERSION CHECK
# ============================================================================

@fortinet_bp.route('/api/version-check')
@login_required
def api_version_check():
    """API: Verifica status de uma versão FortiOS."""
    version = request.args.get('version')

    if not version:
        return jsonify({'error': 'Version parameter required'}), 400

    try:
        service = get_fortinet_matching_service()
        result = service.check_version_status(version)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error checking version {version}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API - PRODUTOS E VERSÕES
# ============================================================================

@fortinet_bp.route('/api/products')
@login_required
def api_list_products():
    """API: Lista produtos Fortinet disponíveis."""
    products = []

    for key, product in FORTINET_PRODUCTS.items():
        products.append({
            'key': key,
            'name': product.name,
            'cpe_product': product.cpe_product,
            'type': product.product_type.value,
            'description': product.description,
            'cpe_prefix': product.cpe_prefix,
            'models': product.common_models or []
        })

    return jsonify({
        'products': products,
        'total': len(products)
    })


@fortinet_bp.route('/api/versions')
@login_required
def api_list_versions():
    """API: Lista versões FortiOS conhecidas."""
    versions = []

    for branch, branch_versions in FORTIOS_VERSIONS.items():
        is_supported = branch in SUPPORTED_FORTIOS_BRANCHES

        for version in branch_versions:
            versions.append({
                'version': version,
                'branch': branch,
                'is_supported': is_supported,
                'is_eol': not is_supported
            })

    return jsonify({
        'versions': versions,
        'supported_branches': SUPPORTED_FORTIOS_BRANCHES,
        'total': len(versions)
    })


@fortinet_bp.route('/api/known-critical-cves')
@login_required
def api_known_critical_cves():
    """API: Lista CVEs críticas conhecidas (hardcoded)."""
    return jsonify({
        'cves': CRITICAL_FORTINET_CVES,
        'total': len(CRITICAL_FORTINET_CVES)
    })


# ============================================================================
# API - ASSETS FORTINET
# ============================================================================

@fortinet_bp.route('/api/assets')
@login_required
def api_list_assets():
    """API: Lista assets Fortinet."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    query = Asset.query.filter(
        db.or_(
            Asset.vendor.has(normalized_name='fortinet'),
            Asset.os_family.ilike('%forti%'),
            Asset.asset_type == 'FIREWALL'
        )
    )

    if not current_user.is_admin:
        query = query.filter_by(owner_id=current_user.id)

    model = request.args.get('model')
    version = request.args.get('version')
    criticality = request.args.get('criticality')

    if model:
        query = query.filter(Asset.hostname.ilike(f'%{model}%'))

    if version:
        query = query.filter(
            db.or_(
                Asset.version.ilike(f'%{version}%'),
                Asset.os_version.ilike(f'%{version}%')
            )
        )

    if criticality:
        query = query.filter_by(criticality=criticality.upper())

    query = query.order_by(Asset.criticality.desc(), Asset.name.asc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    items = []
    for asset in pagination.items:
        asset_dict = asset.to_dict()

        open_vulns = AssetVulnerability.query.filter(
            AssetVulnerability.asset_id == asset.id,
            AssetVulnerability.status.in_([
                VulnerabilityStatus.OPEN.value,
                VulnerabilityStatus.IN_PROGRESS.value
            ])
        ).count()

        asset_dict['open_vulnerabilities'] = open_vulns

        ver = asset.version or asset.os_version
        if ver:
            asset_dict['version_supported'] = is_version_supported(ver)
            asset_dict['version_eol'] = is_version_eol(ver)

        items.append(asset_dict)

    return jsonify({
        'items': items,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
        'per_page': per_page
    })


@fortinet_bp.route('/api/assets/<int:asset_id>/vulnerabilities')
@login_required
def api_asset_vulnerabilities(asset_id):
    """API: Vulnerabilidades de um asset Fortinet."""
    asset = Asset.query.get_or_404(asset_id)

    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)

    assocs = AssetVulnerability.query.filter_by(
        asset_id=asset_id
    ).order_by(
        AssetVulnerability.contextual_risk_score.desc().nulls_last()
    ).all()

    results = []
    for assoc in assocs:
        vuln = Vulnerability.query.filter_by(cve_id=assoc.cve_id).first()

        results.append({
            'cve_id': assoc.cve_id,
            'status': assoc.status,
            'discovered_at': assoc.discovered_at.isoformat() if assoc.discovered_at else None,
            'due_date': assoc.due_date.isoformat() if assoc.due_date else None,
            'contextual_risk_score': assoc.contextual_risk_score,
            'detection_method': assoc.detection_method,
            'notes': assoc.notes,
            'cvss_score': vuln.cvss_score if vuln else None,
            'severity': vuln.base_severity if vuln else None,
            'is_cisa_kev': vuln.is_in_cisa_kev if vuln else False,
            'description': vuln.description[:200] if vuln and vuln.description else None
        })

    return jsonify({
        'asset_id': asset_id,
        'asset_name': asset.name,
        'vulnerabilities': results,
        'total': len(results)
    })
