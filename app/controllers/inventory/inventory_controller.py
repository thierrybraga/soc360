"""
SOC360 Inventory Controller
Rotas para gerenciamento de ativos e inventário.
"""
import logging
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.inventory import Asset, AssetVulnerability, Vendor, Product, AssetCategory
from app.models.nvd import Vulnerability
from app.models.system import AssetType, AssetStatus, VulnerabilityStatus
from app.utils.security import role_required, owner_or_admin_required, audit_action
from app.services.inventory import get_asset_correlation_service


logger = logging.getLogger(__name__)


inventory_bp = Blueprint('inventory', __name__)


def _split_os_label(os_label):
    if not os_label:
        return None, None
    value = os_label.strip()
    if not value:
        return None, None
    parts = value.rsplit(' ', 1)
    if len(parts) == 2 and any(ch.isdigit() for ch in parts[1]):
        return parts[0], parts[1]
    return value, None


@inventory_bp.route('/')
@login_required
def index():
    """Lista de ativos."""
    return render_template('inventory/index.html')


@inventory_bp.route('/add')
@inventory_bp.route('/create')
@login_required
@role_required('ADMIN', 'ANALYST')
def create():
    """Página de criação de ativo."""
    return render_template('inventory/form.html')


@inventory_bp.route('/api/categories')
@login_required
def list_categories():
    """API: Listar categorias de ativos."""
    categories = AssetCategory.query.all()
    return jsonify([c.to_dict() for c in categories])


@inventory_bp.route('/api/categories', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
@audit_action('inventory.category_create')
def create_category():
    """API: Criar nova categoria."""
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Missing name'}), 400
    
    category = AssetCategory(
        name=data['name'],
        description=data.get('description'),
        parent_id=data.get('parent_id'),
        is_organization=data.get('is_organization', False)
    )
    db.session.add(category)
    db.session.commit()
    return jsonify(category.to_dict()), 201


@inventory_bp.route('/api/organizations')
@login_required
def list_organizations():
    """API: Listar organizações (AssetCategory com is_organization=True)."""
    orgs = AssetCategory.query.filter_by(is_organization=True).all()
    return jsonify([o.to_dict() for o in orgs])


@inventory_bp.route('/api/list')
@login_required
def list_assets():
    """API: Listar ativos com filtros e paginação."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    # Filtros
    asset_type = request.args.get('type')
    status = request.args.get('status')
    owner = request.args.get('owner')
    search = request.args.get('search')
    criticality = request.args.get('criticality')
    organization_id = request.args.get('organization_id', type=int)
    
    # Query base - filtrar por owner se não admin
    query = Asset.query
    if not current_user.is_admin:
        query = query.filter(Asset.owner_id == current_user.id)
    
    # Aplicar filtros
    if organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    if asset_type:
        try:
            query = query.filter(Asset.asset_type == AssetType(asset_type))
        except ValueError:
            pass
    
    if status:
        try:
            query = query.filter(Asset.status == AssetStatus(status))
        except ValueError:
            pass
    
    if owner and current_user.is_admin:
        query = query.filter(Asset.owner_id == int(owner))
    
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Asset.name.ilike(search_term),
                Asset.ip_address.cast(db.String).ilike(search_term),
                Asset.hostname.ilike(search_term)
            )
        )
    
    if criticality:
        query = query.filter(Asset.criticality == criticality.upper())
    
    # Ordenação por risco
    query = query.order_by(Asset.criticality.desc(), Asset.name.asc())
    
    # Paginação
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        # include_vuln_stats=False: avoids N+1 lazy loads into the public DB
        # per asset row — risk_score and critical_vulnerability_count are not
        # needed in the list view (they are available on the detail page).
        'items': [a.to_dict(include_vuln_stats=False) for a in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
        'per_page': per_page
    })



@inventory_bp.route('/api/create', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def create_asset():
    """API: Criar novo ativo."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    required_fields = ['name', 'asset_type']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Map legacy/short types to enum values
    type_mapping = {
        'NETWORK': 'NETWORK_DEVICE',
        'CLOUD': 'CLOUD_SERVICE',
        'IOT': 'IOT_DEVICE',
        'MOBILE': 'MOBILE_DEVICE'
    }
    
    raw_type = data['asset_type']
    if raw_type in type_mapping:
        raw_type = type_mapping[raw_type]
    
    # Validar tipo
    try:
        asset_type = AssetType(raw_type)
    except ValueError:
        return jsonify({'error': f'Invalid asset type: {data["asset_type"]}'}), 400
    
    # Verificar IP duplicado
    if data.get('ip_address'):
        existing = Asset.query.filter_by(
            ip_address=data['ip_address'],
            owner_id=current_user.id
        ).first()
        if existing:
            return jsonify({'error': 'IP address already registered'}), 409
    
    correlation_service = get_asset_correlation_service()
    resolved = correlation_service.resolve_vendor_and_product(data)
    vendor_id = data.get('vendor_id')
    product_id = data.get('product_id')
    if not vendor_id and not product_id:
        ensured = correlation_service.ensure_vendor_product(
            vendor_name=resolved.get('vendor_name'),
            product_name=resolved.get('product_name')
        )
        if ensured.get('vendor'):
            vendor_id = ensured['vendor'].id
        if ensured.get('product'):
            product_id = ensured['product'].id
    os_name = data.get('os_name')
    os_version = data.get('os_version')
    if data.get('operating_system') and not os_name:
        os_name, parsed_version = _split_os_label(data.get('operating_system'))
        if not os_version:
            os_version = parsed_version

    # Criar ativo
    asset = Asset(
        name=data['name'],
        asset_type=asset_type.value,
        ip_address=data.get('ip_address'),
        hostname=data.get('hostname'),
        mac_address=data.get('mac_address'),
        os_family=data.get('os_family'),
        os_name=os_name,
        os_version=os_version,
        location=data.get('location'),
        department=data.get('department'),
        owner_id=current_user.id,
        category_id=data.get('category_id'),
        organization_id=data.get('organization_id'),
        parent_id=data.get('parent_id'),
        client_id=data.get('client_id'),
        environment=data.get('environment', 'PRODUCTION').upper(),
        exposure=data.get('exposure', 'INTERNAL').upper(),
        criticality=data.get('criticality', 'MEDIUM').upper(),
        description=data.get('description'),
        tags=data.get('tags', []),
        # Vendor/Product/Version
        vendor_id=vendor_id,
        product_id=product_id,
        version=data.get('version'),
        # BIA fields
        rto_hours=data.get('rto_hours'),
        rpo_hours=data.get('rpo_hours'),
        operational_cost_per_hour=data.get('operational_cost_per_hour'),
        # Software
        installed_software=data.get('installed_software', [])
    )
    custom_fields = asset.custom_fields or {}
    if resolved.get('model'):
        custom_fields['model'] = resolved.get('model')
    if resolved.get('vendor_profile'):
        custom_fields['vendor_profile'] = resolved.get('vendor_profile')
    asset.custom_fields = custom_fields

    db.session.add(asset)
    db.session.commit()
    correlation_result = correlation_service.correlate_asset(asset, auto_associate=True)
    db.session.commit()

    logger.info(f'Asset created: {asset.name} by {current_user.username}')

    return jsonify({
        'message': 'Asset created successfully',
        'asset': asset.to_dict(),
        'correlation': {
            'matched_cves': len(correlation_result['matches']),
            'new_associations': correlation_result['new_associations'],
            'existing_associations': correlation_result['existing_associations']
        }
    }), 201


@inventory_bp.route('/api/<int:asset_id>')
@login_required
def get_asset(asset_id):
    """API: Obter detalhes de um ativo."""
    asset = Asset.query.get_or_404(asset_id)
    
    # Verificar permissão
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    
    return jsonify(asset.to_dict())


@inventory_bp.route('/api/<int:asset_id>', methods=['PUT'])
@login_required
@role_required('ADMIN', 'ANALYST')
def update_asset(asset_id):
    """API: Atualizar ativo."""
    asset = Asset.query.get_or_404(asset_id)
    
    # Verificar permissão
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    correlation_service = get_asset_correlation_service()
    resolved = correlation_service.resolve_vendor_and_product(data)
    if ('vendor_id' not in data) and (resolved.get('vendor_name') or data.get('vendor_name')):
        ensured = correlation_service.ensure_vendor_product(
            vendor_name=resolved.get('vendor_name') or data.get('vendor_name'),
            product_name=resolved.get('product_name') or data.get('product_name')
        )
        if ensured.get('vendor'):
            data['vendor_id'] = ensured['vendor'].id
        if ensured.get('product'):
            data['product_id'] = ensured['product'].id
    if data.get('operating_system') and not data.get('os_name'):
        os_name, os_version = _split_os_label(data.get('operating_system'))
        data['os_name'] = os_name
        if os_version and not data.get('os_version'):
            data['os_version'] = os_version

    updatable_fields = [
        'name', 'hostname', 'mac_address', 'os_family', 'os_name', 'os_version',
        'location', 'department', 'criticality', 'description', 'tags',
        'rto_hours', 'rpo_hours', 'operational_cost_per_hour',
        'installed_software', 'status', 'version', 'vendor_id', 'product_id',
        'category_id', 'parent_id', 'client_id', 'environment', 'exposure'
    ]

    # Resolver vendor por nome se fornecido
    if 'vendor_name' in data and 'vendor_id' not in data:
        vendor = Vendor.get_by_name(data['vendor_name'])
        if vendor:
            data['vendor_id'] = vendor.id

    # Resolver product por nome se fornecido
    if 'product_name' in data and 'product_id' not in data:
        vid = data.get('vendor_id') or asset.vendor_id
        if vid:
            product = Product.get_by_name(data['product_name'], vendor_id=vid)
            if product:
                data['product_id'] = product.id

    for field in updatable_fields:
        if field in data:
            if field == 'status':
                try:
                    setattr(asset, field, AssetStatus(data[field]))
                except ValueError:
                    continue
            else:
                setattr(asset, field, data[field])
    custom_fields = asset.custom_fields or {}
    if resolved.get('model'):
        custom_fields['model'] = resolved.get('model')
    if resolved.get('vendor_profile'):
        custom_fields['vendor_profile'] = resolved.get('vendor_profile')
    asset.custom_fields = custom_fields
    
    db.session.commit()
    correlation_result = correlation_service.correlate_asset(asset, auto_associate=True)
    db.session.commit()
    
    logger.info(f'Asset updated: {asset.name} by {current_user.username}')
    
    return jsonify({
        'message': 'Asset updated successfully',
        'asset': asset.to_dict(),
        'correlation': {
            'matched_cves': len(correlation_result['matches']),
            'new_associations': correlation_result['new_associations'],
            'existing_associations': correlation_result['existing_associations']
        }
    })


@inventory_bp.route('/api/<int:asset_id>', methods=['DELETE'])
@login_required
@role_required('ADMIN')
def delete_asset(asset_id):
    """API: Deletar ativo."""
    asset = Asset.query.get_or_404(asset_id)
    
    db.session.delete(asset)
    db.session.commit()
    
    logger.info(f'Asset deleted: {asset.name} by {current_user.username}')
    
    return jsonify({'message': 'Asset deleted successfully'})


@inventory_bp.route('/api/<int:asset_id>/vulnerabilities')
@login_required
def asset_vulnerabilities(asset_id):
    """API: Vulnerabilidades associadas a um ativo."""
    asset = Asset.query.get_or_404(asset_id)
    
    # Verificar permissão
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    
    # Buscar associações
    associations = AssetVulnerability.query.filter_by(
        asset_id=asset_id
    ).order_by(AssetVulnerability.contextual_risk_score.desc()).all()
    
    result = []
    for assoc in associations:
        vuln = Vulnerability.query.filter_by(cve_id=assoc.cve_id).first()
        if vuln:
            result.append({
                'vulnerability': vuln.to_dict(),
                'status': assoc.status if assoc.status else None,
                'discovered_at': assoc.discovered_at.isoformat() if assoc.discovered_at else None,
                'due_date': assoc.due_date.isoformat() if assoc.due_date else None,
                'contextual_risk_score': assoc.contextual_risk_score,
                'notes': assoc.notes,
                'cwes': [w.cwe_id for w in vuln.weaknesses],
                'model': (asset.custom_fields or {}).get('model')
            })
    
    return jsonify({'vulnerabilities': result})


@inventory_bp.route('/api/<int:asset_id>/vulnerabilities/<cve_id>', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def associate_vulnerability(asset_id, cve_id):
    """API: Associar vulnerabilidade a um ativo."""
    asset = Asset.query.get_or_404(asset_id)
    vuln = Vulnerability.query.filter_by(cve_id=cve_id.upper()).first_or_404()
    
    # Verificar permissão
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    
    # Verificar se já existe
    existing = AssetVulnerability.query.filter_by(
        asset_id=asset_id,
        cve_id=cve_id.upper()
    ).first()
    
    if existing:
        return jsonify({'error': 'Association already exists'}), 409
    
    # Criar associação
    data = request.get_json() or {}

    assoc = AssetVulnerability(
        asset_id=asset_id,
        cve_id=cve_id.upper(),
        status=VulnerabilityStatus(data.get('status', 'OPEN')).value,
        discovered_at=datetime.utcnow(),
        notes=data.get('notes')
    )
    # Adicionar à sessão antes de calcular o risco — os relacionamentos
    # asset e vulnerability só são carregáveis com o objeto rastreado.
    db.session.add(assoc)
    db.session.flush()  # Garante que assoc.id existe e os rels funcionam
    assoc.calculate_contextual_risk()

    db.session.commit()

    logger.info(f'Vulnerability {cve_id} associated to asset {asset.name}')

    return jsonify({
        'message': 'Vulnerability associated successfully',
        'contextual_risk_score': assoc.contextual_risk_score
    }), 201


@inventory_bp.route('/api/<int:asset_id>/vulnerabilities/<cve_id>', methods=['DELETE'])
@login_required
@role_required('ADMIN', 'ANALYST')
def remove_vulnerability(asset_id, cve_id):
    """API: Remover associação de vulnerabilidade de um ativo."""
    assoc = AssetVulnerability.query.filter_by(
        asset_id=asset_id,
        cve_id=cve_id.upper()
    ).first_or_404()
    asset = Asset.query.get(asset_id)
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    db.session.delete(assoc)
    db.session.commit()
    return jsonify({'message': f'{cve_id} removed from asset'})


@inventory_bp.route('/api/<int:asset_id>/vulnerabilities', methods=['DELETE'])
@login_required
@role_required('ADMIN', 'ANALYST')
def remove_all_vulnerabilities(asset_id):
    """API: Remover todas as associações de vulnerabilidade de um ativo."""
    asset = Asset.query.get_or_404(asset_id)
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)
    count = AssetVulnerability.query.filter_by(asset_id=asset_id).delete()
    db.session.commit()
    return jsonify({'message': f'{count} vulnerabilities removed from asset'})


@inventory_bp.route('/api/<int:asset_id>/vulnerabilities/<cve_id>', methods=['PUT'])
@login_required
@role_required('ADMIN', 'ANALYST')
def update_vulnerability_status(asset_id, cve_id):
    """API: Atualizar status de vulnerabilidade."""
    assoc = AssetVulnerability.query.filter_by(
        asset_id=asset_id,
        cve_id=cve_id.upper()
    ).first_or_404()
    
    asset = Asset.query.get_or_404(asset_id)
    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)

    data = request.get_json() or {}

    if 'status' in data:
        try:
            assoc.update_status(VulnerabilityStatus(data['status']).value, current_user.id)
        except ValueError:
            return jsonify({'error': 'Invalid status'}), 400

    if 'notes' in data:
        assoc.notes = data['notes']

    if 'due_date' in data:
        try:
            assoc.due_date = datetime.fromisoformat(data['due_date'])
        except ValueError:
            pass

    db.session.commit()

    return jsonify({'message': 'Vulnerability status updated'})


@inventory_bp.route('/api/scan', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def scan_assets():
    """API: Escanear ativos em busca de vulnerabilidades."""
    data = request.get_json() or {}
    asset_ids = data.get('asset_ids', [])
    scan_all = data.get('scan_all', False)
    
    if not asset_ids and not scan_all:
        return jsonify({'error': 'No assets specified'}), 400
    
    # Buscar ativos
    if scan_all:
        if current_user.is_admin:
            assets = Asset.query.all()
        else:
            assets = Asset.query.filter_by(owner_id=current_user.id).all()
    else:
        assets = Asset.query.filter(Asset.id.in_(asset_ids)).all()
    
    matches = []
    service = get_asset_correlation_service()
    total_new_associations = 0
    total_existing_associations = 0
    for asset in assets:
        # Verificar permissão
        if not current_user.is_admin and asset.owner_id != current_user.id:
            continue
        
        correlation_result = service.correlate_asset(asset, auto_associate=True)
        total_new_associations += correlation_result['new_associations']
        total_existing_associations += correlation_result['existing_associations']
        for match in correlation_result['matches']:
            matches.append({
                'asset_id': asset.id,
                'asset_name': asset.name,
                'cve_id': match['cve_id'],
                'cvss_score': match['cvss_score'],
                'severity': match['severity'],
                'matched_vendor': asset.vendor.name if asset.vendor else None,
                'cwes': match.get('cwes', []),
                'confidence': match.get('confidence')
            })
    db.session.commit()
    
    return jsonify({
        'matches': matches,
        'total': len(matches),
        'new_associations': total_new_associations,
        'existing_associations': total_existing_associations
    })


@inventory_bp.route('/api/vendor-profiles')
@login_required
def vendor_profiles():
    service = get_asset_correlation_service()
    return jsonify(service.get_vendor_profile_payload())


@inventory_bp.route('/api/stats')
@login_required
def stats():
    """API: Estatísticas de ativos."""
    # Query base
    query = Asset.query
    if not current_user.is_admin:
        query = query.filter(Asset.owner_id == current_user.id)
    
    # Total por tipo
    type_q = db.session.query(Asset.asset_type, db.func.count(Asset.id))
    if not current_user.is_admin:
        type_q = type_q.filter(Asset.owner_id == current_user.id)
    type_counts = type_q.group_by(Asset.asset_type).all()

    # Total por criticidade
    crit_q = db.session.query(Asset.criticality, db.func.count(Asset.id))
    if not current_user.is_admin:
        crit_q = crit_q.filter(Asset.owner_id == current_user.id)
    criticality_counts = crit_q.group_by(Asset.criticality).all()
    
    # Total com vulnerabilidades
    assets_with_vulns = db.session.query(
        db.func.count(db.distinct(AssetVulnerability.asset_id))
    ).scalar()
    
    # Vulnerabilidades abertas
    open_vulns = AssetVulnerability.query.filter(
        AssetVulnerability.status == VulnerabilityStatus.OPEN.value
    ).count()

    # Vulnerabilidades mitigadas
    mitigated_vulns = AssetVulnerability.query.filter(
        AssetVulnerability.status == VulnerabilityStatus.MITIGATED.value
    ).count()

    # Cross-DB: fetch only the cve_id column (not full objects) to keep memory
    # low, then filter asset_vulnerabilities with the resulting ID set.
    critical_cve_ids = {
        row[0]
        for row in db.session.query(Vulnerability.cve_id).filter(
            Vulnerability.base_severity == 'CRITICAL'
        ).all()
    }
    critical_vulns = (
        AssetVulnerability.query
        .filter(
            AssetVulnerability.status == VulnerabilityStatus.OPEN.value,
            AssetVulnerability.cve_id.in_(critical_cve_ids),
        )
        .count()
        if critical_cve_ids else 0
    )

    return jsonify({
        'total': query.count(),
        'by_type': {str(row[0]): row[1] for row in type_counts},
        'by_criticality': {row[0]: row[1] for row in criticality_counts},
        'with_vulnerabilities': assets_with_vulns,
        'open_vulnerabilities': open_vulns,
        'mitigated_vulnerabilities': mitigated_vulns,
        'critical_vulnerabilities': critical_vulns
    })


@inventory_bp.route('/<int:asset_id>')
@login_required
def detail(asset_id):
    """Detalhes de um ativo."""
    asset = Asset.query.get_or_404(asset_id)

    if not current_user.is_admin and asset.owner_id != current_user.id:
        abort(403)

    # ------------------------------------------------------------------
    # Pre-fetch all associations and batch-load vulnerabilities from the
    # public DB in one query — avoids N+1 and broken attribute access in
    # the template (AssetVulnerability has no .severity attribute).
    # ------------------------------------------------------------------
    associations = (
        AssetVulnerability.query
        .filter_by(asset_id=asset_id)
        .order_by(
            AssetVulnerability.contextual_risk_score.desc(),
            AssetVulnerability.discovered_at.desc()
        )
        .all()
    )

    cve_ids = [a.cve_id for a in associations]

    # Batch-load from public DB
    vuln_map = {}
    if cve_ids:
        from app.models.nvd.vulnerability import Vulnerability as _Vuln
        vulns_batch = _Vuln.query.filter(_Vuln.cve_id.in_(cve_ids)).all()
        vuln_map = {v.cve_id: v for v in vulns_batch}

    # Build enriched rows — everything the template needs in one dict per row
    open_statuses = {VulnerabilityStatus.OPEN.value, VulnerabilityStatus.IN_PROGRESS.value}
    vuln_rows = []
    severity_counts = {}
    for assoc in associations:
        vuln = vuln_map.get(assoc.cve_id)
        severity = (vuln.base_severity or 'UNKNOWN') if vuln else 'UNKNOWN'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        vuln_rows.append({
            'cve_id':               assoc.cve_id,
            'status':               assoc.status,
            'severity':             severity,
            'cvss_score':           float(vuln.cvss_score) if vuln and vuln.cvss_score else None,
            'contextual_risk':      assoc.contextual_risk_score,
            'discovered_at':        assoc.discovered_at,
            'days_open':            assoc.days_open,
            'is_overdue':           assoc.is_overdue,
            'is_open':              assoc.status in open_statuses,
            'notes':                assoc.notes,
            'description':          (vuln.description[:160] if vuln and vuln.description else None),
            'cisa_kev':             bool(getattr(vuln, 'cisa_kev', False)) if vuln else False,
        })

    status_counts = AssetVulnerability.count_by_status(asset_id=asset_id)
    total_associations = len(associations)

    # ------------------------------------------------------------------
    # Radar chart — all values on a 0-10 scale
    # ------------------------------------------------------------------
    radar_chart = None
    open_rows = [r for r in vuln_rows if r['is_open']]
    if open_rows:
        scores = [r['cvss_score'] for r in open_rows if r['cvss_score'] is not None]
        avg_cvss = round(sum(scores) / len(scores), 1) if scores else 0.0

        criticality_map = {'LOW': 2, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
        env_map    = {'PRODUCTION': 10, 'STAGING': 7,  'DEV': 4,  'DMZ': 9}
        exp_map    = {'INTERNAL':    4, 'CLOUD':   7,  'EXTERNAL': 10}

        bia      = round(float(asset.bia_score or 0) / 10, 1)
        crit_val = criticality_map.get((asset.criticality or '').upper(), 5)
        env_val  = env_map.get((asset.environment or '').upper(), 5)
        exp_val  = exp_map.get((asset.exposure   or '').upper(), 5)

        radar_chart = {
            'labels': ['Avg CVSS', 'BIA Score', 'Criticidade', 'Exposição', 'Ambiente'],
            'values': [avg_cvss, bia, crit_val, exp_val, env_val],
        }

    return render_template(
        'inventory/detail.html',
        asset=asset,
        vuln_rows=vuln_rows,
        status_counts=status_counts,
        severity_counts=severity_counts,
        total_associations=total_associations,
        radar_chart=radar_chart,
    )
