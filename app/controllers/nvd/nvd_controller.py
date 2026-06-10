"""
SOC360 NVD Controller
Rotas para visualização e gerenciamento de vulnerabilidades.
"""
import logging
from datetime import datetime, timedelta, timezone
from statistics import mean

from flask import Blueprint, current_app, render_template, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func, case
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models.nvd import Vulnerability, CvssMetric, Weakness, Reference, Mitigation, Credit, AffectedProduct
from app.services.nvd import NVDOperationAlreadyRunning, NVDSyncService, SyncMode
from app.models.inventory.category import AssetCategory
from app.utils.security import role_required
def _is_sqlite():
    """Detecta se o banco em uso é SQLite verificando o URI configurado no app."""
    from flask import current_app
    uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    return uri.startswith('sqlite')


logger = logging.getLogger(__name__)


nvd_bp = Blueprint('nvd', __name__)


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _serialize_dt(dt):
    """Convert datetime to ISO string, return None if None."""
    return dt.isoformat() if dt else None


def _now_utc_naive():
    """Return UTC now as naive datetime for existing DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _build_mitigation_history(cve_id: str, limit: int = 100):
    from app.models.inventory import Asset, AssetVulnerability

    mitigation_entries = []
    mitigations = Mitigation.query.filter_by(cve_id=cve_id).order_by(Mitigation.created_at.desc()).limit(limit).all()
    for m in mitigations:
        mitigation_entries.append({
            'timestamp': _serialize_dt(m.created_at),
            'kind': 'mitigation_record',
            'title': m.type or 'Mitigation',
            'description': m.description,
            'source': m.source,
            'effectiveness': m.effectiveness,
            'user_id': None,
            'asset_vulnerability_id': None
        })

    workflow_entries = []
    associations = AssetVulnerability.query.options(
        joinedload(AssetVulnerability.asset),
        joinedload(AssetVulnerability.assignee)
    ).outerjoin(
        Asset, Asset.id == AssetVulnerability.asset_id
    ).filter(
        func.upper(AssetVulnerability.cve_id) == cve_id
    ).order_by(AssetVulnerability.updated_at.desc()).limit(limit).all()

    for av in associations:
        asset_label = av.asset.name if av.asset else f'Asset #{av.asset_id}'
        ts = av.updated_at or av.created_at
        workflow_entries.append({
            'timestamp': _serialize_dt(ts),
            'kind': 'workflow_event',
            'title': f'Status {av.status} for {asset_label}',
            'description': av.remediation_notes or av.notes or '',
            'source': 'asset_workflow',
            'effectiveness': None,
            'user_id': av.assignee_id,
            'username': av.assignee.username if av.assignee else None,
            'status': av.status,
            'asset_vulnerability_id': av.id,
            'due_date': av.due_date.isoformat() if av.due_date else None
        })
        if av.acknowledged_at:
            workflow_entries.append({
                'timestamp': _serialize_dt(av.acknowledged_at),
                'kind': 'workflow_event',
                'title': f'Acknowledged for {asset_label}',
                'description': '',
                'source': 'asset_workflow',
                'effectiveness': None,
                'user_id': av.assignee_id,
                'username': av.assignee.username if av.assignee else None,
                'status': 'IN_PROGRESS',
                'asset_vulnerability_id': av.id,
                'due_date': None
            })
        if av.resolved_at:
            workflow_entries.append({
                'timestamp': _serialize_dt(av.resolved_at),
                'kind': 'workflow_event',
                'title': f'Resolved for {asset_label}',
                'description': '',
                'source': 'asset_workflow',
                'effectiveness': None,
                'user_id': av.assignee_id,
                'username': av.assignee.username if av.assignee else None,
                'status': av.status,
                'asset_vulnerability_id': av.id,
                'due_date': None
            })

    combined = mitigation_entries + workflow_entries
    combined.sort(key=lambda x: x['timestamp'] or '', reverse=True)
    return combined[:limit]


@nvd_bp.route('/')
@login_required
def index():
    """Lista de vulnerabilidades."""
    return render_template('nvd/index.html')




@nvd_bp.route('/api/list')
@login_required
def list_vulnerabilities():
    """API: Listar vulnerabilidades com filtros e paginação."""
    # Paginação
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    # Filtros
    severity = request.args.get('severity')
    vendor = request.args.get('vendor')
    product = request.args.get('product')
    search = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    cisa_kev = request.args.get('cisa_kev')

    # Aceita ambos os nomes de parâmetros de ordenação
    sort_by = request.args.get('sort_by') or request.args.get('sort', 'published_date')
    sort_order = request.args.get('sort_order') or request.args.get('order', 'desc')

    # Mapear nomes JS -> campos do model
    sort_field_map = {
        'published': 'published_date',
        'published_date': 'published_date',
        'cve_id': 'cve_id',
        'cvss_score': 'cvss_score',
        'severity': 'base_severity',
        'base_severity': 'base_severity',
        'last_modified': 'last_modified_date',
    }
    sort_field = sort_field_map.get(sort_by, 'published_date')

    # Query base
    query = Vulnerability.query

    # Aplicar filtros
    _valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    _score_ranges = {
        'CRITICAL': (9.0, None),
        'HIGH': (7.0, 9.0),
        'MEDIUM': (4.0, 7.0),
        'LOW': (0.001, 4.0),
    }
    if severity:
        sev_upper = severity.upper()
        if sev_upper in _score_ranges:
            min_score, max_score = _score_ranges[sev_upper]
            score_conditions = [Vulnerability.cvss_score >= min_score]
            if max_score is not None:
                score_conditions.append(Vulnerability.cvss_score < max_score)
            # Match stored severity OR derive from score for UNKNOWN/NULL records
            query = query.filter(
                db.or_(
                    Vulnerability.base_severity == sev_upper,
                    db.and_(
                        db.or_(
                            Vulnerability.base_severity.is_(None),
                            Vulnerability.base_severity.notin_(_valid_severities)
                        ),
                        *score_conditions
                    )
                )
            )
        else:
            query = query.filter(Vulnerability.base_severity == sev_upper)

    if vendor:
        # PostgreSQL JSONB containment
        query = query.filter(
            db.cast(
                Vulnerability.nvd_vendors_data, db.Text
            ).ilike(f'%{vendor}%')
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

    # Ordenação
    sort_column = getattr(
        Vulnerability, sort_field, Vulnerability.published_date
    )
    if sort_order == 'desc':
        query = query.order_by(sort_column.desc().nulls_last())
    else:
        query = query.order_by(sort_column.asc().nulls_first())

    # Paginação
    pagination = query.paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Estatísticas de severidade (contagem global, não filtrada).
    # Usa ORM + JOIN com CvssMetric para obter severidade mesmo quando ausente na tabela principal.
    try:
        total_cves = Vulnerability.query.count()

        # Contagem por severidade feita 100% em SQL (uma linha de resultado por
        # severidade), em vez de trazer UMA LINHA POR CVE para contar em Python.
        # O método anterior transferia centenas de milhares de linhas a cada
        # carregamento da lista (lento e propenso a timeout do worker em base
        # cheia). Bucketiza por base_severity com fallback para cvss_score.
        _valid = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        sev_bucket = case(
            (Vulnerability.base_severity.in_(_valid), Vulnerability.base_severity),
            (Vulnerability.cvss_score >= 9.0, 'CRITICAL'),
            (Vulnerability.cvss_score >= 7.0, 'HIGH'),
            (Vulnerability.cvss_score >= 4.0, 'MEDIUM'),
            (Vulnerability.cvss_score > 0, 'LOW'),
            else_=None,
        )
        counts = dict(
            db.session.execute(
                db.select(sev_bucket.label('sev'), func.count()).group_by(sev_bucket)
            ).all()
        )
        count_critical = counts.get('CRITICAL', 0)
        count_high = counts.get('HIGH', 0)
        count_medium = counts.get('MEDIUM', 0)
        count_low = counts.get('LOW', 0)
    except Exception as _stats_err:
        logger.error(f'Stats query error: {type(_stats_err).__name__}: {_stats_err}')
        count_critical = count_high = count_medium = count_low = 0
        total_cves = pagination.total

    def _serialize_item(v):
        d = v.to_list_dict()
        # Ensure products and vuln_status are always present
        if 'products' not in d:
            d['products'] = v.products
        if 'vuln_status' not in d:
            d['vuln_status'] = v.vuln_status
        return d

    return jsonify({
        'items': [_serialize_item(v) for v in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
        'per_page': per_page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev,
        '_v': 'v2-raw-sql',
        'stats': {
            'total': total_cves,
            'critical': count_critical,
            'high': count_high,
            'medium': count_medium,
            'low': count_low,
        }
    })


@nvd_bp.route('/<cve_id>')
@login_required
def detail(cve_id):
    """Detalhes de uma vulnerabilidade."""
    from app.models.mitre import Technique
    vuln = Vulnerability.query.options(
        selectinload(Vulnerability.mitre_techniques).selectinload(Technique.tactics),
        selectinload(Vulnerability.mitre_techniques).selectinload(Technique.mitigations),
    ).filter_by(cve_id=cve_id.upper()).first_or_404()

    # Carregar relacionamentos explicitamente
    cvss_metrics = CvssMetric.query.filter_by(cve_id=vuln.cve_id).all()
    weaknesses = Weakness.query.filter_by(cve_id=vuln.cve_id).all()
    references = Reference.query.filter_by(cve_id=vuln.cve_id).all()

    mitigations = Mitigation.query.filter_by(cve_id=vuln.cve_id).all()
    credits_raw = Credit.query.filter_by(cve_id=vuln.cve_id).all()
    # Deduplicate credits by normalized (value, type) — NVD feeds often return
    # the same researcher under multiple credit types or with trivial case/whitespace diffs.
    _seen_credit_keys = set()
    credits = []
    for _c in credits_raw:
        _key = ((_c.value or '').strip().lower(), (_c.type or '').strip().lower())
        if not _key[0] or _key in _seen_credit_keys:
            continue
        _seen_credit_keys.add(_key)
        credits.append(_c)
    affected_products = AffectedProduct.query.filter_by(cve_id=vuln.cve_id).all()

    # Importar models de inventory (cross-db)
    from app.models.inventory import Asset, AssetVulnerability
    affected_assets_query = AssetVulnerability.query.options(
        joinedload(AssetVulnerability.asset),
        joinedload(AssetVulnerability.assignee)
    ).outerjoin(
        Asset, Asset.id == AssetVulnerability.asset_id
    ).filter(
        func.upper(AssetVulnerability.cve_id) == vuln.cve_id
    )

    affected_assets = affected_assets_query.order_by(
        Asset.name.asc().nulls_last(),
        AssetVulnerability.discovered_at.desc()
    ).all()

    open_statuses = {'OPEN', 'IN_PROGRESS'}
    resolved_statuses = {'RESOLVED', 'MITIGATED'}
    open_assets_count = sum(1 for av in affected_assets if av.status in open_statuses)
    resolved_assets_count = sum(1 for av in affected_assets if av.status in resolved_statuses)
    overdue_assets_count = sum(1 for av in affected_assets if av.is_overdue)
    unassigned_assets_count = sum(1 for av in affected_assets if av.assignee_id is None)
    contextual_scores = [av.contextual_risk_score for av in affected_assets if av.contextual_risk_score is not None]
    avg_contextual_risk = round(mean(contextual_scores), 2) if contextual_scores else None
    max_contextual_risk = round(max(contextual_scores), 2) if contextual_scores else None

    asset_type_counts = {}
    asset_criticality_counts = {}
    for av in affected_assets:
        if av.asset and av.asset.asset_type:
            key = av.asset.asset_type.upper()
            asset_type_counts[key] = asset_type_counts.get(key, 0) + 1
        if av.asset and av.asset.criticality:
            key = av.asset.criticality.upper()
            asset_criticality_counts[key] = asset_criticality_counts.get(key, 0) + 1

    top_asset_types = sorted(
        asset_type_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )[:3]

    # Escolher a métrica primária (prefere CVSS v3.x > v2.0)
    primary_metric = None
    if cvss_metrics:
        v3_metrics = [m for m in cvss_metrics if (m.version or '').startswith('3')]
        v4_metrics = [m for m in cvss_metrics if (m.version or '').startswith('4')]
        primary_metric = (v4_metrics or v3_metrics or cvss_metrics)[0]

    # Threat Intel score (0–10)
    threat_intel_score = 0
    if vuln.exploit_available:
        threat_intel_score += 4
    if vuln.is_in_cisa_kev:
        threat_intel_score += 4
    if not vuln.patch_available:
        threat_intel_score += 2
    threat_intel_score = min(threat_intel_score, 10)

    # Exposure score baseado em número de ativos + severidade agregada
    exposure_score = min(len(affected_assets) * 2, 10) if affected_assets else 0.0

    # Open Risk score — média de risco contextual dos ativos OPEN/IN_PROGRESS
    if avg_contextual_risk is not None:
        open_scores = [av.contextual_risk_score for av in affected_assets
                       if av.status in open_statuses and av.contextual_risk_score is not None]
        open_risk_score = round(mean(open_scores), 2) if open_scores else avg_contextual_risk
    else:
        open_risk_score = 0.0

    # Derivar exploitability/impact se a métrica não tiver (fallback usando o próprio CVSS)
    base_score = round(float(vuln.cvss_score or 0), 2)
    if primary_metric and primary_metric.exploitability_score is not None:
        exploitability_val = round(float(primary_metric.exploitability_score), 2)
    else:
        # heurística: ~40% do base score se indisponível
        exploitability_val = round(base_score * 0.4, 2)
    if primary_metric and primary_metric.impact_score is not None:
        impact_val = round(float(primary_metric.impact_score), 2)
    else:
        impact_val = round(base_score * 0.6, 2)

    # Radar chart — sempre renderiza quando houver ao menos o CVSS base;
    # dimensões de inventário podem ser 0 quando não há ativos associados.
    radar_chart = None
    if vuln.cvss_score is not None or primary_metric:
        radar_chart = {
            'labels': [
                'CVSS Base',
                'Exploitability',
                'Impact',
                'Asset Exposure',
                'Open Risk',
                'Threat Intel',
            ],
            'values': [
                base_score,
                exploitability_val,
                impact_val,
                round(float(exposure_score), 2),
                round(float(open_risk_score), 2),
                round(float(threat_intel_score), 2),
            ],
        }

    # Separar referências por tipo
    patch_refs = [r for r in references if r.is_patch]
    exploit_refs = [r for r in references if r.is_exploit]
    advisory_refs = [r for r in references if r.is_vendor_advisory]
    other_refs = [r for r in references if not r.is_patch and not r.is_exploit and not r.is_vendor_advisory]

    return render_template(
        'nvd/detail.html',
        vulnerability=vuln,
        cvss_metrics=cvss_metrics,
        weaknesses=weaknesses,
        references=references,
        patch_refs=patch_refs,
        exploit_refs=exploit_refs,
        advisory_refs=advisory_refs,
        other_refs=other_refs,
        mitigations=mitigations,
        credits=credits,
        affected_products=affected_products,
        affected_assets=affected_assets,
        open_assets_count=open_assets_count,
        resolved_assets_count=resolved_assets_count,
        overdue_assets_count=overdue_assets_count,
        unassigned_assets_count=unassigned_assets_count,
        avg_contextual_risk=avg_contextual_risk,
        max_contextual_risk=max_contextual_risk,
        top_asset_types=top_asset_types,
        asset_criticality_counts=asset_criticality_counts,
        radar_chart=radar_chart,
        mitigation_history=_build_mitigation_history(vuln.cve_id),
    )


@nvd_bp.route('/api/<cve_id>/mitigations/workflow', methods=['POST'])
@login_required
def mitigation_workflow(cve_id):
    cve_id_upper = cve_id.upper()
    payload = request.get_json(silent=True) or {}
    action = (payload.get('action') or '').strip().lower()
    if action not in {'start', 'update', 'resolve', 'mitigate', 'accept_risk', 'reopen', 'add_note'}:
        return jsonify({'error': 'Invalid action'}), 400

    from app.models.inventory import Asset, AssetVulnerability

    asset_vuln = None
    asset_vuln_id = payload.get('asset_vulnerability_id')
    if asset_vuln_id:
        asset_vuln = AssetVulnerability.query.options(
            joinedload(AssetVulnerability.asset),
            joinedload(AssetVulnerability.assignee)
        ).filter(
            AssetVulnerability.id == asset_vuln_id,
            func.upper(AssetVulnerability.cve_id) == cve_id_upper
        ).first()
        if not asset_vuln:
            return jsonify({'error': 'Asset vulnerability association not found'}), 404
        if not current_user.is_admin and (not asset_vuln.asset or asset_vuln.asset.owner_id != current_user.id):
            return jsonify({'error': 'Forbidden'}), 403
    elif not current_user.is_admin:
        return jsonify({'error': 'asset_vulnerability_id is required for non-admin users'}), 400

    notes = (payload.get('notes') or '').strip()
    effectiveness = (payload.get('effectiveness') or '').strip() or None
    source = (payload.get('source') or '').strip() or 'organization'
    mitigation_type = (payload.get('type') or '').strip() or 'Workaround'
    mitigation_description = (payload.get('mitigation_description') or '').strip()
    due_date = _parse_iso_datetime(payload.get('due_date'))
    assignee_id = payload.get('assignee_id')

    status_map = {
        'start': 'IN_PROGRESS',
        'update': None,
        'resolve': 'RESOLVED',
        'mitigate': 'MITIGATED',
        'accept_risk': 'ACCEPTED',
        'reopen': 'OPEN',
        'add_note': None
    }

    now = _now_utc_naive()
    changed_status = None
    try:
        if asset_vuln:
            next_status = status_map[action]
            if next_status:
                asset_vuln.status = next_status
                changed_status = next_status
            if action == 'start' and not asset_vuln.acknowledged_at:
                asset_vuln.acknowledged_at = now
            if action in {'resolve', 'mitigate'}:
                asset_vuln.resolved_at = now
            if action == 'reopen':
                asset_vuln.resolved_at = None
            if due_date:
                asset_vuln.due_date = due_date
            if assignee_id is not None and current_user.is_admin:
                asset_vuln.assignee_id = assignee_id
            if notes:
                previous = (asset_vuln.remediation_notes or '').strip()
                prefix = f"[{now.strftime('%Y-%m-%d %H:%M:%S')}][{action.upper()}]"
                asset_vuln.remediation_notes = f"{previous}\n{prefix} {notes}".strip() if previous else f"{prefix} {notes}"
            if mitigation_description:
                extra = f" mitigation={mitigation_type} source={source}"
                if effectiveness:
                    extra = f"{extra} effectiveness={effectiveness}"
                description_line = f"[{now.strftime('%Y-%m-%d %H:%M:%S')}][MITIGATION]{extra}: {mitigation_description}"
                asset_vuln.remediation_notes = f"{asset_vuln.remediation_notes}\n{description_line}".strip() if asset_vuln.remediation_notes else description_line

        db.session.commit()

        return jsonify({
            'success': True,
            'cve_id': cve_id_upper,
            'action': action,
            'asset_vulnerability': asset_vuln.to_dict() if asset_vuln else None,
            'created_mitigation': None,
            'history': _build_mitigation_history(cve_id_upper, limit=40)
        })
    except Exception as exc:
        db.session.rollback()
        logger.error(f'Error on mitigation workflow for {cve_id_upper}: {exc}')
        return jsonify({'error': 'Failed to update mitigation workflow'}), 500


@nvd_bp.route('/api/<cve_id>/mitigations/history')
@login_required
def mitigation_history(cve_id):
    vuln = Vulnerability.query.filter_by(cve_id=cve_id.upper()).first_or_404()
    return jsonify({
        'cve_id': vuln.cve_id,
        'items': _build_mitigation_history(vuln.cve_id, limit=200)
    })


@nvd_bp.route('/api/<cve_id>')
@login_required
def api_detail(cve_id):
    """API JSON: Detalhes completos de uma CVE para modal e integrações."""
    cve_id_upper = cve_id.upper()
    vuln = Vulnerability.query.filter_by(cve_id=cve_id_upper).first_or_404()

    cvss_metrics = (
        CvssMetric.query.filter_by(cve_id=cve_id_upper)
        .order_by(CvssMetric.version.desc())
        .all()
    )
    weaknesses = Weakness.query.filter_by(cve_id=cve_id_upper).all()
    references = (
        Reference.query.filter_by(cve_id=cve_id_upper)
        .order_by(
            Reference.is_patch.desc(),
            Reference.is_vendor_advisory.desc(),
            Reference.is_exploit.desc(),
        )
        .limit(30)
        .all()
    )

    return jsonify({
        'vulnerability': vuln.to_dict(),
        'cvss_metrics': [m.to_dict() for m in cvss_metrics],
        'weaknesses': [w.to_dict() for w in weaknesses],
        'references': [r.to_dict() for r in references],
    })



@nvd_bp.route('/api/sync/reprocess-raw', methods=['POST'])
@login_required
def reprocess_raw():
    """
    Re-extrai weaknesses, references e credits do raw_nvd_data já armazenado.
    Útil quando o sync original rodou com bug no dialeto SQLite e não gravou esses dados.
    """
    from app.services.nvd.bulk_database_service import BulkDatabaseService
    svc = BulkDatabaseService()
    batch_size = 500
    page = 0
    stats = {'weaknesses': 0, 'references': 0, 'credits': 0, 'processed': 0, 'skipped': 0}

    while True:
        vulns = Vulnerability.query.filter(
            Vulnerability.raw_nvd_data.isnot(None)
        ).offset(page * batch_size).limit(batch_size).all()

        if not vulns:
            break

        weakness_records = []
        reference_records = []
        credit_records = []
        cve_ids = []

        for v in vulns:
            raw = v.raw_nvd_data
            if not raw:
                stats['skipped'] += 1
                continue
            cve_ids.append(v.cve_id)
            weakness_records.extend(svc._extract_weakness_data(raw))
            reference_records.extend(svc._extract_reference_data(raw))
            credit_records.extend(svc._extract_credits_data(raw))
            stats['processed'] += 1

        try:
            with svc.bulk_session():
                if weakness_records:
                    svc._upsert_weaknesses(weakness_records)
                    stats['weaknesses'] += len(weakness_records)
                if reference_records:
                    svc._upsert_references(reference_records)
                    stats['references'] += len(reference_records)
                if credit_records:
                    svc._upsert_credits(cve_ids, credit_records)
                    stats['credits'] += len(credit_records)
        except Exception as e:
            logger.error(f'reprocess_raw batch error: {e}')
            return jsonify({'error': str(e)}), 500

        page += 1

    return jsonify({'ok': True, 'stats': stats})


@nvd_bp.route('/api/stats')
@login_required
def stats():
    """API: Estatísticas de vulnerabilidades."""
    # Total por severidade
    severity_counts = db.session.query(
        Vulnerability.base_severity,
        db.func.count(Vulnerability.cve_id)
    ).group_by(Vulnerability.base_severity).all()
    
    # CVEs nas últimas 24h, 7 dias, 30 dias
    now = _now_utc_naive()
    
    last_24h = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(hours=24)
    ).count()
    
    last_7d = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(days=7)
    ).count()
    
    last_30d = Vulnerability.query.filter(
        Vulnerability.published_date >= now - timedelta(days=30)
    ).count()
    
    # Total CISA KEV
    cisa_kev_count = Vulnerability.query.filter(
        Vulnerability.is_in_cisa_kev.is_(True)
    ).count()

    # Top vendors
    # Usando raw SQL para JSONB array unnest (PostgreSQL)
    try:
        with db.engines['public'].connect() as conn:
            top_vendors_query = conn.execute(
                db.text("""
                    SELECT vendor, COUNT(*) as count
                    FROM vulnerabilities,
                         jsonb_array_elements_text(nvd_vendors_data) as vendor
                    GROUP BY vendor
                    ORDER BY count DESC
                    LIMIT 10
                """)
            ).fetchall()
        top_vendors = [{'vendor': row[0], 'count': row[1]} for row in top_vendors_query]
    except Exception:
        top_vendors = []

    return jsonify({
        'total': Vulnerability.query.count(),
        'by_severity': {
            (sev or 'NONE'): count for sev, count in severity_counts
        },
        'last_24h': last_24h,
        'last_7d': last_7d,
        'last_30d': last_30d,
        'cisa_kev': cisa_kev_count,
        'top_vendors': top_vendors
    })



@nvd_bp.route('/api/vendors')
@login_required
def list_vendors():
    """API: Listar vendors com contagem. Compatível com PostgreSQL e SQLite."""
    search = request.args.get('search', '')
    limit = min(request.args.get('limit', 50, type=int), 200)

    try:
        # Usa ORM para garantir o engine correto independente de fallback SQLite/PG
        rows = db.session.execute(
            db.select(Vulnerability.nvd_vendors_data).where(
                Vulnerability.nvd_vendors_data.isnot(None)
            )
        ).scalars().all()

        vendor_counts: dict = {}
        search_lower = search.lower()
        for raw in rows:
            if not raw:
                continue
            lst = raw if isinstance(raw, list) else (list(raw) if hasattr(raw, '__iter__') and not isinstance(raw, str) else [])
            for v in lst:
                if not v or not isinstance(v, str):
                    continue
                if search_lower and search_lower not in v.lower():
                    continue
                vendor_counts[v] = vendor_counts.get(v, 0) + 1

        vendors = sorted(
            [{'name': k, 'count': v} for k, v in vendor_counts.items()],
            key=lambda x: x['count'], reverse=True
        )[:limit]
    except Exception as e:
        logger.error(f'list_vendors error: {type(e).__name__}: {e}')
        vendors = []

    return jsonify({'vendors': vendors})


@nvd_bp.route('/api/products')
@login_required
def list_products():
    """API: Listar produtos (opcionalmente filtrado por vendor). Compatível com PostgreSQL e SQLite."""
    vendor = request.args.get('vendor')
    search = request.args.get('search', '')
    limit = min(request.args.get('limit', 50, type=int), 200)

    try:
        # Usa ORM para garantir o engine correto independente de fallback SQLite/PG
        q = db.select(Vulnerability.nvd_vendors_data, Vulnerability.nvd_products_data).where(
            Vulnerability.nvd_products_data.isnot(None)
        )
        if vendor:
            # Filtra linhas que contêm o vendor — cast para text para ilike funcionar
            q = q.where(
                db.cast(Vulnerability.nvd_vendors_data, db.Text).contains(vendor)
            )
        rows = db.session.execute(q).all()

        product_counts: dict = {}
        search_lower = search.lower()
        for vendors_raw, products_raw in rows:
            if not products_raw:
                continue
            # nvd_products_data pode ser dict {vendor: [products]} ou list
            if isinstance(products_raw, dict):
                if vendor:
                    # Apenas produtos do vendor especificado
                    prod_list = products_raw.get(vendor, [])
                    all_prods = prod_list if isinstance(prod_list, list) else [prod_list]
                else:
                    all_prods = []
                    for v_prods in products_raw.values():
                        if isinstance(v_prods, list):
                            all_prods.extend(v_prods)
                        elif v_prods:
                            all_prods.append(v_prods)
            elif isinstance(products_raw, list):
                all_prods = products_raw
            else:
                continue

            for p in all_prods:
                if not p or not isinstance(p, str):
                    continue
                if search_lower and search_lower not in p.lower():
                    continue
                product_counts[p] = product_counts.get(p, 0) + 1

        products = sorted(
            [{'name': k, 'count': v} for k, v in product_counts.items()],
            key=lambda x: x['count'], reverse=True
        )[:limit]
    except Exception as e:
        logger.error(f'list_products error: {type(e).__name__}: {e}')
        products = []

    return jsonify({'products': products})


@nvd_bp.route('/sync')
@login_required
@role_required('ADMIN', 'ANALYST')
def sync_page():
    """Página de gerenciamento de sincronização."""
    from app.models.system import SyncMetadata
    from datetime import datetime, timezone
    from flask import current_app

    # Prioriza SyncMetadata, depois config do Flask, depois env
    api_key = (
        SyncMetadata.get_value('nvd_api_key') or 
        current_app.config.get('NVD_API_KEY') or 
        current_app.config.get('nvd_api_key')
    )
    api_key_configured = bool(api_key)

    return render_template(
        'nvd/sync.html',
        api_key_configured=api_key_configured,
        now_utc=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    )


@nvd_bp.route('/api/vulnerabilities/<cve_id>/organizations', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def associate_organizations(cve_id):
    """API: Associar organizações a uma CVE."""
    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first_or_404()
    data = request.get_json() or {}
    
    if not data or 'organization_ids' not in data:
        return jsonify({'error': 'Missing organization_ids'}), 400
        
    org_ids = data['organization_ids']
    orgs = AssetCategory.query.filter(
        AssetCategory.id.in_(org_ids),
        AssetCategory.is_organization == True
    ).all()
    
    vuln.organizations = orgs
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'organizations': [o.to_dict() for o in vuln.organizations]
    })


@nvd_bp.route('/api/sync/status')
@login_required
def sync_status():
    """API: Status da sincronização."""
    service = NVDSyncService()
    return jsonify(service.get_progress())


from app.services.mitre.mitre_attack_service import MitreAttackService

@nvd_bp.route('/api/mitre-attack/status')
@login_required
def mitre_attack_status():
    """API: Status da sincronização do MITRE ATT&CK."""
    service = MitreAttackService()
    return jsonify(service.get_progress())

@nvd_bp.route('/api/mitre-attack/sync', methods=['POST'])
@login_required
@role_required('ADMIN')
def mitre_attack_sync():
    """API: Iniciar sincronização do MITRE ATT&CK."""
    from flask import current_app
    app = current_app._get_current_object()
    
    def run_sync(app_instance):
        with app_instance.app_context():
            service = MitreAttackService()
            service.sync_all_domains()
            
    import threading
    thread = threading.Thread(target=run_sync, args=(app,))
    thread.start()
    
    return jsonify({'message': 'Sincronização iniciada em segundo plano.'})

@nvd_bp.route('/api/mitre-attack/map', methods=['POST'])
@login_required
@role_required('ADMIN')
def mitre_attack_map():
    """API: Mapear CVEs para técnicas do ATT&CK."""
    from flask import current_app
    app = current_app._get_current_object()
    
    def run_map(app_instance):
        with app_instance.app_context():
            service = MitreAttackService()
            service.map_cves_to_techniques()
            
    import threading
    thread = threading.Thread(target=run_map, args=(app,))
    thread.start()
    
    return jsonify({'message': 'Mapeamento iniciado em segundo plano.'})


@nvd_bp.route('/api/sync/start', methods=['POST'])
@login_required
@role_required('ADMIN')
def start_sync():
    """API: Iniciar sincronização."""
    from app.services.nvd.nvd_sync_service import SyncMode
    from app.jobs import trigger_nvd_sync
    
    data = request.get_json() or {}
    mode = data.get('mode', 'incremental')
    
    try:
        sync_mode = SyncMode(mode)
    except ValueError:
        return jsonify({'error': f'Invalid mode: {mode}'}), 400
    
    if trigger_nvd_sync(mode=sync_mode.value):
        logger.info(
            f'NVD sync started by {current_user.username}: mode={mode}'
        )
        return jsonify({
            'message': f'Sync started in {mode} mode',
            'status': 'running'
        })

    return jsonify({'error': 'Sync already running'}), 409


@nvd_bp.route('/api/sync/keyword', methods=['POST'])
@login_required
@role_required('ADMIN')
def sync_by_keyword():
    """Sync NVD CVEs por keyword (ex: 'fortinet fortigate'). Síncrono, retorna stats."""
    data = request.get_json() or {}
    keyword = (data.get('keyword') or '').strip()
    if not keyword or len(keyword) < 3:
        return jsonify({'error': 'keyword obrigatório (min 3 chars)'}), 400

    service = NVDSyncService()

    try:
        with service.locked_operation(
            message=f'Sincronizando CVEs da NVD por keyword: {keyword}'
        ):
            service.db_service.reset_stats()
            all_vulns = service.fetcher.fetch_all_pages(
                keyword_search=keyword,
                progress_callback=service._fetch_progress_callback,
                cancel_callback=service._is_cancel_requested,
            )

            if service._is_cancel_requested():
                return jsonify({
                    'ok': False,
                    'keyword': keyword,
                    'fetched': len(all_vulns),
                    'error': 'Sync cancelled'
                }), 409

            service._update_progress(total=len(all_vulns), total_cves=len(all_vulns))

            if all_vulns:
                service.db_service.process_vulnerabilities(
                    all_vulns,
                    progress_callback=service._db_progress_callback,
                )

        return jsonify({
            'ok': True,
            'keyword': keyword,
            'fetched': len(all_vulns),
            'stats': service.db_service.stats
        })
    except NVDOperationAlreadyRunning as exc:
        return jsonify({'error': str(exc)}), 409
    except Exception as e:
        logger.error(f'sync_by_keyword error: {e}')
        return jsonify({'error': str(e)}), 500


@nvd_bp.route('/api/sync/cancel', methods=['POST'])
@login_required
@role_required('ADMIN')
def cancel_sync():
    """API: Cancelar sincronização."""
    service = NVDSyncService()

    if service.cancel_sync():
        logger.info(f'NVD sync cancelled by {current_user.username}')
        return jsonify({'message': 'Sync cancellation requested'})
    else:
        return jsonify({'error': 'No sync running'}), 400


@nvd_bp.route('/api/search')
@login_required
def search_cves():
    """API: Busca avançada de CVEs."""
    query_text = request.args.get('q', '')

    if not query_text or len(query_text) < 3:
        return jsonify(
            {'error': 'Query must be at least 3 characters'}
        ), 400

    # Busca em CVE ID e descrição
    results = Vulnerability.query.filter(
        db.or_(
            Vulnerability.cve_id.ilike(f'%{query_text}%'),
            Vulnerability.description.ilike(f'%{query_text}%')
        )
    ).order_by(Vulnerability.cvss_score.desc()).limit(20).all()

    return jsonify({
        'results': [
            {
                'cve_id': v.cve_id,
                'description': (
                    v.description[:200] + '...'
                    if len(v.description) > 200 else v.description
                ),
                'cvss_score': v.cvss_score,
                'severity': v.base_severity
            }
            for v in results
        ]
    })


@nvd_bp.route('/api/timeline')
@login_required
def timeline():
    """API: Timeline de CVEs por data."""
    days = request.args.get('days', 30, type=int)
    severity = request.args.get('severity')
    
    start_date = _now_utc_naive() - timedelta(days=days)
    
    query = db.session.query(
        db.func.date(Vulnerability.published_date).label('date'),
        db.func.count(Vulnerability.cve_id).label('count')
    ).filter(
        Vulnerability.published_date >= start_date
    )
    
    if severity:
        query = query.filter(Vulnerability.base_severity == severity.upper())
    
    results = query.group_by(
        db.func.date(Vulnerability.published_date)
    ).order_by('date').all()
    
    return jsonify({
        'timeline': [
            {'date': str(row.date), 'count': row.count}
            for row in results
        ]
    })


@nvd_bp.route('/api/import/bulk', methods=['POST'])
@login_required
@role_required('ADMIN')
def bulk_import():
    """API: Importar CVEs em massa (JSON)."""
    import threading

    from app.extensions.celery_extension import CELERY_AVAILABLE
    from app.tasks.nvd import bulk_import_task
    
    data = request.get_json() or {}
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({'error': 'File path required'}), 400

    testing = bool(current_app.config.get('TESTING', False))
    eager = bool(current_app.config.get('CELERY_TASK_ALWAYS_EAGER', False))
    can_dispatch = (
        CELERY_AVAILABLE
        and hasattr(bulk_import_task, 'delay')
        and not testing
        and not eager
    )

    if can_dispatch:
        sync_service = NVDSyncService()
        token = sync_service.reserve_sync(SyncMode.CUSTOM)
        if not token:
            return jsonify({'error': 'Sync already running'}), 409
        try:
            sync_service._update_progress(
                message=f'Importação em massa NVD enfileirada: {file_path}'
            )
            task = bulk_import_task.delay(file_path, lock_token=token)
            return jsonify({
                'message': 'Bulk import started',
                'task_id': task.id
            }), 202
        except Exception as exc:
            logger.error('Failed to dispatch NVD bulk import task: %s', exc)
            sync_service._update_progress(
                status='failed',
                error=str(exc),
                message=f'Falha ao enfileirar importação NVD: {exc}',
            )
            sync_service._release_sync_lock()

    app = current_app._get_current_object()

    def run_import(app_instance, path):
        with app_instance.app_context():
            try:
                bulk_import_task(path)
            except Exception as exc:
                logger.error('NVD bulk import fallback failed: %s', exc)

    thread = threading.Thread(
        target=run_import,
        args=(app, file_path),
        daemon=True,
    )
    thread.start()

    return jsonify({
        'message': 'Bulk import started',
        'task_id': None
    }), 202
