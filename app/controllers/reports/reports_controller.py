"""
SOC360 Reports Controller
Rotas para geração e gerenciamento de relatórios.
"""
import logging
import os
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, abort, send_file, current_app
from flask_login import login_required, current_user

from app.extensions import db
from app.models.monitoring import Report, RiskAssessment
from app.models.system import ReportType, ReportStatus
from app.utils.security import role_required


logger = logging.getLogger(__name__)


reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/')
@login_required
def index():
    """Lista de relatórios."""
    return render_template('reports/index.html')


@reports_bp.route('/api/list')
@login_required
def list_reports():
    """API: Listar relatórios."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    
    # Query base
    query = Report.query
    if not current_user.is_admin:
        query = query.filter(Report.user_id == current_user.id)
    
    # Filtros
    report_type = request.args.get('type')
    status = request.args.get('status')
    search = request.args.get('search')

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Report.title.ilike(search_term)) |
            (Report.description.ilike(search_term))
        )
    
    if report_type:
        try:
            # Tenta converter string para Enum (ex: EXECUTIVE -> ReportType.EXECUTIVE)
            # Se vier da URL como string simples, precisamos garantir match com Enum
            r_type = ReportType[report_type] if report_type in ReportType.__members__ else ReportType(report_type)
            query = query.filter(Report.report_type == r_type.value)
        except (ValueError, KeyError):
            pass
    
    if status:
        try:
            r_status = ReportStatus[status] if status in ReportStatus.__members__ else ReportStatus(status)
            query = query.filter(Report.status == r_status.value)
        except (ValueError, KeyError):
            pass
    
    # Ordenação
    query = query.order_by(Report.created_at.desc())
    
    # Paginação
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'items': [r.to_dict() for r in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@reports_bp.route('/api/generate', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def generate_report():
    """API: Gerar novo relatório."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    required_fields = ['title', 'report_type']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Validar tipo
    try:
        # Mapeia valores do form para Enum
        report_type_str = data['report_type']
        if report_type_str == 'EXECUTIVE_SUMMARY': report_type = ReportType.EXECUTIVE
        elif report_type_str == 'TECHNICAL_REPORT': report_type = ReportType.TECHNICAL
        elif report_type_str == 'RISK_ASSESSMENT': report_type = ReportType.RISK_ASSESSMENT  # Se não existir no Enum, dar erro? Enum tem EXECUTIVE, TECHNICAL, COMPLIANCE, INCIDENT, TREND
        elif report_type_str == 'COMPLIANCE_REPORT': report_type = ReportType.COMPLIANCE
        elif report_type_str == 'TREND_ANALYSIS': report_type = ReportType.TREND
        else:
            report_type = ReportType(report_type_str)
    except ValueError:
        return jsonify({'error': f'Invalid report type: {data["report_type"]}'}), 400
    
    # Criar relatório
    report = Report(
        title=data['title'],
        description=data.get('description'),
        report_type=report_type.value,
        filters=data.get('parameters', {}),
        user_id=current_user.id
    )
    
    db.session.add(report)
    db.session.commit()
    
    # Iniciar geração em background
    report.start_generation()
    from app.jobs import trigger_report_generation
    trigger_report_generation(report.id)
    
    logger.info(f'Report generation started: {report.title} by {current_user.username}')
    
    return jsonify({
        'message': 'Report generation started',
        'report': report.to_dict()
    }), 202


@reports_bp.route('/api/<int:report_id>')
@login_required
def get_report(report_id):
    """API: Obter detalhes de um relatório."""
    report = Report.query.get_or_404(report_id)
    
    if not current_user.is_admin and report.user_id != current_user.id:
        abort(403)
    
    return jsonify(report.to_dict())


@reports_bp.route('/api/<int:report_id>/download')
@login_required
def download_report(report_id):
    """Download do relatório em PDF (gerado sob demanda se necessário)."""
    report = Report.query.get_or_404(report_id)

    if not current_user.is_admin and report.user_id != current_user.id:
        abort(403)

    if report.status != ReportStatus.COMPLETED.value:
        return jsonify({'error': 'Report not ready'}), 400

    # Gera PDF sob demanda se ainda não existir no disco
    pdf_path = None
    if report.file_path and os.path.exists(report.file_path):
        pdf_path = report.file_path
    else:
        try:
            from app.services.reports import ensure_report_pdf
            pdf_path = ensure_report_pdf(report)
        except Exception as e:
            logger.error(f'Erro ao gerar PDF sob demanda para report {report_id}: {e}', exc_info=True)
            return jsonify({'error': f'Falha ao gerar PDF: {e}'}), 500

    if not pdf_path or not os.path.exists(pdf_path):
        return jsonify({'error': 'Report file not found'}), 404

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f'{report.title.replace(" ", "_")}.pdf',
        mimetype='application/pdf',
    )


@reports_bp.route('/api/<int:report_id>/share', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def share_report(report_id):
    """API: Gerar link de compartilhamento."""
    report = Report.query.get_or_404(report_id)
    
    if not current_user.is_admin and report.user_id != current_user.id:
        abort(403)
    
    data = request.get_json() or {}
    expires_hours = data.get('expires_hours')  # None = sem expiração

    token = report.generate_share_token(expires_hours=expires_hours)

    share_url = f"{request.host_url}reports/shared/{token}"

    return jsonify({
        'share_url': share_url,
        'expires_at': report.share_expires_at.isoformat() if report.share_expires_at else None
    })


@reports_bp.route('/shared/<token>')
def view_shared_report(token):
    """Visualizar relatório compartilhado."""
    report = Report.query.filter_by(share_token=token).first_or_404()
    
    if report.share_expires_at and report.share_expires_at < datetime.utcnow():
        abort(410)  # Gone - link expirado
    
    return render_template('reports/shared.html', report=report)


@reports_bp.route('/api/<int:report_id>', methods=['DELETE'])
@login_required
@role_required('ADMIN')
def delete_report(report_id):
    """API: Deletar relatório."""
    report = Report.query.get_or_404(report_id)
    
    # Remover arquivo se existir
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except Exception as e:
            logger.error(f'Error removing report file: {e}')
    
    db.session.delete(report)
    db.session.commit()
    
    logger.info(f'Report deleted: {report.title} by {current_user.username}')
    
    return jsonify({'message': 'Report deleted successfully'})


@reports_bp.route('/api/templates')
@login_required
def report_templates():
    """API: Templates de relatórios disponíveis."""
    templates = [
        {
            'name': 'Executive Summary',
            'report_type': 'EXECUTIVE_SUMMARY',
            'description': 'High-level overview of vulnerability landscape for executives',
            'parameters': {
                'include_charts': True,
                'time_range_days': 30
            }
        },
        {
            'name': 'Technical Report',
            'report_type': 'TECHNICAL_REPORT',
            'description': 'Detailed technical analysis of vulnerabilities',
            'parameters': {
                'include_cve_details': True,
                'include_mitigations': True
            }
        },
        {
            'name': 'Compliance Report',
            'report_type': 'COMPLIANCE_REPORT',
            'description': 'Compliance status against security frameworks',
            'parameters': {
                'framework': 'CIS',
                'include_remediation_status': True
            }
        },
        {
            'name': 'Risk Assessment',
            'report_type': 'RISK_ASSESSMENT',
            'description': 'Risk analysis with business impact assessment',
            'parameters': {
                'include_bia': True,
                'asset_groups': []
            }
        },
        {
            'name': 'Trend Analysis',
            'report_type': 'TREND_ANALYSIS',
            'description': 'Vulnerability trends over time',
            'parameters': {
                'time_range_days': 90,
                'group_by': 'severity'
            }
        }
    ]
    
    return jsonify({'templates': templates})


@reports_bp.route('/api/stats')
@login_required
def stats():
    """API: Estatísticas de relatórios."""
    query = Report.query
    if not current_user.is_admin:
        query = query.filter(Report.user_id == current_user.id)
    
    total = query.count()
    
    # Por status
    status_counts = db.session.query(
        Report.status,
        db.func.count(Report.id)
    )
    if not current_user.is_admin:
        status_counts = status_counts.filter(Report.user_id == current_user.id)
    status_counts = status_counts.group_by(Report.status).all()
    
    # Por tipo
    type_counts = db.session.query(
        Report.report_type,
        db.func.count(Report.id)
    )
    if not current_user.is_admin:
        type_counts = type_counts.filter(Report.user_id == current_user.id)
    type_counts = type_counts.group_by(Report.report_type).all()
    
    def _key(val):
        """Garante que o valor retornado é sempre a string simples do enum, não o repr."""
        if val is None:
            return 'UNKNOWN'
        return val.value if hasattr(val, 'value') else str(val)

    return jsonify({
        'total': total,
        'by_status': {_key(row[0]): row[1] for row in status_counts},
        'by_type': {_key(row[0]): row[1] for row in type_counts}
    })


@reports_bp.route('/<int:report_id>')
@login_required
def detail(report_id):
    """Detalhes de um relatório."""
    report = Report.query.get_or_404(report_id)
    
    if not current_user.is_admin and report.user_id != current_user.id:
        abort(403)
    
    return render_template('reports/detail.html', report=report)


def _generate_report_data(report: Report) -> None:
    """
    Gera dados do relatório — **escopado aos ativos cadastrados do usuário** e
    suas CVEs associadas (via AssetVulnerability).

    Todos os tipos de relatório (EXECUTIVE, TECHNICAL, RISK_ASSESSMENT,
    COMPLIANCE, TREND, INCIDENT) agora operam exclusivamente sobre o inventário
    do usuário — nenhum tipo consulta o universo global de CVEs.
    """
    from app.models.nvd import Vulnerability
    from app.models.inventory import Asset, AssetVulnerability
    from app.models.system.enums import VulnerabilityStatus
    from datetime import timedelta

    try:
        params = report.filters or {}
        time_range = int(params.get('time_range_days', 30))
        start_date = datetime.utcnow() - timedelta(days=time_range)

        # ------------------------------------------------------------------
        # Contexto base: ativos do usuário + suas CVEs associadas
        # ------------------------------------------------------------------
        assets = Asset.query.filter_by(owner_id=report.user_id).all()
        asset_ids = [a.id for a in assets]
        asset_by_id = {a.id: a for a in assets}

        # Pega todas as AssetVulnerability dos ativos + a Vulnerability linkada
        av_rows = []
        if asset_ids:
            av_rows = (
                db.session.query(AssetVulnerability, Vulnerability)
                .join(Vulnerability, AssetVulnerability.cve_id == Vulnerability.cve_id)
                .filter(AssetVulnerability.asset_id.in_(asset_ids))
                .all()
            )

        # Agrupa CVEs únicas (um mesmo CVE pode afetar vários ativos)
        unique_cves: dict = {}
        # Também guarda lista de ativos afetados por CVE
        cve_to_assets: dict = {}
        for av, vuln in av_rows:
            if vuln.cve_id not in unique_cves:
                unique_cves[vuln.cve_id] = vuln
                cve_to_assets[vuln.cve_id] = []
            cve_to_assets[vuln.cve_id].append({
                'asset_id': av.asset_id,
                'asset_name': asset_by_id.get(av.asset_id).name if asset_by_id.get(av.asset_id) else 'desconhecido',
                'status': av.status,
                'discovered_at': av.discovered_at.isoformat() if av.discovered_at else None,
            })

        vulns = list(unique_cves.values())

        def _severity_counts(filter_fn=None):
            buckets = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            for v in vulns:
                if filter_fn and not filter_fn(v):
                    continue
                buckets[v.base_severity or 'UNKNOWN'] = buckets.get(v.base_severity or 'UNKNOWN', 0) + 1
            return buckets

        def _short(desc, n=200):
            if not desc:
                return ''
            return (desc[:n] + '…') if len(desc) > n else desc

        data = {
            # metadados do inventário
            'total_assets': len(assets),
            'assets_with_vulns': sum(1 for a in assets if any(av.asset_id == a.id for av, _ in av_rows)),
            'scope': 'user_assets',
            # lista resumida dos ativos (até 50)
            'assets_overview': [
                {
                    'id': a.id,
                    'name': a.name,
                    'criticality': a.criticality,
                    'environment': a.environment,
                    'exposure': a.exposure,
                    'vulnerabilities': sum(1 for av, _ in av_rows if av.asset_id == a.id),
                }
                for a in assets[:50]
            ],
        }

        # Se não há ativos, preenche estrutura vazia e deixa a IA comentar
        if not assets:
            data['total_cves'] = 0
            data['by_severity'] = _severity_counts()
            data['empty_inventory'] = True
        else:
            data['total_cves'] = len(vulns)
            data['by_severity'] = _severity_counts()

        # ------------------------------------------------------------------
        # EXECUTIVE — visão de negócio do inventário
        # ------------------------------------------------------------------
        if report.report_type == ReportType.EXECUTIVE.value:
            period_vulns = [v for v in vulns if v.published_date and v.published_date >= start_date]
            data['recent_cves'] = len(period_vulns)
            data['by_severity_period'] = _severity_counts(
                lambda v: v.published_date and v.published_date >= start_date
            )
            data['cisa_kev'] = sum(1 for v in vulns if v.is_in_cisa_kev)

            # Top 5 CVEs críticas mais recentes que afetam o inventário
            critical_recent = sorted(
                [v for v in vulns if v.base_severity == 'CRITICAL'],
                key=lambda v: v.published_date or datetime.min,
                reverse=True,
            )[:5]
            data['critical_recent'] = [
                {
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'published': v.published_date.isoformat() if v.published_date else None,
                    'description': _short(v.description, 200),
                    'affected_assets': cve_to_assets.get(v.cve_id, []),
                }
                for v in critical_recent
            ]

        # ------------------------------------------------------------------
        # TECHNICAL — detalhamento técnico das CVEs do inventário
        # ------------------------------------------------------------------
        elif report.report_type == ReportType.TECHNICAL.value:
            period_vulns = [v for v in vulns if v.published_date and v.published_date >= start_date]
            data['period_cves'] = len(period_vulns)
            data['by_severity'] = _severity_counts(
                lambda v: v.published_date and v.published_date >= start_date
            )
            data['cisa_kev'] = sum(1 for v in period_vulns if v.is_in_cisa_kev)
            data['with_patch'] = sum(1 for v in period_vulns if v.patch_available)
            data['with_exploit'] = sum(1 for v in period_vulns if v.exploit_available)

            # Top 10 CVEs CRITICAL/HIGH com exploit que afetam o inventário
            exploitable = sorted(
                [v for v in vulns
                 if v.exploit_available and v.base_severity in ('CRITICAL', 'HIGH')],
                key=lambda v: v.cvss_score or 0,
                reverse=True,
            )[:10]
            data['exploitable_top'] = [
                {
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'base_severity': v.base_severity,
                    'description': _short(v.description, 200),
                    'patch_available': v.patch_available,
                    'is_in_cisa_kev': v.is_in_cisa_kev,
                    'affected_assets': cve_to_assets.get(v.cve_id, []),
                }
                for v in exploitable
            ]

        # ------------------------------------------------------------------
        # RISK_ASSESSMENT — avaliação de risco por ativo do inventário
        # ------------------------------------------------------------------
        elif report.report_type == ReportType.RISK_ASSESSMENT.value:
            high_risk_assets = []
            all_scored_assets = []
            for asset in assets:
                asset_avs = [av for av, _ in av_rows if av.asset_id == asset.id]
                vuln_count = len(asset_avs)
                max_cvss = 0.0
                for av, vuln in av_rows:
                    if av.asset_id == asset.id and (vuln.cvss_score or 0) > max_cvss:
                        max_cvss = vuln.cvss_score or 0.0
                # score contextual usando calculate_risk_score(max_cvss)
                try:
                    risk_score = asset.calculate_risk_score(max_cvss) if hasattr(asset, 'calculate_risk_score') else max_cvss
                except Exception:
                    risk_score = max_cvss
                rec = {
                    'id': asset.id,
                    'name': asset.name,
                    'criticality': asset.criticality,
                    'environment': asset.environment,
                    'exposure': asset.exposure,
                    'risk_score': round(float(risk_score or 0), 2),
                    'max_cvss': round(float(max_cvss or 0), 2),
                    'vulnerabilities': vuln_count,
                }
                all_scored_assets.append(rec)
                if vuln_count > 0 and (risk_score or 0) > 7.0:
                    high_risk_assets.append(rec)

            high_risk_assets.sort(key=lambda x: x['risk_score'], reverse=True)
            all_scored_assets.sort(key=lambda x: x['risk_score'], reverse=True)
            data['high_risk_assets'] = high_risk_assets
            data['scored_assets'] = all_scored_assets[:30]

        # ------------------------------------------------------------------
        # COMPLIANCE — status de remediação das AssetVulnerabilities do usuário
        # ------------------------------------------------------------------
        elif report.report_type == ReportType.COMPLIANCE.value:
            status_counts = {
                VulnerabilityStatus.OPEN.value: 0,
                VulnerabilityStatus.IN_PROGRESS.value: 0,
                VulnerabilityStatus.MITIGATED.value: 0,
                VulnerabilityStatus.ACCEPTED.value: 0,
                VulnerabilityStatus.RESOLVED.value: 0,
            }
            for av, _ in av_rows:
                if av.status in status_counts:
                    status_counts[av.status] += 1
            total_items = sum(status_counts.values())
            remediation_rate = round(
                (status_counts[VulnerabilityStatus.MITIGATED.value]
                 + status_counts[VulnerabilityStatus.RESOLVED.value]) / total_items * 100, 1
            ) if total_items > 0 else 0.0

            data['total_open'] = status_counts[VulnerabilityStatus.OPEN.value]
            data['total_in_progress'] = status_counts[VulnerabilityStatus.IN_PROGRESS.value]
            data['total_mitigated'] = status_counts[VulnerabilityStatus.MITIGATED.value]
            data['total_accepted'] = status_counts[VulnerabilityStatus.ACCEPTED.value]
            data['total_resolved'] = status_counts[VulnerabilityStatus.RESOLVED.value]
            data['remediation_rate_pct'] = remediation_rate

            # amostra das CVEs em aberto (mais graves) com ativos afetados
            open_cve_ids = {
                av.cve_id for av, _ in av_rows
                if av.status == VulnerabilityStatus.OPEN.value
            }
            open_cves_sorted = sorted(
                [v for v in vulns if v.cve_id in open_cve_ids],
                key=lambda v: v.cvss_score or 0,
                reverse=True,
            )[:10]
            data['open_cves_sample'] = [
                {
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'base_severity': v.base_severity,
                    'status': VulnerabilityStatus.OPEN.value,
                    'affected_assets': cve_to_assets.get(v.cve_id, []),
                }
                for v in open_cves_sorted
            ]

        # ------------------------------------------------------------------
        # TREND — timeline das CVEs do inventário
        # ------------------------------------------------------------------
        elif report.report_type == ReportType.TREND.value:
            timeline: dict = {}
            period_vulns = [v for v in vulns if v.published_date and v.published_date >= start_date]
            for v in period_vulns:
                month = v.published_date.strftime('%Y-%m') if v.published_date else 'UNKNOWN'
                sev = v.base_severity or 'UNKNOWN'
                timeline.setdefault(month, {})
                timeline[month][sev] = timeline[month].get(sev, 0) + 1

            data['timeline'] = dict(sorted(timeline.items()))
            data['total_period'] = len(period_vulns)
            data['by_severity'] = _severity_counts(
                lambda v: v.published_date and v.published_date >= start_date
            )

        # ------------------------------------------------------------------
        # INCIDENT — CVEs urgentes que afetam o inventário
        # ------------------------------------------------------------------
        elif report.report_type == ReportType.INCIDENT.value:
            incident_vulns = sorted(
                [v for v in vulns
                 if v.base_severity in ('CRITICAL', 'HIGH')
                 and v.published_date and v.published_date >= start_date],
                key=lambda v: v.cvss_score or 0,
                reverse=True,
            )[:20]

            data['incident_cves'] = [
                {
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'base_severity': v.base_severity,
                    'published': v.published_date.isoformat() if v.published_date else None,
                    'is_in_cisa_kev': v.is_in_cisa_kev,
                    'exploit_available': v.exploit_available,
                    'description': _short(v.description, 300),
                    'affected_assets': cve_to_assets.get(v.cve_id, []),
                }
                for v in incident_vulns
            ]
            data['total_incident_cves'] = len(incident_vulns)
            data['critical_count'] = sum(1 for v in incident_vulns if v.base_severity == 'CRITICAL')
            data['high_count'] = sum(1 for v in incident_vulns if v.base_severity == 'HIGH')

        # ------------------------------------------------------------------
        # Persist raw aggregated data first (so UI can show partial data
        # even if the AI call fails)
        # ------------------------------------------------------------------
        report.data = data
        db.session.commit()

        # ------------------------------------------------------------------
        # AI-generated narrative — single complete prompt per report type
        # ------------------------------------------------------------------
        try:
            from app.services.reports import generate_ai_report
            ai_result = generate_ai_report(
                report_type=report.report_type,
                data=data,
                period_days=time_range,
            )
            report.set_ai_content(
                summary=ai_result['markdown'],
                recommendations=ai_result['recommendations'],
                model_used=ai_result.get('model'),
            )
            data['ai_status'] = 'completed'
            data['ai_model'] = ai_result.get('model')
            report.data = data
            db.session.commit()
            logger.info(
                'AI content saved for report %s (%s) — model=%s',
                report.id, report.report_type, ai_result.get('model')
            )
        except Exception as ai_err:
            # AI is best-effort — a failure shouldn't fail the whole report.
            data['ai_status'] = 'skipped'
            data['ai_error'] = str(ai_err)[:500]
            report.data = data
            db.session.commit()
            logger.warning(
                'AI generation skipped for report %s (%s): %s',
                report.id, report.report_type, ai_err
            )

        # ------------------------------------------------------------------
        # Gera PDF imediatamente (cache pronto para download posterior)
        # ------------------------------------------------------------------
        try:
            from app.services.reports import generate_report_pdf
            generate_report_pdf(report)
        except Exception as pdf_err:
            logger.warning(
                'PDF pre-render falhou para report %s (%s): %s',
                report.id, report.report_type, pdf_err
            )

        # ------------------------------------------------------------------
        # Mark as COMPLETED
        # ------------------------------------------------------------------
        report.complete_generation()
        db.session.commit()

    except Exception as e:
        logger.error(f'Report generation failed: {e}', exc_info=True)
        try:
            report.status = ReportStatus.FAILED.value   # .value corrigido
            report.error_message = str(e)
            report.data = {'error': str(e)}
            db.session.commit()
        except Exception as db_err:
            logger.error(f'Failed to persist report failure: {db_err}', exc_info=True)
            db.session.rollback()
