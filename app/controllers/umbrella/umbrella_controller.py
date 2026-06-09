"""
Cisco Umbrella integration blueprint.

Provides a dashboard for generating Umbrella reports with mock or real API data.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

from flask import (
    Blueprint, render_template, request, jsonify, send_file, current_app
)
from flask_login import login_required, current_user

from app.extensions.db import db
from app.models.umbrella import (
    UmbrellaOrganization,
    UmbrellaNetwork,
    UmbrellaRoamingComputer,
    UmbrellaVirtualAppliance,
    UmbrellaReportData,
    UmbrellaGeneratedReport,
)
from app.services.umbrella import UmbrellaAPIClient, generate_full_report, UmbrellaConfigService
from app.utils.security import role_required, admin_required

logger = logging.getLogger(__name__)

umbrella_bp = Blueprint(
    'umbrella',
    __name__,
    url_prefix='/integrations/umbrella',
)


def _get_client():
    """Factory para o cliente Umbrella baseado nas configurações do app."""
    api_key, api_secret = UmbrellaConfigService.get_runtime_credentials()
    if api_key and api_secret:
        client = UmbrellaAPIClient(api_key=api_key, api_secret=api_secret, use_mock=False)
    else:
        use_mock = current_app.config.get('UMBRELLA_USE_MOCK', True)
        client = UmbrellaAPIClient(use_mock=use_mock)
    client.authenticate()
    return client


def _load_mock_data_if_empty():
    """Carrega dados mock se não houver organizações no banco."""
    if UmbrellaOrganization.query.first() is None:
        logger.info("Loading mock Umbrella data...")
        mock_orgs = [
            {"organizationId": 1001, "organizationName": "Empresa ABC Tecnologia", "status": "active"},
            {"organizationId": 1002, "organizationName": "Indústria XYZ Ltda", "status": "active"},
            {"organizationId": 1003, "organizationName": "Banco Financeiro SA", "status": "active"},
            {"organizationId": 1004, "organizationName": "Hospital Central", "status": "active"},
            {"organizationId": 1005, "organizationName": "Varejo Global", "status": "active"},
        ]
        networks_data = {
            1001: [
                {"networkId": 101, "name": "Rede Matriz", "ipAddress": "192.168.1.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 102, "name": "Rede Filial SP", "ipAddress": "10.0.1.0/29", "status": "active", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 103, "name": "Rede Filial RJ", "ipAddress": "10.0.2.0/29", "status": "inactive", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 104, "name": "Rede DR", "ipAddress": "172.16.0.0/24", "status": "inactive", "isDynamic": False, "primaryPolicy": "Default Policy"},
            ],
            1002: [
                {"networkId": 201, "name": "Produção", "ipAddress": "192.168.10.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 202, "name": "Administrativo", "ipAddress": "192.168.20.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
            ],
            1003: [
                {"networkId": 301, "name": "Data Center Principal", "ipAddress": "10.10.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "Strict Policy"},
                {"networkId": 302, "name": "Agências", "ipAddress": "10.20.0.0/16", "status": "active", "isDynamic": True, "primaryPolicy": "Default Policy"},
                {"networkId": 303, "name": "ATMs", "ipAddress": "10.30.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "ATM Policy"},
            ],
            1004: [
                {"networkId": 401, "name": "Rede Administrativa", "ipAddress": "192.168.50.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 402, "name": "Rede Médica", "ipAddress": "192.168.100.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Healthcare Policy"},
            ],
            1005: [
                {"networkId": 501, "name": "Sede", "ipAddress": "10.100.0.0/16", "status": "active", "isDynamic": False, "primaryPolicy": "Default Policy"},
                {"networkId": 502, "name": "Lojas", "ipAddress": "10.200.0.0/16", "status": "active", "isDynamic": True, "primaryPolicy": "Retail Policy"},
                {"networkId": 503, "name": "E-commerce", "ipAddress": "10.150.0.0/24", "status": "active", "isDynamic": False, "primaryPolicy": "Web Policy"},
            ],
        }
        roaming_data = {
            1001: [
                {"deviceId": "dev001", "name": "LAPTOP-EXEC-01", "status": "active", "lastSync": "2025-04-10T08:00:00Z", "osVersion": "Windows 11"},
                {"deviceId": "dev002", "name": "LAPTOP-DEV-02", "status": "active", "lastSync": "2025-04-10T09:30:00Z", "osVersion": "Windows 11"},
                {"deviceId": "dev003", "name": "MACBOOK-DESIGN", "status": "inactive", "lastSync": "2025-03-01T10:00:00Z", "osVersion": "macOS 14"},
            ],
            1002: [],
            1003: [
                {"deviceId": "bank001", "name": "NOTEBOOK-GERENTE", "status": "active", "lastSync": "2025-04-11T07:00:00Z", "osVersion": "Windows 11"},
            ],
            1004: [
                {"deviceId": "hosp001", "name": "LAPTOP-MEDICO-01", "status": "active", "lastSync": "2025-04-10T06:00:00Z", "osVersion": "Windows 10"},
                {"deviceId": "hosp002", "name": "LAPTOP-MEDICO-02", "status": "active", "lastSync": "2025-04-10T07:00:00Z", "osVersion": "Windows 10"},
            ],
            1005: [
                {"deviceId": "var001", "name": "TABLET-VENDEDOR", "status": "active", "lastSync": "2025-04-10T08:00:00Z", "osVersion": "Windows 11"},
            ],
        }
        va_data = {
            1001: [
                {"vaId": "va-001", "name": "VA-Primary", "status": "active", "ipAddress": "192.168.1.10"},
                {"vaId": "va-002", "name": "VA-Secondary", "status": "inactive", "ipAddress": "192.168.1.11"},
            ],
            1002: [
                {"vaId": "va-ind-01", "name": "VA-Producao", "status": "active", "ipAddress": "192.168.10.10"},
            ],
            1003: [
                {"vaId": "va-bank-01", "name": "VA-DC-Primary", "status": "active", "ipAddress": "10.10.0.10"},
                {"vaId": "va-bank-02", "name": "VA-DC-Secondary", "status": "active", "ipAddress": "10.10.0.11"},
            ],
            1004: [],
            1005: [
                {"vaId": "va-var-01", "name": "VA-Sede", "status": "active", "ipAddress": "10.100.0.10"},
            ],
        }
        
        try:
            for org in mock_orgs:
                org_id = org['organizationId']
                new_org = UmbrellaOrganization(
                    organization_id=org_id,
                    organization_name=org['organizationName'],
                    status=org['status']
                )
                db.session.add(new_org)
                
                # Add networks
                for net in networks_data.get(org_id, []):
                    db.session.add(UmbrellaNetwork(
                        organization_id=org_id,
                        network_id=net.get('networkId'),
                        name=net.get('name'),
                        ip_address=net.get('ipAddress'),
                        status=net.get('status'),
                        is_dynamic=net.get('isDynamic', False),
                        primary_policy=net.get('primaryPolicy')
                    ))
                
                # Add roaming computers
                for comp in roaming_data.get(org_id, []):
                    last_sync = None
                    if comp.get('lastSync'):
                        try:
                            last_sync = datetime.fromisoformat(comp['lastSync'].replace('Z', '+00:00'))
                        except Exception:
                            pass
                    db.session.add(UmbrellaRoamingComputer(
                        organization_id=org_id,
                        device_id=comp.get('deviceId'),
                        name=comp.get('name'),
                        status=comp.get('status'),
                        last_sync=last_sync,
                        os_version=comp.get('osVersion')
                    ))
                
                # Add virtual appliances
                for va in va_data.get(org_id, []):
                    db.session.add(UmbrellaVirtualAppliance(
                        organization_id=org_id,
                        va_id=va.get('vaId'),
                        name=va.get('name'),
                        status=va.get('status'),
                        ip_address=va.get('ipAddress')
                    ))
            
            db.session.commit()
            logger.info(f"Loaded {len(mock_orgs)} mock organizations")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error loading mock data: {e}")


# =============================================================================
# PAGES
# =============================================================================

@umbrella_bp.route('/')
@login_required
def dashboard():
    """Umbrella dashboard with organizations and report generation."""
    # Load mock data if database is empty
    _load_mock_data_if_empty()
    return render_template('umbrella/dashboard.html')


# =============================================================================
# API — ORGANIZATIONS
# =============================================================================

@umbrella_bp.route('/api/organizations')
@login_required
def api_organizations():
    orgs = UmbrellaOrganization.query.order_by(UmbrellaOrganization.organization_name).all()
    return jsonify([o.to_dict() for o in orgs])


@umbrella_bp.route('/organization/<int:org_id>')
@login_required
def organization_detail(org_id):
    """Organization detail page."""
    org = UmbrellaOrganization.query.filter_by(organization_id=org_id).first_or_404()
    networks = UmbrellaNetwork.query.filter_by(organization_id=org_id).all()
    roaming = UmbrellaRoamingComputer.query.filter_by(organization_id=org_id).all()
    vas = UmbrellaVirtualAppliance.query.filter_by(organization_id=org_id).all()
    reports = UmbrellaGeneratedReport.query.filter_by(organization_id=org_id).order_by(UmbrellaGeneratedReport.created_at.desc()).all()
    return render_template('umbrella/organization_detail.html',
                         org=org,
                         networks=networks,
                         roaming=roaming,
                         vas=vas,
                         reports=reports)


@umbrella_bp.route('/api/organization/<int:org_id>')
@login_required
def api_organization_detail(org_id):
    org = UmbrellaOrganization.query.filter_by(organization_id=org_id).first_or_404()
    networks = UmbrellaNetwork.query.filter_by(organization_id=org_id).all()
    roaming = UmbrellaRoamingComputer.query.filter_by(organization_id=org_id).all()
    vas = UmbrellaVirtualAppliance.query.filter_by(organization_id=org_id).all()
    return jsonify({
        'organization': org.to_dict(),
        'networks': [n.to_dict() for n in networks],
        'roaming_computers': [r.to_dict() for r in roaming],
        'virtual_appliances': [v.to_dict() for v in vas],
    })


# =============================================================================
# API — REFRESH DATA
# =============================================================================

@umbrella_bp.route('/api/refresh-data')
@login_required
@role_required('ADMIN', 'ANALYST')
def api_refresh_data():
    try:
        client = _get_client()
        orgs = client.get_organizations()
        for org in orgs:
            org_id = org['organizationId']
            org_name = org['organizationName']
            status = org.get('status', 'active')

            # Upsert organization
            existing = UmbrellaOrganization.query.filter_by(organization_id=org_id).first()
            if existing:
                existing.organization_name = org_name
                existing.status = status
                existing.updated_at = datetime.utcnow()
            else:
                existing = UmbrellaOrganization(
                    organization_id=org_id,
                    organization_name=org_name,
                    status=status,
                )
                db.session.add(existing)
            db.session.flush()

            client.set_organization(org_id)

            # Networks
            networks = client.get_networks()
            UmbrellaNetwork.query.filter_by(organization_id=org_id).delete()
            for net in networks:
                db.session.add(UmbrellaNetwork(
                    organization_id=org_id,
                    network_id=net.get('networkId'),
                    name=net.get('name'),
                    ip_address=net.get('ipAddress'),
                    status=net.get('status'),
                    is_dynamic=net.get('isDynamic', False),
                    primary_policy=net.get('primaryPolicy'),
                ))

            # Roaming computers
            roaming = client.get_roaming_computers()
            UmbrellaRoamingComputer.query.filter_by(organization_id=org_id).delete()
            for comp in roaming:
                last_sync = None
                if comp.get('lastSync'):
                    try:
                        last_sync = datetime.fromisoformat(comp['lastSync'].replace('Z', '+00:00'))
                    except Exception:
                        pass
                db.session.add(UmbrellaRoamingComputer(
                    organization_id=org_id,
                    device_id=comp.get('deviceId'),
                    name=comp.get('name'),
                    status=comp.get('status'),
                    last_sync=last_sync,
                    os_version=comp.get('osVersion'),
                ))

            # Virtual appliances
            vas = client.get_virtual_appliances()
            UmbrellaVirtualAppliance.query.filter_by(organization_id=org_id).delete()
            for va in vas:
                db.session.add(UmbrellaVirtualAppliance(
                    organization_id=org_id,
                    va_id=va.get('vaId'),
                    name=va.get('name'),
                    status=va.get('status'),
                    ip_address=va.get('ipAddress'),
                ))

        db.session.commit()
        return jsonify({'success': True, 'message': f'Refreshed data for {len(orgs)} organizations'})
    except Exception as e:
        db.session.rollback()
        logger.exception('Umbrella refresh-data failed')
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# API — GENERATE REPORT
# =============================================================================

@umbrella_bp.route('/api/generate-report', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def api_generate_report():
    data = request.get_json()
    org_id = data.get('organization_id')
    org_name = data.get('organization_name')
    period_start = data.get('period_start')
    period_end = data.get('period_end')

    if not all([org_id, org_name, period_start, period_end]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        start_date = datetime.strptime(period_start, '%Y-%m-%d')
        end_date = datetime.strptime(period_end, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format, expected YYYY-MM-DD'}), 400

    try:
        client = _get_client()
        client.set_organization(org_id)
        report_data = client.collect_all_report_data(start_date, end_date)

        # Persist report data cache
        for data_type, payload in report_data.items():
            existing = UmbrellaReportData.query.filter_by(
                organization_id=org_id,
                period_start=start_date,
                period_end=end_date,
                data_type=data_type,
            ).first()
            if existing:
                existing.data_json = payload
                existing.updated_at = datetime.utcnow()
            else:
                db.session.add(UmbrellaReportData(
                    organization_id=org_id,
                    period_start=start_date,
                    period_end=end_date,
                    data_type=data_type,
                    data_json=payload,
                ))
        db.session.commit()

        reports_dir = current_app.config.get('UMBRELLA_REPORTS_DIR', os.path.join(current_app.config.get('REPORTS_DIR', '/app/reports'), 'umbrella'))
        pdf_temp_dir = os.path.join(reports_dir, 'temp')
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(pdf_temp_dir, exist_ok=True)

        result = generate_full_report(
            org_id, org_name, period_start, period_end,
            report_data, reports_dir, pdf_temp_dir
        )

        status = 'completed' if result.get('pdf_filename') else 'docx_only'
        gen = UmbrellaGeneratedReport(
            organization_id=org_id,
            organization_name=org_name,
            period_start=start_date,
            period_end=end_date,
            file_path=result.get('docx') or result.get('pdf'),
            docx_filename=result.get('docx_filename'),
            pdf_filename=result.get('pdf_filename'),
            status=status,
        )
        db.session.add(gen)
        db.session.commit()

        return jsonify({
            'success': True,
            'docx_url': f"/integrations/umbrella/download/{result['docx_filename']}" if result.get('docx_filename') else None,
            'pdf_url': f"/integrations/umbrella/download/{result['pdf_filename']}" if result.get('pdf_filename') else None,
            'message': 'Report generated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.exception('Umbrella generate-report failed')
        return jsonify({'error': str(e)}), 500


# =============================================================================
# API — REPORTS LIST
# =============================================================================

@umbrella_bp.route('/api/reports')
@login_required
def api_reports():
    org_id = request.args.get('organization_id', type=int)
    query = UmbrellaGeneratedReport.query.order_by(UmbrellaGeneratedReport.created_at.desc())
    if org_id:
        query = query.filter_by(organization_id=org_id)
    reports = query.all()
    return jsonify([r.to_dict() for r in reports])


# =============================================================================
# DOWNLOAD
# =============================================================================

@umbrella_bp.route('/download/<filename>')
@login_required
def download_file(filename):
    # Reject any path separators or traversal sequences before building the path
    if os.sep in filename or (os.altsep and os.altsep in filename) or '..' in filename:
        return jsonify({'error': 'Invalid filename'}), 400
    reports_dir = current_app.config.get(
        'UMBRELLA_REPORTS_DIR',
        os.path.join(current_app.config.get('REPORTS_DIR', '/app/reports'), 'umbrella'),
    )
    file_path = os.path.realpath(os.path.join(reports_dir, filename))
    safe_base = os.path.realpath(reports_dir)
    if not file_path.startswith(safe_base + os.sep) and file_path != safe_base:
        return jsonify({'error': 'Invalid filename'}), 400
    if not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404
    mimetype = (
        'application/pdf'
        if filename.endswith('.pdf')
        else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )
    return send_file(file_path, as_attachment=True, mimetype=mimetype)


# =============================================================================
# API — CONFIGURATION (admin only)
# =============================================================================

@umbrella_bp.route('/api/config/status')
@login_required
@admin_required
def api_config_status():
    """Return masked Umbrella credential status."""
    return jsonify(UmbrellaConfigService.status())


@umbrella_bp.route('/api/config/credentials', methods=['POST'])
@login_required
@admin_required
def api_config_save():
    """Save/update encrypted Umbrella API credentials."""
    payload = request.get_json(silent=True) or {}
    api_key    = (payload.get('api_key') or '').strip()
    api_secret = (payload.get('api_secret') or '').strip()
    try:
        status = UmbrellaConfigService.save_credentials(api_key, api_secret)
        return jsonify({'message': 'Credenciais Cisco Umbrella salvas com sucesso.', 'status': status})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        logger.exception('Umbrella credentials save failed')
        return jsonify({'error': 'Erro ao salvar credenciais Umbrella.'}), 500


@umbrella_bp.route('/api/config/credentials', methods=['DELETE'])
@login_required
@admin_required
def api_config_remove():
    """Remove encrypted Umbrella credentials stored in DB."""
    status = UmbrellaConfigService.remove_credentials()
    return jsonify({'message': 'Credenciais Umbrella removidas do armazenamento interno.', 'status': status})


@umbrella_bp.route('/api/config/test', methods=['POST'])
@login_required
@admin_required
def api_config_test():
    """Test Umbrella API connectivity with configured or supplied credentials."""
    payload = request.get_json(silent=True) or {}
    api_key    = (payload.get('api_key') or '').strip() or None
    api_secret = (payload.get('api_secret') or '').strip() or None
    result = UmbrellaConfigService.test_connection(api_key, api_secret)
    return jsonify(result), (200 if result.get('ok') else 400)