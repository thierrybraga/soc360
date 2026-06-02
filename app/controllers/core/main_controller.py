"""
SOC360 Core Controller
Rotas principais: home, dashboard, loading.
"""
import logging

from flask import Blueprint, render_template, redirect, url_for, jsonify, flash, request, current_app, session
from flask_login import login_required, current_user

from app.models.auth import User

logger = logging.getLogger(__name__)
from app.models.system import SyncMetadata
from app.extensions import db
from app.forms.auth_forms import ProfileForm, ChangePasswordForm, ApiKeyForm, TacacsConfigForm
from app.utils.security import admin_required


core_bp = Blueprint('core', __name__)


@core_bp.route('/')
def index():
    """
    Rota raiz.
    Redireciona para init-root se nenhum usuário ativo,
    caso contrário para dashboard.
    """
    # Verificar se existe algum usuário ativo
    active_users = User.query.filter_by(is_active=True).count()

    if active_users == 0:
        # Primeiro acesso - redirecionar para criar admin
        return redirect(url_for('auth.init_root'))

    # Usuário logado - dashboard
    if current_user.is_authenticated:
        return redirect(url_for('core.dashboard'))

    # Não logado - login
    return redirect(url_for('auth.login'))


@core_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Dashboard principal com visão geral.
    O carregamento de dados detalhados é feito via AJAX no front-end.
    """
    return render_template('core/dashboard.html')


@core_bp.route('/loading')
def loading():
    """
    Página de loading (Redirecionada para Sync).
    Consolidada com a página de gerenciamento de sincronização.
    """
    return redirect(url_for('nvd.sync_page'))


@core_bp.route('/health')
def health_check():
    """Health check endpoint para Docker/Kubernetes."""
    health = {
        'status': 'healthy',
        'database': 'unknown',
        'redis': 'unknown',
        'sync': 'unknown'
    }

    # Verificar banco de dados
    try:
        db.session.execute(db.text('SELECT 1'))
        health['database'] = 'connected'
    except Exception as e:
        health['database'] = f'error: {str(e)}'
        health['status'] = 'degraded'

    # Verificar Redis
    try:
        from app.services.core import RedisCacheService
        cache = RedisCacheService()
        if cache.ping():
            health['redis'] = 'connected'
        else:
            health['redis'] = 'disconnected'
            health['status'] = 'degraded'
    except Exception as e:
        health['redis'] = f'error: {str(e)}'
        health['status'] = 'degraded'

    # Status do sync
    health['sync'] = SyncMetadata.get('nvd_sync_progress_status', 'unknown')

    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code


@core_bp.route('/about')
def about():
    """Página sobre o sistema."""
    return render_template('pages/about.html')


@core_bp.route('/settings/api/openai-key', methods=['GET'])
@core_bp.route('/api/v1/admin/openai-key', methods=['GET'])
@login_required
@admin_required
def openai_key_status():
    """Admin API: return masked OpenAI key status only."""
    from app.services.core.openai_config_service import OpenAIConfigService
    return jsonify(OpenAIConfigService.status())


@core_bp.route('/settings/api/openai-key', methods=['POST'])
@core_bp.route('/api/v1/admin/openai-key', methods=['POST'])
@login_required
@admin_required
def openai_key_save():
    """Admin API: save/update encrypted OpenAI key."""
    from app.services.core.openai_config_service import OpenAIConfigService

    payload = request.get_json(silent=True) or {}
    api_key = (payload.get('api_key') or '').strip()
    try:
        status = OpenAIConfigService.save_key(api_key)
        return jsonify({
            'message': 'Chave OpenAI salva com sucesso.',
            'status': status,
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        logger.exception('OpenAI key save failed')
        return jsonify({'error': 'Erro ao salvar chave OpenAI.'}), 500


@core_bp.route('/settings/api/openai-key/test', methods=['POST'])
@core_bp.route('/api/v1/admin/openai-key/test', methods=['POST'])
@login_required
@admin_required
def openai_key_test():
    """Admin API: test configured OpenAI key or supplied unsaved key."""
    from app.services.core.openai_config_service import OpenAIConfigService

    payload = request.get_json(silent=True) or {}
    api_key = (payload.get('api_key') or '').strip() or None
    if api_key and not OpenAIConfigService.validate_key_format(api_key):
        return jsonify({
            'ok': False,
            'message': 'Formato de chave OpenAI inválido.',
        }), 400

    result = OpenAIConfigService.test_connection(api_key)
    status_code = 200 if result.get('ok') else 400
    return jsonify(result), status_code


@core_bp.route('/settings/api/openai-key', methods=['DELETE'])
@core_bp.route('/api/v1/admin/openai-key', methods=['DELETE'])
@login_required
@admin_required
def openai_key_delete():
    """Admin API: remove encrypted OpenAI key stored in DB."""
    from app.services.core.openai_config_service import OpenAIConfigService

    status = OpenAIConfigService.remove_key()
    return jsonify({
        'message': 'Chave OpenAI removida do armazenamento interno.',
        'status': status,
    })


@core_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Configurações do usuário — perfil, segurança, API key, TACACS+, sessão."""
    # Determine which tab to activate (preserved across redirects via ?tab=)
    active_tab = request.args.get('tab', 'profile')

    # Aviso de credenciais padrão — exibido apenas uma vez por sessão de login
    # (o auth_controller já exibe um flash no login; este complementa para quem
    #  chega em settings mais tarde na sessão, sem duplicar a cada page load)
    _warn_key = '_settings_cred_warned'
    if (current_user.is_admin
            and (current_user.force_password_reset
                 or current_user.username.lower() == 'admin')
            and not session.get(_warn_key)):
        flash(
            'Conta administrador com credenciais padrão detectadas. '
            'Altere a senha na aba Segurança imediatamente.',
            'warning'
        )
        session[_warn_key] = True

    # ── Inicializa forms ──────────────────────────────────────────────
    profile_form  = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()
    api_key_form  = ApiKeyForm()

    if request.method != 'POST':
        return _render_settings(
            profile_form, password_form, api_key_form,
            active_tab=active_tab
        )

    # ── POST handlers ────────────────────────────────────────────────

    # --- Perfil ---
    if 'profile_submit' in request.form:
        profile_form = ProfileForm()
        if profile_form.validate_on_submit():
            existing = User.query.filter_by(
                username=profile_form.username.data
            ).first()
            if existing and existing.id != current_user.id:
                flash('Nome de usuário já está em uso.', 'danger')
            else:
                existing_email = User.query.filter_by(
                    email=profile_form.email.data
                ).first()
                if existing_email and existing_email.id != current_user.id:
                    flash('E-mail já está em uso.', 'danger')
                else:
                    current_user.username   = profile_form.username.data
                    current_user.email      = profile_form.email.data
                    current_user.first_name = profile_form.first_name.data or None
                    current_user.last_name  = profile_form.last_name.data  or None
                    current_user.phone      = profile_form.phone.data      or None
                    current_user.department = profile_form.department.data or None
                    current_user.job_title  = profile_form.job_title.data  or None
                    current_user.timezone   = profile_form.timezone.data   or 'UTC'
                    try:
                        current_user.save()
                        flash('Perfil atualizado com sucesso!', 'success')
                        return redirect(
                            url_for('core.settings') + '?tab=profile'
                        )
                    except Exception as exc:
                        logger.exception('Profile save failed')
                        flash(f'Erro ao atualizar perfil: {exc}', 'danger')

        # Validation failed — re-render with errors on the profile tab
        password_form = ChangePasswordForm(formdata=None)
        return _render_settings(
            profile_form, password_form, api_key_form,
            active_tab='profile'
        )

    # --- Senha ---
    elif 'password_submit' in request.form:
        password_form = ChangePasswordForm()
        if password_form.validate_on_submit():
            if current_user.check_password(password_form.current_password.data):
                current_user.set_password(password_form.new_password.data)
                current_user.force_password_reset = False
                try:
                    current_user.save()
                    flash('Senha alterada com sucesso!', 'success')
                    return redirect(
                        url_for('core.settings') + '?tab=security'
                    )
                except Exception as exc:
                    logger.exception('Password change failed')
                    flash(f'Erro ao alterar senha: {exc}', 'danger')
            else:
                password_form.current_password.errors.append(
                    'Senha atual incorreta.'
                )

        profile_form = ProfileForm(formdata=None, obj=current_user)
        return _render_settings(
            profile_form, password_form, api_key_form,
            active_tab='security'
        )

    # --- API Key ---
    elif 'api_key_generate' in request.form:
        current_user.generate_api_key()
        flash('Nova API Key gerada com sucesso!', 'success')
        return redirect(url_for('core.settings') + '?tab=api')

    elif 'api_key_regenerate' in request.form:
        current_user.generate_api_key()
        flash('Chave de API regenerada. A chave anterior foi invalidada.', 'success')
        return redirect(url_for('core.settings') + '?tab=api')

    elif 'api_key_revoke' in request.form:
        current_user.revoke_api_key()
        flash('API Key revogada com sucesso!', 'success')
        return redirect(url_for('core.settings') + '?tab=api')

    # --- TACACS+ ---
    elif 'tacacs_config_submit' in request.form or 'tacacs_test_submit' in request.form:
        if not current_user.is_admin:
            flash(
                'Somente administradores podem gerenciar configurações de autenticação.',
                'danger'
            )
            return redirect(url_for('core.settings') + '?tab=tacacs')

        tacacs_form_posted = TacacsConfigForm()
        if tacacs_form_posted.validate_on_submit():
            from app.services.auth import TacacsConfig, TacacsService
            try:
                new_cfg = TacacsConfig(
                    enabled=bool(tacacs_form_posted.enabled.data),
                    host=(tacacs_form_posted.host.data or '').strip(),
                    port=int(tacacs_form_posted.port.data or 49),
                    secret=tacacs_form_posted.secret.data or '',
                    timeout=int(tacacs_form_posted.timeout.data or 10),
                    auth_type=tacacs_form_posted.auth_type.data or 'ascii',
                    fallback_local=bool(tacacs_form_posted.fallback_local.data),
                    auto_create_user=bool(tacacs_form_posted.auto_create_user.data),
                    default_email_domain=(
                        tacacs_form_posted.default_email_domain.data or ''
                    ).strip(),
                )
                new_cfg.save()

                if 'tacacs_test_submit' in request.form:
                    probe    = (tacacs_form_posted.probe_username.data or '').strip() or None
                    probe_pw = tacacs_form_posted.probe_password.data or None
                    result   = TacacsService.test_connection(probe, probe_pw)
                    ok = result.get('tcp_ok') and (
                        not result.get('auth_attempted') or result.get('auth_ok')
                    )
                    flash(
                        f"Teste TACACS+: {result.get('message', 'sem mensagem')}",
                        'success' if ok else 'warning'
                    )
                else:
                    flash('Configuração TACACS+ salva com sucesso.', 'success')

                return redirect(url_for('core.settings') + '?tab=tacacs')

            except ValueError as ve:
                flash(f'Configuração inválida: {ve}', 'danger')
            except Exception as exc:
                logger.exception('TACACS config save/test failed')
                flash(f'Erro ao processar configuração TACACS+: {exc}', 'danger')

        # Validation failed — re-render preserving posted form with errors
        tacacs_ctx               = _build_tacacs_context()
        tacacs_ctx['tacacs_form'] = tacacs_form_posted
        return render_template(
            'pages/settings.html',
            profile_form=profile_form,
            password_form=password_form,
            api_key_form=api_key_form,
            active_tab='tacacs',
            **tacacs_ctx,
            **_build_openai_context(),
        )

    # Fallback — unknown submit button
    return redirect(url_for('core.settings') + f'?tab={active_tab}')


def _render_settings(profile_form, password_form, api_key_form, active_tab='profile'):
    """Helper: render settings template with all required context."""
    return render_template(
        'pages/settings.html',
        profile_form=profile_form,
        password_form=password_form,
        api_key_form=api_key_form,
        active_tab=active_tab,
        **_build_tacacs_context(),
        **_build_openai_context(),
    )


def _build_tacacs_context():
    """Assemble the TACACS+ context dict passed to the settings template."""
    from app.services.auth import TacacsService
    cfg = TacacsService.load_config()
    tacacs_form = TacacsConfigForm(
        enabled=cfg.enabled,
        host=cfg.host,
        port=cfg.port,
        timeout=cfg.timeout,
        auth_type=cfg.auth_type,
        fallback_local=cfg.fallback_local,
        auto_create_user=cfg.auto_create_user,
        default_email_domain=cfg.default_email_domain,
    )
    return {
        'tacacs_form':        tacacs_form,
        'tacacs_config':      cfg,
        'tacacs_dependency':  TacacsService.dependency_status(),
        'tacacs_last_test':   TacacsService.last_test_status(),
    }


def _build_openai_context():
    """OpenAI admin configuration status for the settings template."""
    from app.services.core.openai_config_service import OpenAIConfigService
    return {
        'openai_config': OpenAIConfigService.status(),
    }
