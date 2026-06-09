'use strict';

// ────────────────────────────────────────────────────────────────────────────
// TAB ACTIVATION FROM URL
// ────────────────────────────────────────────────────────────────────────────

function activateTabFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get('tab');
    if (!tab) return;

    // Find the button for this tab
    const btn = document.querySelector(`button[data-bs-target="#tab-${tab}"]`);
    if (!btn) return;

    // If Bootstrap 5 tab is available, trigger it
    if (window.bootstrap && window.bootstrap.Tab) {
        const bsTab = new window.bootstrap.Tab(btn);
        bsTab.show();
        return;
    }

    // Fallback: manual activation
    // Deactivate all
    document.querySelectorAll('.sidebar-nav__item').forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-pane').forEach(p => {
        p.classList.remove('show', 'active');
    });

    // Activate target
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    const paneId = btn.getAttribute('data-bs-target');
    const pane = document.querySelector(paneId);
    if (pane) {
        pane.classList.add('show', 'active');
    }
}

// Update URL when tab changes (without page reload)
function setupTabUrlSync() {
    document.querySelectorAll('.sidebar-nav__item').forEach(btn => {
        btn.addEventListener('shown.bs.tab', function () {
            const target = this.getAttribute('data-bs-target') || '';
            const tabName = target.replace('#tab-', '');
            if (tabName) {
                const url = new URL(window.location);
                url.searchParams.set('tab', tabName);
                window.history.replaceState({}, '', url.toString());
            }
        });

        // Fallback for non-Bootstrap Tab event
        btn.addEventListener('click', function () {
            const target = this.getAttribute('data-bs-target') || '';
            const tabName = target.replace('#tab-', '');
            if (tabName) {
                const url = new URL(window.location);
                url.searchParams.set('tab', tabName);
                window.history.replaceState({}, '', url.toString());
            }

            // Manual tab activation if Bootstrap JS not loaded
            if (!window.bootstrap) {
                document.querySelectorAll('.sidebar-nav__item').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                document.querySelectorAll('.tab-pane').forEach(p => {
                    p.classList.remove('show', 'active');
                });
                this.classList.add('active');
                this.setAttribute('aria-selected', 'true');
                const pane = document.querySelector(target);
                if (pane) pane.classList.add('show', 'active');
            }
        });
    });
}

// ────────────────────────────────────────────────────────────────────────────
// PASSWORD STRENGTH
// ────────────────────────────────────────────────────────────────────────────

function validatePasswordStrength(password) {
    const result = {
        score: 0,
        level: 'weak',
        isValid: false,
        checks: {
            length: password.length >= 12,
            upper:  /[A-Z]/.test(password),
            lower:  /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            symbol: /[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>/?]/.test(password)
        }
    };

    if (result.checks.length) result.score += 2;
    else if (password.length >= 8) result.score += 1;
    if (result.checks.upper)  result.score += 1;
    if (result.checks.lower)  result.score += 1;
    if (result.checks.number) result.score += 1;
    if (result.checks.symbol) result.score += 2;

    if (result.score >= 6) result.level = 'strong';
    else if (result.score >= 4) result.level = 'medium';
    else result.level = 'weak';

    result.isValid = result.score >= 5;
    return result;
}

function updateStrengthBar(password) {
    const wrap  = document.getElementById('pwStrengthWrap');
    const fill  = document.getElementById('pwStrengthFill');
    const label = document.getElementById('pwStrengthLabel');
    const reqs  = document.getElementById('pwReqs');

    if (!wrap) return;

    if (!password) {
        wrap.hidden = true;
        if (reqs) reqs.hidden = true;
        return;
    }

    wrap.hidden = false;
    if (reqs) reqs.hidden = false;

    const result = validatePasswordStrength(password);
    const widths = { weak: '33%', medium: '66%', strong: '100%' };
    const labels = { weak: 'Fraca', medium: 'Moderada', strong: 'Forte' };

    if (fill) {
        fill.style.width = widths[result.level];
        fill.className = `pw-strength-fill ${result.level}`;
    }
    if (label) label.textContent = labels[result.level];

    if (reqs) {
        Object.entries(result.checks).forEach(([key, met]) => {
            const chip = reqs.querySelector(`[data-req="${key}"]`);
            if (chip) chip.classList.toggle('met', met);
        });
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TOGGLE PASSWORD VISIBILITY
// ────────────────────────────────────────────────────────────────────────────

function togglePassword(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;

    const btn  = document.querySelector(`button[data-target="${fieldId}"]`);
    const icon = btn?.querySelector('i');
    const show = input.type === 'password';

    input.type = show ? 'text' : 'password';

    if (icon) {
        icon.classList.toggle('fa-eye',       !show);
        icon.classList.toggle('fa-eye-slash',  show);
    }
    if (btn) {
        btn.setAttribute('aria-pressed', String(show));
        btn.setAttribute('aria-label', show ? 'Ocultar' : 'Mostrar');
    }
}

// ────────────────────────────────────────────────────────────────────────────
// COPY TO CLIPBOARD
// ────────────────────────────────────────────────────────────────────────────

function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const wasPassword = el.type === 'password';
    if (wasPassword) el.type = 'text';
    el.select();
    el.setSelectionRange(0, 99999);
    const val = el.value;
    if (wasPassword) el.type = 'password';

    navigator.clipboard.writeText(val).then(() => {
        showCopyFeedback(elementId, 'success');
        window.OpenMonitor?.showToast('Chave copiada!', 'success');
    }).catch(() => {
        try {
            document.execCommand('copy');
            showCopyFeedback(elementId, 'success');
            window.OpenMonitor?.showToast('Chave copiada!', 'success');
        } catch {
            window.OpenMonitor?.showToast('Falha ao copiar', 'error');
        }
    });
}

function showCopyFeedback(elementId, status) {
    const btn = document.querySelector(`.copy-btn[data-target="${elementId}"]`);
    if (!btn) return;
    btn.classList.remove('copied', 'failed');
    void btn.offsetWidth;
    btn.classList.add(status === 'success' ? 'copied' : 'failed');
    setTimeout(() => btn.classList.remove('copied', 'failed'), 1500);
}

// ────────────────────────────────────────────────────────────────────────────
// FORM VALIDATION
// ────────────────────────────────────────────────────────────────────────────

function setupFormValidation() {
    const newPasswordInput     = document.getElementById('newPasswordInput');
    const confirmPasswordField = document.querySelector('[name="confirm_new_password"]');

    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', function () {
            updateStrengthBar(this.value);
            if (this.value) this.classList.remove('is-invalid');
        });
    }

    if (confirmPasswordField && newPasswordInput) {
        confirmPasswordField.addEventListener('blur', function () {
            if (!this.value) return;
            const match = this.value === newPasswordInput.value;
            this.classList.toggle('is-invalid', !match);

            let feedback = this.closest('.input-group')?.nextElementSibling;
            if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                feedback = this.parentElement.parentElement.querySelector('.invalid-feedback');
            }
            if (!match) {
                if (!feedback) {
                    feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    this.closest('.form-group')?.appendChild(feedback);
                }
                feedback.innerHTML = '<i class="fas fa-info-circle"></i> As senhas não correspondem';
            } else if (feedback) {
                feedback.remove();
            }
        });
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DANGEROUS ACTION HANDLER
// ────────────────────────────────────────────────────────────────────────────

async function confirmDangerous(message, opts) {
    const confirmFn = window.OpenMonitor?.confirm;
    if (typeof confirmFn === 'function') {
        return await confirmFn(message, opts);
    }
    return window.confirm(`${opts?.title || 'Confirmar'}\n\n${message}`);
}

function setupDangerousActionHandlers() {
    const revokeBtn = document.getElementById('revokeKeyBtn');
    if (revokeBtn) {
        revokeBtn.addEventListener('click', async function (e) {
            e.preventDefault();
            const ok = await confirmDangerous(
                'Todas as aplicações usando essa chave deixarão de funcionar imediatamente.',
                { title: 'Revogar Chave de API', confirmText: 'Revogar', cancelText: 'Cancelar' }
            );
            if (ok) {
                const form = this.closest('form');
                if (form) {
                    const hidden = document.createElement('input');
                    hidden.type  = 'hidden';
                    hidden.name  = 'api_key_revoke';
                    hidden.value = '1';
                    form.appendChild(hidden);
                    form.submit();
                }
            }
        });
    }

    document.querySelectorAll('button[name="api_key_regenerate"]').forEach(btn => {
        btn.addEventListener('click', async function (e) {
            e.preventDefault();
            const ok = await confirmDangerous(
                'A chave atual será invalidada imediatamente. Integrações existentes precisarão ser atualizadas.',
                { title: 'Regenerar Chave de API', confirmText: 'Regenerar', cancelText: 'Cancelar' }
            );
            if (ok) {
                const form = this.closest('form');
                if (form) {
                    const hidden = document.createElement('input');
                    hidden.type  = 'hidden';
                    hidden.name  = this.name;
                    hidden.value = this.value || '1';
                    form.appendChild(hidden);
                    form.submit();
                }
            }
        });
    });
}

// ────────────────────────────────────────────────────────────────────────────
// OPENAI ADMIN CONFIG
// ────────────────────────────────────────────────────────────────────────────

function openaiCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

async function openaiRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options,
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-CSRFToken': openaiCsrfToken(),
            ...(options.headers || {})
        }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(body.error || body.message || 'Falha ao processar configuração OpenAI.');
    }
    return body;
}

function setOpenAIButtonsBusy(busy) {
    ['openai-save-btn', 'openai-test-btn', 'openai-remove-btn'].forEach(id => {
        const btn = document.getElementById(id);
        if (!btn) return;
        if (id === 'openai-remove-btn' && !btn.dataset.disabledByStatus) {
            btn.dataset.disabledByStatus = btn.disabled ? 'true' : 'false';
        }
        btn.disabled = busy || (id === 'openai-remove-btn' && btn.dataset.disabledByStatus === 'true');
    });
}

function renderOpenAIStatus(status) {
    const configured = Boolean(status?.configured);
    const source = status?.source || '';
    const badge = document.getElementById('openai-status-badge');
    const alert = document.getElementById('openai-status-alert');
    const title = document.getElementById('openai-status-title');
    const text = document.getElementById('openai-status-text');
    const removeBtn = document.getElementById('openai-remove-btn');

    if (badge) {
        badge.classList.toggle('scard__status--ok', configured);
        badge.innerHTML = `<i class="fas fa-circle"></i>${configured ? 'Chave configurada' : 'Chave não configurada'}`;
    }
    if (alert) {
        alert.classList.toggle('alert-success', configured);
        alert.classList.toggle('alert-warning', !configured);
    }
    if (title) {
        title.textContent = configured ? 'Chave configurada' : 'Chave não configurada';
    }
    if (text) {
        if (!configured) {
            text.textContent = 'Cadastre uma chave para habilitar respostas reais da OpenAI.';
        } else {
            const sourceText = source === 'environment'
                ? ' via variável de ambiente'
                : ' via armazenamento seguro interno';
            text.textContent = `Usando ${status.masked_key || 'sk-...'}${sourceText}.`;
        }
    }
    if (removeBtn) {
        const disabledByStatus = !configured || source === 'environment';
        removeBtn.dataset.disabledByStatus = disabledByStatus ? 'true' : 'false';
        removeBtn.disabled = disabledByStatus;
    }
}

function showOpenAIResult(message, type = 'success') {
    const toast = window.OpenMonitor?.showToast;
    if (typeof toast === 'function') {
        toast(message, type);
        return;
    }
    window.alert(message);
}

function setupOpenAIConfig() {
    const form = document.getElementById('openaiConfigForm');
    if (!form) return;

    const input = document.getElementById('openaiApiKeyInput');
    const testBtn = document.getElementById('openai-test-btn');
    const removeBtn = document.getElementById('openai-remove-btn');

    form.addEventListener('submit', async event => {
        event.preventDefault();
        const apiKey = input?.value.trim() || '';
        if (!apiKey) {
            showOpenAIResult('Informe uma chave OpenAI para salvar.', 'warning');
            input?.focus();
            return;
        }

        setOpenAIButtonsBusy(true);
        try {
            const body = await openaiRequest('/api/v1/admin/openai-key', {
                method: 'POST',
                body: JSON.stringify({ api_key: apiKey })
            });
            if (input) input.value = '';
            renderOpenAIStatus(body.status);
            showOpenAIResult(body.message || 'Chave OpenAI salva com sucesso.', 'success');
        } catch (error) {
            showOpenAIResult(error.message, 'error');
        } finally {
            setOpenAIButtonsBusy(false);
        }
    });

    testBtn?.addEventListener('click', async () => {
        const apiKey = input?.value.trim() || '';
        setOpenAIButtonsBusy(true);
        try {
            const body = await openaiRequest('/api/v1/admin/openai-key/test', {
                method: 'POST',
                body: JSON.stringify(apiKey ? { api_key: apiKey } : {})
            });
            if (input) input.value = '';
            showOpenAIResult(body.message || 'Conexão testada com sucesso.', body.ok ? 'success' : 'warning');
        } catch (error) {
            showOpenAIResult(error.message, 'error');
        } finally {
            setOpenAIButtonsBusy(false);
        }
    });

    removeBtn?.addEventListener('click', async () => {
        const ok = await confirmDangerous(
            'A chave salva no armazenamento interno será removida. Se houver uma chave em variável de ambiente, ela continuará ativa.',
            { title: 'Remover chave OpenAI', confirmText: 'Remover', cancelText: 'Cancelar' }
        );
        if (!ok) return;

        setOpenAIButtonsBusy(true);
        try {
            const body = await openaiRequest('/api/v1/admin/openai-key', { method: 'DELETE' });
            if (input) input.value = '';
            renderOpenAIStatus(body.status);
            showOpenAIResult(body.message || 'Chave OpenAI removida.', 'success');
        } catch (error) {
            showOpenAIResult(error.message, 'error');
        } finally {
            setOpenAIButtonsBusy(false);
        }
    });
}

// ────────────────────────────────────────────────────────────────────────────
// TACACS+ FORM — loading states and double-submit guard
// ────────────────────────────────────────────────────────────────────────────

function setupTacacsForm() {
    const form = document.getElementById('tacacsForm');
    if (!form) return;

    const saveBtn = form.querySelector('button[name="tacacs_config_submit"]');
    const testBtn = form.querySelector('button[name="tacacs_test_submit"]');

    function setSubmitting(activeBtn) {
        [saveBtn, testBtn].forEach(btn => {
            if (!btn) return;
            btn.disabled = true;
        });
        if (activeBtn) {
            const icon = activeBtn.querySelector('i');
            if (icon) {
                activeBtn.dataset.origIcon = icon.className;
                icon.className = 'fas fa-spinner fa-spin';
            }
        }
    }

    [saveBtn, testBtn].forEach(btn => {
        if (!btn) return;
        btn.addEventListener('click', () => {
            // Small delay to allow the browser to set btn as submitter before disabling
            setTimeout(() => setSubmitting(btn), 50);
        });
    });
}

// ────────────────────────────────────────────────────────────────────────────
// CISCO UMBRELLA ADMIN CONFIG
// ────────────────────────────────────────────────────────────────────────────

function umbrellaCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

async function umbrellaRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options,
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-CSRFToken': umbrellaCsrfToken(),
            ...(options.headers || {})
        }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(body.error || body.message || 'Falha ao processar configuração Umbrella.');
    }
    return body;
}

function setUmbrellaButtonsBusy(busy) {
    ['umbrella-save-btn', 'umbrella-test-btn', 'umbrella-remove-btn'].forEach(id => {
        const btn = document.getElementById(id);
        if (!btn) return;
        if (id === 'umbrella-remove-btn' && !btn.dataset.disabledByStatus) {
            btn.dataset.disabledByStatus = btn.disabled ? 'true' : 'false';
        }
        btn.disabled = busy || (id === 'umbrella-remove-btn' && btn.dataset.disabledByStatus === 'true');
    });
}

function renderUmbrellaStatus(status) {
    const configured = Boolean(status?.configured);
    const source = status?.source || '';
    const badge   = document.getElementById('umbrella-status-badge');
    const alert   = document.getElementById('umbrella-status-alert');
    const title   = document.getElementById('umbrella-status-title');
    const text    = document.getElementById('umbrella-status-text');
    const removeBtn = document.getElementById('umbrella-remove-btn');

    if (badge) {
        badge.classList.toggle('scard__status--ok', configured);
        badge.innerHTML = `<i class="fas fa-circle"></i>${configured ? 'Credenciais configuradas' : 'Modo demo ativo'}`;
    }
    if (alert) {
        alert.classList.toggle('alert-success', configured);
        alert.classList.toggle('alert-warning', !configured);
        const icon = alert.querySelector('i');
        if (icon) {
            icon.className = configured ? 'fas fa-circle-check' : 'fas fa-circle-exclamation';
        }
    }
    if (title) {
        title.textContent = configured ? 'Credenciais configuradas' : 'Modo demo ativo';
    }
    if (text) {
        if (!configured) {
            text.textContent = 'Cadastre as credenciais para conectar à API real da Cisco Umbrella.';
        } else {
            const sourceText = source === 'environment'
                ? ' via variável de ambiente'
                : ' via armazenamento seguro interno';
            text.textContent = `Usando key ${status.masked_key || '****...'}${sourceText}.`;
        }
    }
    if (removeBtn) {
        const disabledByStatus = !configured || source === 'environment';
        removeBtn.dataset.disabledByStatus = disabledByStatus ? 'true' : 'false';
        removeBtn.disabled = disabledByStatus;
    }
}

function showUmbrellaResult(message, type = 'success') {
    const toast = window.OpenMonitor?.showToast;
    if (typeof toast === 'function') {
        toast(message, type);
        return;
    }
    window.alert(message);
}

function setupUmbrellaConfig() {
    const form = document.getElementById('umbrellaConfigForm');
    if (!form) return;

    const keyInput    = document.getElementById('umbrellaApiKeyInput');
    const secretInput = document.getElementById('umbrellaApiSecretInput');
    const testBtn     = document.getElementById('umbrella-test-btn');
    const removeBtn   = document.getElementById('umbrella-remove-btn');

    form.addEventListener('submit', async event => {
        event.preventDefault();
        const apiKey    = keyInput?.value.trim() || '';
        const apiSecret = secretInput?.value.trim() || '';
        if (!apiKey || !apiSecret) {
            showUmbrellaResult('Informe a API Key e o API Secret para salvar.', 'warning');
            (!apiKey ? keyInput : secretInput)?.focus();
            return;
        }

        setUmbrellaButtonsBusy(true);
        try {
            const body = await umbrellaRequest('/integrations/umbrella/api/config/credentials', {
                method: 'POST',
                body: JSON.stringify({ api_key: apiKey, api_secret: apiSecret })
            });
            if (keyInput) keyInput.value = '';
            if (secretInput) secretInput.value = '';
            renderUmbrellaStatus(body.status);
            showUmbrellaResult(body.message || 'Credenciais Umbrella salvas com sucesso.', 'success');
        } catch (error) {
            showUmbrellaResult(error.message, 'error');
        } finally {
            setUmbrellaButtonsBusy(false);
        }
    });

    testBtn?.addEventListener('click', async () => {
        const apiKey    = keyInput?.value.trim() || '';
        const apiSecret = secretInput?.value.trim() || '';
        setUmbrellaButtonsBusy(true);
        try {
            const payload = (apiKey && apiSecret) ? { api_key: apiKey, api_secret: apiSecret } : {};
            const body = await umbrellaRequest('/integrations/umbrella/api/config/test', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            showUmbrellaResult(body.message || 'Conexão testada com sucesso.', body.ok ? 'success' : 'warning');
        } catch (error) {
            showUmbrellaResult(error.message, 'error');
        } finally {
            setUmbrellaButtonsBusy(false);
        }
    });

    removeBtn?.addEventListener('click', async () => {
        const ok = await confirmDangerous(
            'As credenciais salvas no armazenamento interno serão removidas. Se houver credenciais em variáveis de ambiente, elas continuarão ativas.',
            { title: 'Remover credenciais Umbrella', confirmText: 'Remover', cancelText: 'Cancelar' }
        );
        if (!ok) return;

        setUmbrellaButtonsBusy(true);
        try {
            const body = await umbrellaRequest('/integrations/umbrella/api/config/credentials', { method: 'DELETE' });
            if (keyInput) keyInput.value = '';
            if (secretInput) secretInput.value = '';
            renderUmbrellaStatus(body.status);
            showUmbrellaResult(body.message || 'Credenciais Umbrella removidas.', 'success');
        } catch (error) {
            showUmbrellaResult(error.message, 'error');
        } finally {
            setUmbrellaButtonsBusy(false);
        }
    });
}

// ────────────────────────────────────────────────────────────────────────────
// BUTTON FEEDBACK
// ────────────────────────────────────────────────────────────────────────────

function setupButtonFeedback() {
    document.querySelectorAll('button[data-action]').forEach(btn => {
        btn.addEventListener('click', function () {
            this.style.pointerEvents = 'none';
            this.style.opacity = '0.65';
            setTimeout(() => {
                this.style.pointerEvents = '';
                this.style.opacity = '';
            }, 2500);
        });
    });
}

// ────────────────────────────────────────────────────────────────────────────
// AUTO-DISMISS FLASH MESSAGES
// ────────────────────────────────────────────────────────────────────────────

function setupFlashAutoDismiss() {
    const container = document.getElementById('flashMessages');
    if (!container) return;
    setTimeout(() => {
        container.querySelectorAll('.alert').forEach(alert => {
            alert.style.transition = 'opacity 0.5s ease, max-height 0.5s ease';
            alert.style.opacity = '0';
            alert.style.maxHeight = '0';
            alert.style.overflow = 'hidden';
            setTimeout(() => alert.remove(), 500);
        });
    }, 6000);
}

// ────────────────────────────────────────────────────────────────────────────
// INIT
// ────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Activate correct tab from URL param
    activateTabFromUrl();

    // Sync URL when tabs change
    setupTabUrlSync();

    // Password toggle buttons
    document.querySelectorAll('.toggle-password-btn').forEach(btn => {
        btn.addEventListener('click', e => {
            e.preventDefault();
            togglePassword(btn.getAttribute('data-target'));
        });
        btn.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                btn.click();
            }
        });
    });

    // Copy buttons
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', e => {
            e.preventDefault();
            copyToClipboard(btn.getAttribute('data-target'));
        });
    });

    setupFormValidation();
    setupDangerousActionHandlers();
    setupTacacsForm();
    setupOpenAIConfig();
    setupUmbrellaConfig();
    setupButtonFeedback();
    setupFlashAutoDismiss();
});
