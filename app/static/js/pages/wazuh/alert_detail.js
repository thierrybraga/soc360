'use strict';

(async function () {
    const shell = document.querySelector('[data-page="wazuh-alert-detail"]');
    const id = shell?.dataset.alertId;
    const element = document.getElementById('detail-content');

    if (!id || !element) {
        return;
    }

    const escapeHtml = window.OpenMonitor?.utils?.escapeHtml || ((value) => {
        const div = document.createElement('div');
        div.textContent = value || '';
        return div.innerHTML;
    });

    try {
        const response = await fetch(`/integrations/wazuh/api/alerts/${id}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const alert = data.alert || {};
        element.innerHTML = `
            <h2 class="h4 mb-2">${escapeHtml(alert.rule_description || '')}</h2>
            <div class="mb-3">
                <span class="badge bg-secondary">${escapeHtml(alert.severity || '')}</span>
                <span class="badge bg-dark text-light border">${escapeHtml(alert.status || '')}</span>
                <span class="text-muted ms-2">Rule ${escapeHtml(alert.rule_id || '-')} · level ${escapeHtml(alert.rule_level || '-')}</span>
            </div>
            <dl class="row small">
                <dt class="col-sm-3">Agente</dt><dd class="col-sm-9">${escapeHtml(alert.agent_name || '-')} (${escapeHtml(alert.agent_ip || '-')})</dd>
                <dt class="col-sm-3">Manager</dt><dd class="col-sm-9">${escapeHtml(alert.manager_name || '-')}</dd>
                <dt class="col-sm-3">Decoder</dt><dd class="col-sm-9">${escapeHtml(alert.decoder_name || '-')}</dd>
                <dt class="col-sm-3">Location</dt><dd class="col-sm-9"><code>${escapeHtml(alert.location || '-')}</code></dd>
                <dt class="col-sm-3">MITRE</dt><dd class="col-sm-9">${escapeHtml((alert.rule_mitre_ids || []).join(', ') || '-')}</dd>
                <dt class="col-sm-3">Timestamp</dt><dd class="col-sm-9">${escapeHtml(alert.timestamp || '-')}</dd>
            </dl>
            <h3 class="h6">Log bruto</h3>
            <pre class="bg-dark text-light rounded p-3 small">${escapeHtml(alert.full_log || '')}</pre>
        `;
    } catch (error) {
        element.innerHTML = `<div class="alert alert-danger">Falha ao carregar alerta: ${escapeHtml(error.message)}</div>`;
    }
}());
