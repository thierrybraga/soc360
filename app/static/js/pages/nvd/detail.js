'use strict';

(function () {
    const shell = document.querySelector('[data-page="nvd-detail"]');
    const cveId = shell?.dataset.cveId || '';
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

    function escapeHtml(value) {
        return String(value || '').replace(/[&<>"']/g, char => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[char]));
    }

    function showAlert(message, type) {
        const alertBox = document.getElementById('mitigationWorkflowAlert');
        if (!alertBox) return;
        alertBox.className = `alert alert-${type} py-2 mb-3`;
        alertBox.textContent = message;
        alertBox.classList.remove('d-none');
        setTimeout(() => alertBox.classList.add('d-none'), 6000);
    }

    function bindWorkflowStepper() {
        const stepper = document.getElementById('workflowStepper');
        const actionInput = document.getElementById('mitigationAction');
        stepper?.addEventListener('click', event => {
            const pill = event.target.closest('.step-pill');
            if (!pill) return;
            stepper.querySelectorAll('.step-pill').forEach(item => item.classList.remove('active'));
            pill.classList.add('active');
            if (actionInput) actionInput.value = pill.dataset.action;
        });
    }

    function bindAssetFilters() {
        const filterTabs = document.getElementById('assetFilterTabs');
        const assetTable = document.getElementById('affectedAssetsTable');
        if (!filterTabs || !assetTable) return;

        filterTabs.addEventListener('click', event => {
            const button = event.target.closest('.tab-btn');
            if (!button) return;
            filterTabs.querySelectorAll('.tab-btn').forEach(item => item.classList.remove('active'));
            button.classList.add('active');
            const filter = button.dataset.filter;
            assetTable.querySelectorAll('tbody tr').forEach(row => {
                const visible = filter === 'ALL'
                    ? true
                    : filter === 'OVERDUE'
                        ? row.dataset.overdue === 'true'
                        : row.dataset.status === filter;
                row.classList.toggle('is-hidden', !visible);
            });
        });
    }

    function bindAssetSorting() {
        const assetTable = document.getElementById('affectedAssetsTable');
        if (!assetTable) return;

        const criticalityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, '': 0 };
        const headers = assetTable.querySelectorAll('thead th.sortable');
        headers.forEach((header, columnIndex) => {
            header.addEventListener('click', () => {
                const type = header.dataset.sortType || 'text';
                const currentDirection = header.classList.contains('sort-asc') ? 'asc'
                    : header.classList.contains('sort-desc') ? 'desc'
                        : null;
                const nextDirection = currentDirection === 'asc' ? 'desc' : 'asc';
                headers.forEach(item => {
                    item.classList.remove('sort-asc', 'sort-desc');
                    const indicator = item.querySelector('.sort-indicator');
                    if (indicator) indicator.textContent = '⇅';
                });
                header.classList.add(`sort-${nextDirection}`);
                const indicator = header.querySelector('.sort-indicator');
                if (indicator) indicator.textContent = nextDirection === 'asc' ? '▲' : '▼';

                const tbody = assetTable.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const multiplier = nextDirection === 'asc' ? 1 : -1;

                rows.sort((a, b) => {
                    const av = (a.children[columnIndex]?.dataset.sortValue || '').trim();
                    const bv = (b.children[columnIndex]?.dataset.sortValue || '').trim();
                    if (type === 'number') return ((parseFloat(av) || 0) - (parseFloat(bv) || 0)) * multiplier;
                    if (type === 'date') {
                        if (!av && !bv) return 0;
                        if (!av) return 1;
                        if (!bv) return -1;
                        return av.localeCompare(bv) * multiplier;
                    }
                    if (type === 'criticality') {
                        return ((criticalityRank[av.toUpperCase()] || 0) - (criticalityRank[bv.toUpperCase()] || 0)) * multiplier;
                    }
                    return av.localeCompare(bv) * multiplier;
                });
                rows.forEach(row => tbody.appendChild(row));
            });
        });
    }

    function renderHistory(items) {
        const historyContainer = document.getElementById('mitigationHistoryContainer');
        if (!historyContainer) return;

        if (!items || items.length === 0) {
            historyContainer.innerHTML = '<p class="text-muted small mb-0">Nenhum histórico de mitigação registrado.</p>';
            return;
        }

        const html = items.map(item => {
            const timestamp = item.timestamp ? new Date(item.timestamp).toLocaleString('pt-BR') : '-';
            const status = item.status ? `<span class="badge bg-dark border border-secondary text-secondary">${escapeHtml(item.status)}</span>` : '';
            const effectiveness = item.effectiveness ? `<span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25">${escapeHtml(item.effectiveness)}</span>` : '';
            const source = item.source ? `<span class="badge bg-secondary bg-opacity-25 text-secondary border border-secondary border-opacity-25">${escapeHtml(item.source)}</span>` : '';
            const user = item.username ? `<span class="badge bg-dark border border-info text-info"><i class="fas fa-user me-1"></i>${escapeHtml(item.username)}</span>` : '';
            return `<div class="history-entry" data-kind="${escapeHtml(item.kind || '')}">
                <div class="d-flex justify-content-between align-items-start gap-2">
                    <div class="flex-grow-1">
                        <div class="text-white fw-medium small">${escapeHtml(item.title || '')}</div>
                        ${item.description ? `<div class="text-muted small mt-1">${escapeHtml(item.description)}</div>` : ''}
                        <div class="mt-1 d-flex flex-wrap gap-2">${status}${effectiveness}${source}${user}</div>
                    </div>
                    <span class="text-muted small flex-shrink-0 text-nowrap"><i class="fas fa-clock me-1"></i>${timestamp}</span>
                </div>
            </div>`;
        }).join('');
        historyContainer.innerHTML = `<div class="history-timeline">${html}</div>`;
    }

    async function refreshHistory() {
        if (!cveId) return;
        try {
            const response = await fetch(`/vulnerabilities/api/${encodeURIComponent(cveId)}/mitigations/history`);
            if (!response.ok) return;
            const data = await response.json();
            renderHistory(data.items || []);
        } catch (_) {
            /* best-effort */
        }
    }

    function bindMitigationWorkflow() {
        const refreshButton = document.getElementById('refreshHistoryBtn');
        const submitButton = document.getElementById('submitMitigationWorkflow');

        refreshButton?.addEventListener('click', () => {
            refreshButton.disabled = true;
            refreshHistory().finally(() => { refreshButton.disabled = false; });
        });

        submitButton?.addEventListener('click', async () => {
            submitButton.disabled = true;
            const payload = {
                action: document.getElementById('mitigationAction')?.value || 'update',
                asset_vulnerability_id: document.getElementById('mitigationAssetVulnId')?.value || null,
                type: document.getElementById('mitigationType')?.value || null,
                effectiveness: document.getElementById('mitigationEffectiveness')?.value || null,
                due_date: document.getElementById('mitigationDueDate')?.value || null,
                mitigation_description: document.getElementById('mitigationDescription')?.value || '',
                notes: document.getElementById('mitigationNotes')?.value || '',
                source: 'organization'
            };

            try {
                const response = await fetch(`/vulnerabilities/api/${encodeURIComponent(cveId)}/mitigations/workflow`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (!response.ok) {
                    showAlert(data.error || 'Falha ao atualizar workflow de mitigação.', 'danger');
                    return;
                }
                showAlert('Workflow de mitigação atualizado com sucesso.', 'success');
                renderHistory(data.history || []);
                await refreshHistory();
            } catch (_) {
                showAlert('Erro de conexão ao atualizar mitigação.', 'danger');
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    function bindAnchorNav() {
        const anchors = document.querySelectorAll('.section-anchor-nav a');
        const sections = Array.from(anchors).map(anchor => document.querySelector(anchor.getAttribute('href'))).filter(Boolean);
        if (!sections.length) return;

        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                const id = entry.target.id;
                anchors.forEach(anchor => anchor.classList.toggle('active', anchor.getAttribute('href') === `#${id}`));
            });
        }, { rootMargin: '-40% 0px -55% 0px', threshold: 0 });
        sections.forEach(section => observer.observe(section));
    }

    function cssVar(name, fallback) {
        const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return value || fallback;
    }

    function severityColor(maxValue) {
        if (maxValue >= 9) return { border: '#ef4444', bg: 'rgba(239,68,68,0.18)', point: '#ef4444' };
        if (maxValue >= 7) return { border: '#f97316', bg: 'rgba(249,115,22,0.18)', point: '#f97316' };
        if (maxValue >= 4) return { border: '#eab308', bg: 'rgba(234,179,8,0.18)', point: '#eab308' };
        return { border: '#22c55e', bg: 'rgba(34,197,94,0.18)', point: '#22c55e' };
    }

    function buildRadar(labels, values) {
        const radarCanvas = document.getElementById('riskRadarChart');
        if (!radarCanvas || typeof Chart === 'undefined') return null;

        const colors = severityColor(Math.max(...values));
        const textColor = cssVar('--text-secondary', '#cbd5e1');
        const mutedColor = cssVar('--text-muted', '#94a3b8');
        const bgPrimary = cssVar('--bg-primary', '#0f172a');
        const bgSecondary = cssVar('--bg-secondary', '#1e293b');
        const borderColor = cssVar('--border-color', 'rgba(148,163,184,0.15)');

        return new Chart(radarCanvas, {
            type: 'radar',
            data: {
                labels,
                datasets: [{
                    label: 'Risk Profile',
                    data: values,
                    borderWidth: 2,
                    borderColor: colors.border,
                    backgroundColor: colors.bg,
                    pointBackgroundColor: colors.point,
                    pointBorderColor: bgPrimary,
                    pointBorderWidth: 1.5,
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: colors.border,
                    pointRadius: 4,
                    pointHoverRadius: 7,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 600, easing: 'easeInOutQuart' },
                scales: {
                    r: {
                        min: 0,
                        max: 10,
                        ticks: { stepSize: 2, color: mutedColor, backdropColor: 'transparent', font: { size: 10, family: "'Inter', sans-serif" } },
                        grid: { color: borderColor },
                        angleLines: { color: borderColor },
                        pointLabels: { color: textColor, font: { size: 11, weight: '600', family: "'Inter', sans-serif" } }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: bgSecondary,
                        borderColor,
                        borderWidth: 1,
                        titleColor: textColor,
                        bodyColor: textColor,
                        padding: 10,
                        callbacks: {
                            title: () => 'Postura de Risco',
                            label(ctx) {
                                const value = typeof ctx.raw === 'number' ? ctx.raw.toFixed(2) : ctx.raw;
                                const bar = '█'.repeat(Math.round(ctx.raw)) + '░'.repeat(10 - Math.round(ctx.raw));
                                return ` ${ctx.label}: ${value}/10  ${bar}`;
                            }
                        }
                    }
                }
            }
        });
    }

    function initRadar() {
        if (!shell?.dataset.radarLabels || !shell?.dataset.radarValues) return;
        const labels = JSON.parse(shell.dataset.radarLabels);
        const values = JSON.parse(shell.dataset.radarValues);
        let chartInstance = buildRadar(labels, values);
        document.addEventListener('themechange', () => {
            chartInstance?.destroy();
            chartInstance = buildRadar(labels, values);
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        bindWorkflowStepper();
        bindAssetFilters();
        bindAssetSorting();
        bindMitigationWorkflow();
        bindAnchorNav();
        initRadar();
        refreshHistory();
    });
}());
