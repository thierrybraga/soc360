'use strict';

(function () {
    const shell = document.querySelector('[data-page="asset-detail"]');
    const assetId = Number(shell?.dataset.assetId);

    function cssVar(name, fallback) {
        const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return value || fallback;
    }

    function maxColor(maxValue) {
        if (maxValue >= 8) return { border: '#ef4444', bg: 'rgba(239,68,68,0.15)', point: '#ef4444' };
        if (maxValue >= 6) return { border: '#f97316', bg: 'rgba(249,115,22,0.15)', point: '#f97316' };
        if (maxValue >= 4) return { border: '#eab308', bg: 'rgba(234,179,8,0.15)', point: '#eab308' };
        return { border: '#22c55e', bg: 'rgba(34,197,94,0.15)', point: '#22c55e' };
    }

    function buildRadar(labels, values) {
        const canvas = document.getElementById('assetRiskRadar');
        if (!canvas || typeof Chart === 'undefined') return null;

        const maxValue = Math.max(...values);
        const colors = maxColor(maxValue);
        const textColor = cssVar('--text-secondary', '#94a3b8');
        const mutedColor = cssVar('--text-muted', '#64748b');
        const bgSecondary = cssVar('--bg-secondary', '#1e293b');
        const borderColor = cssVar('--border-color', 'rgba(148,163,184,0.15)');
        const bgPrimary = cssVar('--bg-primary', '#0f172a');

        return new Chart(canvas, {
            type: 'radar',
            data: {
                labels,
                datasets: [{
                    label: 'Perfil de Risco',
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
                        ticks: {
                            stepSize: 2,
                            color: mutedColor,
                            backdropColor: 'transparent',
                            font: { size: 9, family: "'Inter', sans-serif" }
                        },
                        grid: { color: borderColor },
                        angleLines: { color: borderColor },
                        pointLabels: {
                            color: textColor,
                            font: { size: 10, weight: '600', family: "'Inter', sans-serif" }
                        }
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
                            title: () => 'Risco do Ativo',
                            label(ctx) {
                                const value = typeof ctx.raw === 'number' ? ctx.raw.toFixed(1) : ctx.raw;
                                const filled = '█'.repeat(Math.round(ctx.raw));
                                const empty = '░'.repeat(10 - Math.round(ctx.raw));
                                return ` ${ctx.label}: ${value}/10  ${filled}${empty}`;
                            }
                        }
                    }
                }
            }
        });
    }

    function initRadar() {
        if (!shell?.dataset.radarLabels || !shell?.dataset.radarValues) {
            return;
        }

        const labels = JSON.parse(shell.dataset.radarLabels);
        const values = JSON.parse(shell.dataset.radarValues);
        let radarInstance = buildRadar(labels, values);
        document.addEventListener('themechange', () => {
            radarInstance?.destroy();
            radarInstance = buildRadar(labels, values);
        });
    }

    function correlate(button) {
        if (!button || !assetId) return;

        const originalHtml = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Correlacionando...';

        fetch('/assets/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
            },
            credentials: 'same-origin',
            body: JSON.stringify({ asset_ids: [assetId] })
        })
            .then(response => response.json())
            .then(data => {
                const toast = document.getElementById('correlate-toast');
                const message = document.getElementById('correlate-msg');
                const newAssociations = data.new_associations || 0;
                const total = data.total || 0;

                if (!toast || !message) return;

                const alert = toast.querySelector('.alert');
                if (newAssociations > 0) {
                    alert.className = 'alert alert-success d-flex align-items-center gap-2';
                    message.textContent = `${newAssociations} nova(s) CVE(s) encontrada(s)! Total correlacionado: ${total}. Recarregando...`;
                    toast.classList.remove('is-hidden');
                    toast.style.display = 'block';
                    setTimeout(() => window.location.reload(), 1800);
                    return;
                }

                alert.className = 'alert alert-info d-flex align-items-center gap-2';
                message.textContent = total > 0
                    ? `${total} CVE(s) já correlacionadas - nenhuma nova encontrada.`
                    : 'Nenhuma CVE correspondente a este ativo foi encontrada na base.';
                toast.classList.remove('is-hidden');
                toast.style.display = 'block';
                button.disabled = false;
                button.innerHTML = originalHtml;
            })
            .catch(error => {
                console.error('Correlation error:', error);
                button.disabled = false;
                button.innerHTML = originalHtml;
                window.OpenMonitor?.showToast?.('Erro ao correlacionar CVEs. Tente novamente.', 'error');
            });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initRadar();
        ['btn-correlate', 'btn-correlate-2', 'btn-correlate-empty'].forEach(id => {
            const button = document.getElementById(id);
            button?.addEventListener('click', () => correlate(button));
        });
    });
}());
