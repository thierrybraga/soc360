'use strict';

(function () {
    function setDefaultDates() {
        const end = new Date();
        const start = new Date();
        start.setDate(end.getDate() - 30);
        const endInput = document.getElementById('report-end');
        const startInput = document.getElementById('report-start');
        if (endInput) endInput.value = end.toISOString().split('T')[0];
        if (startInput) startInput.value = start.toISOString().split('T')[0];
    }

    function showReportModal() {
        bootstrap.Modal.getOrCreateInstance(document.getElementById('reportModal')).show();
    }

    async function submitReport(event) {
        const button = event.currentTarget;
        const originalHtml = button.innerHTML;
        const payload = {
            organization_id: parseInt(document.getElementById('report-org-id').value, 10),
            organization_name: document.getElementById('report-org-name').value,
            period_start: document.getElementById('report-start').value,
            period_end: document.getElementById('report-end').value
        };

        if (!payload.period_start || !payload.period_end) {
            window.OpenMonitor?.showToast?.('Informe o período', 'warning');
            return;
        }

        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Gerando...';

        try {
            const response = await fetch('/integrations/umbrella/api/generate-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
                },
                body: JSON.stringify(payload)
            });
            const data = await response.json();

            if (!data.success) {
                window.OpenMonitor?.showToast?.(data.error || 'Erro ao gerar relatório', 'error');
                return;
            }

            bootstrap.Modal.getInstance(document.getElementById('reportModal'))?.hide();
            const shouldDownload = window.OpenMonitor?.confirm
                ? await window.OpenMonitor.confirm('Relatório gerado. Deseja fazer o download?', { confirmText: 'Download' })
                : window.confirm('Relatório gerado! Deseja fazer o download?');

            if (shouldDownload) {
                window.location.href = data.docx_url || data.pdf_url;
            } else {
                window.location.reload();
            }
        } catch (error) {
            console.error('Report generation failed:', error);
            window.OpenMonitor?.showToast?.('Erro ao gerar relatório', 'error');
        } finally {
            button.disabled = false;
            button.innerHTML = originalHtml;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        setDefaultDates();
        document.getElementById('btn-generate-report')?.addEventListener('click', showReportModal);
        document.getElementById('btn-submit-report')?.addEventListener('click', submitReport);
    });
}());
