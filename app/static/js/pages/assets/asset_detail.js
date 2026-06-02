'use strict';

(function () {
    function showFeedback({ title, message, iconClass, toneClass }) {
        const toastEl = document.getElementById('feedback-toast');
        if (!toastEl || !window.bootstrap) {
            return;
        }

        const toastBody = toastEl.querySelector('.toast-body');
        const toastIcon = toastEl.querySelector('.toast-header i');
        const toastTitle = toastEl.querySelector('.toast-header strong');

        if (toastIcon) {
            toastIcon.className = iconClass;
            toastIcon.classList.remove('ast-text-info', 'ast-text-success', 'ast-text-warning');
            if (toneClass) toastIcon.classList.add(toneClass);
        }
        if (toastTitle) toastTitle.textContent = title;
        if (toastBody) toastBody.textContent = message;

        bootstrap.Toast.getOrCreateInstance(toastEl).show();
    }

    function pingAsset() {
        showFeedback({
            title: 'Testando...',
            message: 'Testando conectividade com o ativo...',
            iconClass: 'bi bi-hourglass-split me-2',
            toneClass: 'ast-text-warning'
        });

        setTimeout(() => {
            showFeedback({
                title: 'Sucesso',
                message: 'Ativo respondeu ao ping com sucesso!',
                iconClass: 'bi bi-check-circle-fill me-2',
                toneClass: 'ast-text-success'
            });
        }, 2000);
    }

    function scanPorts() {
        showFeedback({
            title: 'Escaneando...',
            message: 'Escaneando portas do ativo...',
            iconClass: 'bi bi-hourglass-split me-2',
            toneClass: 'ast-text-warning'
        });

        setTimeout(() => {
            showFeedback({
                title: 'Concluído',
                message: 'Escaneamento concluído. 5 portas abertas encontradas.',
                iconClass: 'bi bi-check-circle-fill me-2',
                toneClass: 'ast-text-success'
            });
        }, 3000);
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('ping-btn')?.addEventListener('click', pingAsset);
        document.getElementById('scan-btn')?.addEventListener('click', scanPorts);
    });
}());
