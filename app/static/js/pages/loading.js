'use strict';

(function () {
    function checkSyncStatus() {
        fetch('/vulnerabilities/api/sync/status')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed' || data.status === 'idle') {
                    window.location.href = document.body.dataset.loadingRedirect || '/dashboard';
                    return;
                }

                const current = data.processed_cves || 0;
                const total = data.total_cves || 1;
                const progress = (current / total) * 100;
                const progressBar = document.getElementById('sync-progress-bar');
                const message = document.getElementById('sync-message');

                if (progressBar) {
                    progressBar.style.setProperty('--progress-width', `${progress}%`);
                    progressBar.setAttribute('aria-valuenow', String(Math.round(progress)));
                }
                if (message) {
                    message.textContent = `Processando: ${current} / ${total}`;
                }
                setTimeout(checkSyncStatus, 2000);
            })
            .catch(error => {
                console.error('Error checking sync status:', error);
                setTimeout(checkSyncStatus, 5000);
            });
    }

    document.addEventListener('DOMContentLoaded', checkSyncStatus);
}());
