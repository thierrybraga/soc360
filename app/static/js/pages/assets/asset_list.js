'use strict';

(function () {
    document.addEventListener('DOMContentLoaded', () => {
        const deleteModalEl = document.getElementById('deleteAssetModal');
        const deleteForm = document.getElementById('delete-asset-form');
        const assetNameElement = document.getElementById('asset-name-to-delete');
        const deleteModal = deleteModalEl && window.bootstrap ? new bootstrap.Modal(deleteModalEl) : null;

        document.querySelectorAll('.delete-asset-btn').forEach(button => {
            button.addEventListener('click', () => {
                const assetId = button.dataset.assetId;
                const assetName = button.dataset.assetName;
                const urlTemplate = deleteForm?.dataset.deleteUrlTemplate || '';

                if (assetNameElement) {
                    assetNameElement.textContent = assetName || '';
                }
                if (deleteForm && assetId) {
                    deleteForm.action = urlTemplate.replace('ASSET_ID', assetId);
                }
                deleteModal?.show();
            });
        });

        const searchInput = document.getElementById('asset-search');
        const statusFilter = document.getElementById('status-filter');

        function filterAssets() {
            const searchTerm = (searchInput?.value || '').toLowerCase();
            const selectedStatus = statusFilter?.value || '';
            const rows = document.querySelectorAll('tbody tr[data-asset-id]');

            rows.forEach(row => {
                const name = row.querySelector('td:first-child')?.textContent.toLowerCase() || '';
                const ip = row.querySelector('code')?.textContent.toLowerCase() || '';
                const status = row.querySelector('.status-badge')?.className.toLowerCase() || '';
                const matchesSearch = name.includes(searchTerm) || ip.includes(searchTerm);
                const matchesStatus = !selectedStatus || status.includes(selectedStatus);

                row.classList.toggle('is-hidden', !(matchesSearch && matchesStatus));
            });
        }

        searchInput?.addEventListener('input', filterAssets);
        statusFilter?.addEventListener('change', filterAssets);

        document.getElementById('export-btn')?.addEventListener('click', () => {
            const toastEl = document.getElementById('feedback-toast');
            const toastBody = toastEl?.querySelector('.toast-body');
            if (toastBody) {
                toastBody.textContent = 'Funcionalidade de exportação em desenvolvimento.';
            }
            if (toastEl && window.bootstrap) {
                bootstrap.Toast.getOrCreateInstance(toastEl).show();
            }
        });
    });
}());
