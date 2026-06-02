'use strict';

(function () {
    function validateInput(input) {
        const value = input.trim();
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)?$/;
        return ipRegex.test(value) || domainRegex.test(value);
    }

    function saveRecentSearch(query) {
        let recent = JSON.parse(localStorage.getItem('recentSearches') || '[]');
        recent = recent.filter(item => item !== query);
        recent.unshift(query);
        recent = recent.slice(0, 5);
        localStorage.setItem('recentSearches', JSON.stringify(recent));
    }

    document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('search-form');
        const input = document.getElementById('search-ip');
        const errorDiv = document.getElementById('ip-error');
        const searchBtn = document.getElementById('search-btn');
        const clearBtn = document.getElementById('clear-form');
        const clearInputBtn = document.getElementById('clear-input');
        const btnText = searchBtn?.querySelector('.btn-text');
        const btnLoading = searchBtn?.querySelector('.btn-loading');
        const recentContainer = document.getElementById('recent-searches');
        const recentList = document.getElementById('recent-searches-list');

        function loadRecentSearches() {
            const recent = JSON.parse(localStorage.getItem('recentSearches') || '[]');
            if (!recentList || !recentContainer) return;
            if (!recent.length) {
                recentContainer.classList.add('d-none');
                return;
            }
            recentList.innerHTML = recent.map(query => `
                <div class="recent-search-item" data-query="${OpenMonitor.utils.escapeHtml(query)}">
                    <i class="bi bi-clock-history me-2"></i>
                    <span>${OpenMonitor.utils.escapeHtml(query)}</span>
                    <button type="button" class="btn btn-sm btn-outline-danger remove-recent" data-query="${OpenMonitor.utils.escapeHtml(query)}" title="Remover">
                        <i class="bi bi-x"></i>
                    </button>
                </div>
            `).join('');
            recentContainer.classList.remove('d-none');
        }

        function removeRecentSearch(query) {
            let recent = JSON.parse(localStorage.getItem('recentSearches') || '[]');
            recent = recent.filter(item => item !== query);
            localStorage.setItem('recentSearches', JSON.stringify(recent));
        }

        input?.addEventListener('input', () => {
            const value = input.value.trim();
            if (value === '') {
                input.classList.remove('is-invalid', 'is-valid');
                if (errorDiv) errorDiv.textContent = '';
                if (clearInputBtn) clearInputBtn.style.display = 'none';
                return;
            }
            if (clearInputBtn) clearInputBtn.style.display = 'block';
            if (validateInput(value)) {
                input.classList.remove('is-invalid');
                input.classList.add('is-valid');
                if (errorDiv) errorDiv.textContent = '';
            } else {
                input.classList.remove('is-valid');
                input.classList.add('is-invalid');
                if (errorDiv) errorDiv.textContent = 'Digite um IP ou domínio válido.';
            }
        });

        form?.addEventListener('submit', event => {
            const value = input?.value.trim() || '';
            if (!validateInput(value)) {
                event.preventDefault();
                input?.classList.add('is-invalid');
                if (errorDiv) errorDiv.textContent = 'Digite um IP ou domínio válido.';
                return;
            }
            if (searchBtn) searchBtn.disabled = true;
            btnText?.classList.add('d-none');
            btnLoading?.classList.remove('d-none');
            saveRecentSearch(value);
        });

        clearBtn?.addEventListener('click', () => {
            form?.reset();
            input?.classList.remove('is-valid', 'is-invalid');
            if (errorDiv) errorDiv.textContent = '';
            if (clearInputBtn) clearInputBtn.style.display = 'none';
            input?.focus();
        });

        clearInputBtn?.addEventListener('click', () => {
            if (!input) return;
            input.value = '';
            input.classList.remove('is-valid', 'is-invalid');
            if (errorDiv) errorDiv.textContent = '';
            clearInputBtn.style.display = 'none';
            input.focus();
        });

        document.querySelectorAll('.example-query').forEach(button => {
            button.addEventListener('click', () => {
                const query = button.dataset.query;
                input.value = query;
                input.dispatchEvent(new Event('input'));
                input.focus();
                window.OpenMonitor?.showToast?.(`Exemplo carregado: ${query}`, 'success');
            });
        });

        recentList?.addEventListener('click', event => {
            const removeButton = event.target.closest('.remove-recent');
            if (removeButton) {
                event.stopPropagation();
                removeRecentSearch(removeButton.dataset.query);
                loadRecentSearches();
                return;
            }
            const item = event.target.closest('.recent-search-item');
            if (!item) return;
            input.value = item.dataset.query;
            input.dispatchEvent(new Event('input'));
            recentContainer?.classList.add('d-none');
        });

        input?.addEventListener('focus', () => {
            if (input.value.trim() === '') loadRecentSearches();
        });
        input?.addEventListener('blur', () => {
            setTimeout(() => recentContainer?.classList.add('d-none'), 200);
        });

        if (input?.value.trim()) {
            if (clearInputBtn) clearInputBtn.style.display = 'block';
            input.dispatchEvent(new Event('input'));
        }
        loadRecentSearches();
    });
}());
