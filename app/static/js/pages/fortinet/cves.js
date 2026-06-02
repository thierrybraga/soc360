'use strict';

(function () {
    let currentPage = 1;
    let searchTimer = null;
    const els = {};

    function $(id) {
        return document.getElementById(id);
    }

    function escapeHtml(value) {
        return window.OpenMonitor?.utils?.escapeHtml
            ? window.OpenMonitor.utils.escapeHtml(value || '')
            : String(value || '').replace(/[&<>"']/g, char => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[char]));
    }

    function setVisible(element, visible, display = '') {
        if (!element) return;
        element.classList.toggle('is-hidden', !visible);
        element.style.display = visible ? display : 'none';
    }

    function severityBadge(severity) {
        if (!severity) return '<span class="sev-badge sev-LOW">-</span>';
        return `<span class="sev-badge sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>`;
    }

    function formatDate(iso) {
        if (!iso) return '-';
        return new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric' });
    }

    function loadProducts() {
        fetch('/fortinet/api/products')
            .then(response => response.json())
            .then(data => {
                (data.products || []).forEach(product => {
                    const option = document.createElement('option');
                    option.value = product.cpe_product || product.key;
                    option.textContent = product.name || product.key;
                    els.product.appendChild(option);
                });
            })
            .catch(() => {});
    }

    function loadCVEs(page) {
        if (page) currentPage = page;

        const params = new URLSearchParams({ page: currentPage, per_page: 50 });
        if (els.search.value.trim()) params.set('search', els.search.value.trim());
        if (els.product.value) params.set('product', els.product.value);
        if (els.severity.value) params.set('severity', els.severity.value);
        if (els.kev.value) params.set('cisa_kev', els.kev.value);

        els.tbody.innerHTML = '<tr><td colspan="7" class="ft-cell-center"><i class="fas fa-spinner fa-spin me-1"></i>Carregando...</td></tr>';

        fetch(`/fortinet/api/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                const items = data.items || [];
                const total = data.total || 0;
                const pages = data.pages || 1;

                setVisible(els.summary, true, 'block');
                els.summary.textContent = `Mostrando ${items.length} de ${total} CVE(s)`;

                if (!items.length) {
                    els.tbody.innerHTML = '<tr><td colspan="7" class="ft-cell-center">Nenhuma CVE encontrada com os filtros atuais.</td></tr>';
                    setVisible(els.paginationBar, false);
                    return;
                }

                els.tbody.innerHTML = items.map(renderCveRow).join('');
                renderPagination(currentPage, pages, total);
            })
            .catch(() => {
                els.tbody.innerHTML = '<tr><td colspan="7" class="ft-cell-error">Erro ao carregar CVEs.</td></tr>';
            });
    }

    function renderCveRow(cve) {
        const severity = cve.severity || cve.base_severity;
        const published = cve.published || cve.published_date;
        const isKev = cve.cisa_kev ?? cve.is_in_cisa_kev;
        const products = (cve.products || []).map(product => `<span class="prod-chip">${escapeHtml(product)}</span>`).join('');
        const flags = [
            isKev ? '<span class="flag-badge flag-kev"><i class="fas fa-flag"></i>KEV</span>' : '',
            cve.exploit_available ? '<span class="flag-badge flag-exploit"><i class="fas fa-bomb"></i>Exploit</span>' : '',
            cve.patch_available ? '<span class="flag-badge flag-patch"><i class="fas fa-wrench"></i>Patch</span>' : ''
        ].filter(Boolean).join(' ');
        const rawDescription = cve.description || '';
        const description = escapeHtml(rawDescription.substring(0, 200)) + (rawDescription.length > 200 ? '...' : '');
        const cvssClass = (cve.cvss_score || 0) >= 9 ? 'cvss-critical' : (cve.cvss_score || 0) >= 7 ? 'cvss-high' : '';

        return `<tr>
            <td><a href="/vulnerabilities/${escapeHtml(cve.cve_id)}" target="_blank" rel="noopener">${escapeHtml(cve.cve_id)}</a></td>
            <td>${severityBadge(severity)}</td>
            <td><strong class="${cvssClass}">${cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '-'}</strong></td>
            <td>${products || '<span class="text-muted">-</span>'}</td>
            <td class="text-nowrap">${flags || '<span class="text-muted">-</span>'}</td>
            <td class="text-nowrap text-muted">${formatDate(published)}</td>
            <td class="desc-cell"><p title="${description}">${description}</p></td>
        </tr>`;
    }

    function renderPagination(page, pages, total) {
        if (pages <= 1) {
            setVisible(els.paginationBar, false);
            return;
        }

        setVisible(els.paginationBar, true, 'flex');
        els.pageInfo.textContent = `Página ${page} de ${pages} · ${total} total`;

        let html = `<button class="page-btn" ${page <= 1 ? 'disabled' : ''} data-page="${page - 1}" aria-label="Página anterior"><i class="fas fa-chevron-left"></i></button>`;
        const range = [];
        for (let i = 1; i <= pages; i += 1) {
            if (i === 1 || i === pages || (i >= page - 2 && i <= page + 2)) range.push(i);
            else if (range[range.length - 1] !== '...') range.push('...');
        }
        range.forEach(item => {
            if (item === '...') html += '<button class="page-btn" disabled>...</button>';
            else html += `<button class="page-btn ${item === page ? 'active' : ''}" data-page="${item}">${item}</button>`;
        });
        html += `<button class="page-btn" ${page >= pages ? 'disabled' : ''} data-page="${page + 1}" aria-label="Próxima página"><i class="fas fa-chevron-right"></i></button>`;
        els.pageButtons.innerHTML = html;
    }

    function debounceLoad() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => loadCVEs(1), 350);
    }

    function clearFilters() {
        els.search.value = '';
        els.product.value = '';
        els.severity.value = '';
        els.kev.value = '';
        loadCVEs(1);
    }

    document.addEventListener('DOMContentLoaded', () => {
        Object.assign(els, {
            search: $('filter-search'),
            product: $('filter-product'),
            severity: $('filter-severity'),
            kev: $('filter-kev'),
            clearButton: $('clear-filters-btn'),
            summary: $('results-summary'),
            tbody: $('cves-tbody'),
            paginationBar: $('pagination-bar'),
            pageInfo: $('page-info'),
            pageButtons: $('page-btns')
        });

        if (!els.tbody) return;

        els.search?.addEventListener('input', debounceLoad);
        els.product?.addEventListener('change', () => loadCVEs(1));
        els.severity?.addEventListener('change', () => loadCVEs(1));
        els.kev?.addEventListener('change', () => loadCVEs(1));
        els.clearButton?.addEventListener('click', clearFilters);
        els.pageButtons?.addEventListener('click', event => {
            const button = event.target.closest('[data-page]');
            if (!button || button.disabled) return;
            loadCVEs(Number(button.dataset.page));
        });

        loadProducts();
        loadCVEs(1);
    });
}());
