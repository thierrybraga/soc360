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

    function loadVersions() {
        fetch('/fortinet/api/versions')
            .then(response => response.json())
            .then(data => {
                const supported = (data.versions || []).filter(version => version.is_supported).slice(0, 20);
                if (!supported.length || !els.version) {
                    return;
                }

                const group = document.createElement('optgroup');
                group.label = 'Suportadas';
                supported.forEach(version => {
                    const option = document.createElement('option');
                    option.value = version.version;
                    option.textContent = `${version.version} (${version.branch})`;
                    group.appendChild(option);
                });
                els.version.appendChild(group);
            })
            .catch(() => {});
    }

    function loadAssets(page) {
        if (page) currentPage = page;

        const search = els.search.value.trim();
        const criticality = els.criticality.value;
        const version = els.version.value;
        const params = new URLSearchParams({ page: currentPage, per_page: 25 });

        if (criticality) params.set('criticality', criticality);
        if (version) params.set('version', version);

        els.tbody.innerHTML = '<tr><td colspan="10" class="ft-cell-center"><i class="fas fa-spinner fa-spin me-1"></i>Carregando...</td></tr>';

        fetch(`/fortinet/api/assets?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                let items = data.items || [];
                if (search) {
                    const q = search.toLowerCase();
                    items = items.filter(asset =>
                        (asset.name || '').toLowerCase().includes(q) ||
                        (asset.ip_address || '').toLowerCase().includes(q) ||
                        (asset.hostname || '').toLowerCase().includes(q)
                    );
                }

                const total = data.total || 0;
                const pages = data.pages || 1;
                setVisible(els.summary, true, 'block');
                els.summary.textContent = `Mostrando ${items.length} de ${total} ativo(s)`;

                if (!items.length) {
                    els.tbody.innerHTML = '<tr><td colspan="10" class="ft-cell-center">Nenhum ativo Fortinet encontrado.</td></tr>';
                    setVisible(els.paginationBar, false);
                    return;
                }

                els.tbody.innerHTML = items.map(renderAssetRow).join('');
                renderPagination(currentPage, pages, total);
            })
            .catch(() => {
                els.tbody.innerHTML = '<tr><td colspan="10" class="ft-cell-error">Erro ao carregar assets.</td></tr>';
            });
    }

    function renderAssetRow(asset) {
        const isActive = asset.status === 'ACTIVE';
        const vuln = asset.vulnerability_count || 0;
        const open = asset.open_vulnerabilities || 0;
        const vulnClass = vuln === 0 ? 'vuln-chip--none' : vuln >= 20 ? 'vuln-chip--high' : 'vuln-chip--low';
        const openClass = open === 0 ? 'vuln-chip--none' : 'vuln-chip--high';
        const critMap = { CRITICAL: 'sev-CRITICAL', HIGH: 'sev-HIGH', MEDIUM: 'sev-MEDIUM', LOW: 'sev-LOW' };
        const criticality = asset.criticality
            ? `<span class="sev-badge ${critMap[asset.criticality] || ''}">${escapeHtml(asset.criticality)}</span>`
            : '<span class="text-muted">-</span>';
        const version = asset.os_version || asset.version || '';
        const eolTag = asset.version_eol
            ? '<span class="eol-tag eol-tag--eol">EOL</span>'
            : (!asset.version_supported && version ? '<span class="eol-tag eol-tag--old">Desatualizado</span>' : '');
        const environment = asset.environment
            ? `<span class="ft-muted-sm">${escapeHtml(asset.environment)}</span>`
            : '-';

        return `<tr>
            <td>
                <a href="/assets/${asset.id}">${escapeHtml(asset.name || '-')}</a>
                ${asset.hostname ? `<small class="ft-small-meta">${escapeHtml(asset.hostname)}</small>` : ''}
            </td>
            <td>
                <span class="ft-capitalize">${escapeHtml(asset.product_name || asset.os_name || '-')}</span>
                ${asset.vendor_name ? `<small class="ft-small-meta">${escapeHtml(asset.vendor_name)}</small>` : ''}
            </td>
            <td><code class="ft-code-sm">${escapeHtml(version || '-')}</code>${eolTag}</td>
            <td><code class="ft-code-sm">${escapeHtml(asset.ip_address || '-')}</code></td>
            <td>${environment}</td>
            <td>${criticality}</td>
            <td><span class="vuln-chip ${vulnClass}">${vuln}</span></td>
            <td><span class="vuln-chip ${openClass}">${open}</span></td>
            <td>
                <span class="ft-status-wrap">
                    <span class="status-dot ${isActive ? 'status-dot--active' : 'status-dot--inactive'}"></span>
                    <span class="ft-status-label">${escapeHtml(asset.status || '-')}</span>
                </span>
            </td>
            <td>
                <a href="/assets/${asset.id}" class="btn btn-sm btn-outline-secondary ft-btn-xs" aria-label="Ver ativo">
                    <i class="fas fa-eye"></i>
                </a>
            </td>
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
        for (let i = Math.max(1, page - 2); i <= Math.min(pages, page + 2); i += 1) {
            html += `<button class="page-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        html += `<button class="page-btn" ${page >= pages ? 'disabled' : ''} data-page="${page + 1}" aria-label="Próxima página"><i class="fas fa-chevron-right"></i></button>`;
        els.pageButtons.innerHTML = html;
    }

    function debounceLoad() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => loadAssets(1), 350);
    }

    function clearFilters() {
        els.search.value = '';
        els.criticality.value = '';
        els.version.value = '';
        loadAssets(1);
    }

    function scanAssets() {
        const originalHtml = els.scanButton.innerHTML;

        els.scanButton.disabled = true;
        els.scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Varrendo...';
        setVisible(els.scanResult, false);

        fetch('/fortinet/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
            },
            body: JSON.stringify({ scan_all: true, create_associations: true })
        })
            .then(response => response.json())
            .then(data => {
                els.scanButton.disabled = false;
                els.scanButton.innerHTML = originalHtml;

                const scanned = data.assets_scanned ?? data.total_assets ?? data.results?.length ?? 0;
                const newVulns = data.new_associations || 0;
                const totalMatches = data.total_matches || 0;
                els.scanResult.textContent = data.error
                    ? `Erro: ${data.error}`
                    : `Varredura concluída - ${scanned} ativo(s) verificado(s)` +
                        (totalMatches > 0 ? `, ${totalMatches} CVE(s) encontrada(s)` : '') +
                        (newVulns > 0 ? `, ${newVulns} nova(s) associação(ões)` : '') + '.';
                els.scanResult.classList.toggle('scan-result-bar--error', Boolean(data.error));
                setVisible(els.scanResult, true, 'block');
                setTimeout(() => {
                    setVisible(els.scanResult, false);
                    els.scanResult.classList.remove('scan-result-bar--error');
                }, 8000);
                loadAssets(1);
            })
            .catch(() => {
                els.scanButton.disabled = false;
                els.scanButton.innerHTML = originalHtml;
                els.scanResult.textContent = 'Erro ao executar varredura.';
                els.scanResult.classList.add('scan-result-bar--error');
                setVisible(els.scanResult, true, 'block');
            });
    }

    document.addEventListener('DOMContentLoaded', () => {
        Object.assign(els, {
            scanButton: $('btn-scan'),
            scanResult: $('scan-result'),
            search: $('filter-search'),
            criticality: $('filter-criticality'),
            version: $('filter-version'),
            summary: $('results-summary'),
            tbody: $('assets-tbody'),
            paginationBar: $('pagination-bar'),
            pageInfo: $('page-info'),
            pageButtons: $('page-btns'),
            clearButton: $('clear-filters-btn')
        });

        if (!els.tbody) return;

        els.scanButton?.addEventListener('click', scanAssets);
        els.search?.addEventListener('input', debounceLoad);
        els.criticality?.addEventListener('change', () => loadAssets(1));
        els.version?.addEventListener('change', () => loadAssets(1));
        els.clearButton?.addEventListener('click', clearFilters);
        els.pageButtons?.addEventListener('click', event => {
            const button = event.target.closest('[data-page]');
            if (!button || button.disabled) return;
            loadAssets(Number(button.dataset.page));
        });

        loadVersions();
        loadAssets(1);
    });
}());
