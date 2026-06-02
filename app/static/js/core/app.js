/**
 * SOC360 v3.0 - Main Application JavaScript
 * Global utilities, API client, and UI components
 */

'use strict';

// =============================================================================
// APPLICATION NAMESPACE
// =============================================================================

window.SOC360 = window.SOC360 || {};
window.OpenMonitor = window.SOC360; // backward compat

// =============================================================================
// CONFIGURATION
// =============================================================================

SOC360.config = {
    apiBaseUrl: '',
    csrfToken: document.querySelector('meta[name="csrf-token"]')?.content,
    defaultTimeout: 30000,
    toastDuration: 5000,
    dateFormat: 'YYYY-MM-DD',
    dateTimeFormat: 'YYYY-MM-DD HH:mm:ss'
};

// =============================================================================
// API CLIENT
// =============================================================================

SOC360.api = {
    /**
     * Fetch a fresh CSRF token from the server and update the cached value
     * and the <meta name="csrf-token"> tag. Returns the new token (or null on failure).
     */
    async refreshCsrfToken() {
        try {
            const res = await fetch('/api/v1/csrf-token', {
                method: 'GET',
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' }
            });
            if (!res.ok) return null;
            const body = await res.json().catch(() => ({}));
            const token = body.csrf_token;
            if (token) {
                OpenMonitor.config.csrfToken = token;
                const meta = document.querySelector('meta[name="csrf-token"]');
                if (meta) meta.setAttribute('content', token);
                return token;
            }
        } catch (e) {
            /* fallthrough — return null */
        }
        return null;
    },

    /**
     * Generic request method
     */
    async request(endpoint, options = {}) {
        const url = `${OpenMonitor.config.apiBaseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

        const method = (options.method || 'GET').toUpperCase();
        const needsCsrf = !['GET', 'HEAD', 'OPTIONS'].includes(method);

        const buildConfig = () => {
            const defaultHeaders = { 'Content-Type': 'application/json' };
            if (needsCsrf) {
                defaultHeaders['X-CSRFToken'] = OpenMonitor.config.csrfToken || '';
            }
            return {
                credentials: 'same-origin',
                ...options,
                headers: {
                    ...defaultHeaders,
                    ...options.headers
                }
            };
        };

        const doFetch = async () => fetch(url, buildConfig());

        try {
            let response = await doFetch();

            // Handle 401 Unauthorized (redirect to login)
            if (response.status === 401) {
                window.location.href = '/auth/login';
                return;
            }

            // On CSRF failure (typically 400 with code CSRF_ERROR) — refresh
            // token once and retry before surfacing the error to the user.
            if (needsCsrf && response.status === 400 && !options._csrfRetry) {
                const cloned = response.clone();
                let payload = null;
                try { payload = await cloned.json(); } catch (_) { /* not json */ }
                const looksLikeCsrf = payload && (
                    payload.code === 'CSRF_ERROR' ||
                    /csrf/i.test(payload.message || payload.error || '')
                );
                if (looksLikeCsrf) {
                    const newToken = await this.refreshCsrfToken();
                    if (newToken) {
                        return this.request(endpoint, { ...options, _csrfRetry: true });
                    }
                }
            }

            // Handle different response types
            if (options.responseType === 'blob') {
                if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
                return await response.blob();
            }

            if (options.responseType === 'text') {
                if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
                return await response.text();
            }

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                throw new Error(data.error || data.message || `Request failed with status ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    },

    get(endpoint, params = {}, options = {}) {
        const queryString = OpenMonitor.utils.buildQueryString(params);
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, { method: 'GET', ...options });
    },

    post(endpoint, body = {}) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body)
        });
    },

    put(endpoint, body = {}) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(body)
        });
    },

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
};

// =============================================================================
// UTILITIES
// =============================================================================

OpenMonitor.utils = {
    /**
     * Debounce function execution
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Throttle function execution
     */
    throttle(func, limit) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func(...args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    /**
     * Format date to locale string
     */
    formatDate(dateString, options = {}) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleDateString('pt-BR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            ...options
        });
    },

    /**
     * Format datetime to locale string
     */
    formatDateTime(dateString, options = {}) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleString('pt-BR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            ...options
        });
    },

    /**
     * Format relative time (e.g., "2 hours ago")
     */
    formatRelativeTime(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins} min ago`;
        if (diffHours < 24) return `${diffHours} hours ago`;
        if (diffDays < 7) return `${diffDays} days ago`;
        return this.formatDate(dateString);
    },

    /**
     * Format number with thousand separators
     */
    formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return num.toLocaleString('pt-BR');
    },

    /**
     * Escape HTML entities
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Parse query string to object
     */
    parseQueryString(queryString) {
        const params = new URLSearchParams(queryString);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    },

    /**
     * Build query string from object
     */
    buildQueryString(params) {
        return Object.entries(params)
            .filter(([_, v]) => v !== null && v !== undefined && v !== '')
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
    },

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            console.error('Failed to copy:', err);
            return false;
        }
    },

    /**
     * Get severity color class
     */
    getSeverityClass(severity) {
        const classes = {
            'CRITICAL': 'badge-critical',
            'HIGH': 'badge-high',
            'MEDIUM': 'badge-medium',
            'LOW': 'badge-low',
            'NONE': 'badge-none'
        };
        return classes[severity?.toUpperCase()] || 'badge-none';
    },

    /**
     * Get severity color
     */
    getSeverityColor(severity) {
        const colors = {
            'CRITICAL': '#8b0000',
            'HIGH': '#ef4444',
            'MEDIUM': '#eab308',
            'LOW': '#22c55e',
            'NONE': '#6b7280'
        };
        return colors[severity?.toUpperCase()] || colors.NONE;
    },

    /**
     * Calculate CVSS severity from score
     */
    getCvssSeverity(score) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score > 0) return 'LOW';
        return 'NONE';
    },

    /**
     * Generate unique ID
     */
    generateId() {
        return `om_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
};

// =============================================================================
// UI COMPONENTS
// =============================================================================

OpenMonitor.ui = {
    /**
     * Show toast notification
     */
    toast(message, type = 'info', duration = OpenMonitor.config.toastDuration) {
        const container = document.querySelector('.toast-container') || this.createToastContainer();
        
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="toast-icon fas ${icons[type]}"></i>
            <div class="toast-content">
                <div class="toast-message">${OpenMonitor.utils.escapeHtml(message)}</div>
            </div>
            <button class="toast-close">
                <i class="fas fa-times"></i>
            </button>
        `;

        // Bind close event
        toast.querySelector('.toast-close').addEventListener('click', function() {
            this.parentElement.remove();
        });

        container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                toast.classList.add('hiding');
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    },

    /**
     * Create toast container if not exists
     */
    createToastContainer() {
        const container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
        return container;
    },

    /**
     * Show loading overlay
     */
    showLoading(message = 'Loading...') {
        let overlay = document.querySelector('.loading-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.className = 'loading-overlay';
            overlay.setAttribute('aria-hidden', 'false');
            overlay.innerHTML = `
                <div class="spinner"></div>
                <span class="loading-text">${OpenMonitor.utils.escapeHtml(message)}</span>
            `;
            document.body.appendChild(overlay);
        } else {
            let text = overlay.querySelector('.loading-text');
            if (!text) {
                text = document.createElement('span');
                text.className = 'loading-text';
                overlay.appendChild(text);
            }
            text.textContent = message;
        }
        overlay.classList.remove('is-hidden');
        overlay.setAttribute('aria-hidden', 'false');
        overlay.style.display = 'flex';
        return overlay;
    },

    /**
     * Hide loading overlay
     */
    hideLoading() {
        const overlay = document.querySelector('.loading-overlay');
        if (overlay) {
            overlay.classList.add('is-hidden');
            overlay.setAttribute('aria-hidden', 'true');
            overlay.style.display = 'none';
        }
    },

    /**
     * Show confirmation dialog
     */
    async confirm(message, options = {}) {
        return new Promise((resolve) => {
            // Create modal with proper Bootstrap 5 structure
            const modal = document.createElement('div');
            modal.className = 'modal fade show';
            modal.style.display = 'block';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            
            modal.innerHTML = `
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas ${options.icon || 'fa-question-circle'} me-2"></i>
                                ${options.title || 'Confirmar'}
                            </h5>
                            <button type="button" class="btn-close" data-action="cancel" aria-label="Fechar"></button>
                        </div>
                        <div class="modal-body">
                            <p class="mb-0">${OpenMonitor.utils.escapeHtml(message)}</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-action="cancel">
                                ${options.cancelText || 'Cancelar'}
                            </button>
                            <button type="button" class="btn ${options.confirmClass || 'btn-primary'}" data-action="confirm">
                                ${options.confirmText || 'Confirmar'}
                            </button>
                        </div>
                    </div>
                </div>
            `;

            // Create backdrop
            const backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop fade show';

            // Prevent body scroll
            document.body.classList.add('modal-open');
            document.body.style.overflow = 'hidden';
            
            document.body.appendChild(backdrop);
            document.body.appendChild(modal);

            const cleanup = () => {
                modal.classList.remove('show');
                backdrop.classList.remove('show');
                document.body.classList.remove('modal-open');
                document.body.style.overflow = '';
                setTimeout(() => {
                    modal.remove();
                    backdrop.remove();
                }, 150);
            };

            // Bind events
            modal.querySelector('[data-action="cancel"]').addEventListener('click', () => {
                cleanup();
                resolve(false);
            });

            modal.querySelector('[data-action="confirm"]').addEventListener('click', () => {
                cleanup();
                resolve(true);
            });

            backdrop.addEventListener('click', () => {
                cleanup();
                resolve(false);
            });

            // Handle Escape key
            const handleEscape = (e) => {
                if (e.key === 'Escape') {
                    cleanup();
                    resolve(false);
                    document.removeEventListener('keydown', handleEscape);
                }
            };
            document.addEventListener('keydown', handleEscape);
        });
    },

    /**
     * Initialize modal functionality
     */
    initModals() {
        document.querySelectorAll('[data-modal-toggle]').forEach(trigger => {
            trigger.addEventListener('click', () => {
                const modalId = trigger.dataset.modalToggle;
                const modal = document.getElementById(modalId);
                const backdrop = document.querySelector('.modal-backdrop') || this.createBackdrop();
                
                if (modal) {
                    modal.classList.toggle('show');
                    backdrop.classList.toggle('show');
                }
            });
        });

        document.querySelectorAll('.modal-close, [data-modal-close]').forEach(closeBtn => {
            closeBtn.addEventListener('click', () => {
                const modal = closeBtn.closest('.modal');
                const backdrop = document.querySelector('.modal-backdrop');
                
                if (modal) modal.classList.remove('show');
                if (backdrop) backdrop.classList.remove('show');
            });
        });
    },

    /**
     * Create modal backdrop
     */
    createBackdrop() {
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        document.body.appendChild(backdrop);
        return backdrop;
    },

    /**
     * Initialize dropdown menus
     */
    initDropdowns() {
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            const toggle = dropdown.querySelector('.dropdown-toggle, [data-dropdown-toggle]');
            const menu = dropdown.querySelector('.dropdown-menu');

            if (toggle && menu) {
                toggle.addEventListener('click', (e) => {
                    e.stopPropagation();
                    // Close other dropdowns
                    document.querySelectorAll('.dropdown-menu.show').forEach(m => {
                        if (m !== menu) m.classList.remove('show');
                    });
                    menu.classList.toggle('show');
                });
            }
        });

        // Close dropdowns on outside click
        document.addEventListener('click', () => {
            document.querySelectorAll('.dropdown-menu.show').forEach(menu => {
                menu.classList.remove('show');
            });
        });
    },

    /**
     * Initialize tabs
     */
    initTabs() {
        document.querySelectorAll('.tabs').forEach(tabContainer => {
            const tabs = tabContainer.querySelectorAll('.tab');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const targetId = tab.dataset.tab;
                    
                    // Update active tab
                    tabs.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    
                    // Update active content
                    const contentContainer = tabContainer.nextElementSibling;
                    if (contentContainer) {
                        contentContainer.querySelectorAll('.tab-content').forEach(content => {
                            content.classList.toggle('active', content.id === targetId);
                        });
                    }
                });
            });
        });
    },

    /**
     * Initialize tooltips
     */
    initTooltips() {
        // Tooltips are CSS-only via [data-tooltip] attribute
    },

    /**
     * Initialize global keyboard shortcuts
     */
    initShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Search shortcut (Ctrl+K or Cmd+K)
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('globalSearch');
                if (searchInput) {
                    searchInput.focus();
                }
            }
        });
    },

    /**
     * Set button loading state
     */
    setButtonLoading(button, loading) {
        if (loading) {
            button.disabled = true;
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
        } else {
            button.disabled = false;
            button.innerHTML = button.dataset.originalText || button.innerHTML;
        }
    }
};

OpenMonitor.showToast = (...args) => OpenMonitor.ui.toast(...args);
OpenMonitor.showLoading = (...args) => OpenMonitor.ui.showLoading(...args);
OpenMonitor.hideLoading = () => OpenMonitor.ui.hideLoading();
OpenMonitor.confirm = (...args) => OpenMonitor.ui.confirm(...args);

OpenMonitor.page = {
    getRoot(pageName = null) {
        if (pageName) {
            return document.querySelector(`[data-page="${pageName}"]`);
        }
        return document.querySelector('[data-page]') || document.querySelector('.page-content');
    },

    setBusy(element, busy = true) {
        if (!element) {
            return;
        }
        element.classList.toggle('loading-disabled', busy);
        element.setAttribute('aria-busy', busy ? 'true' : 'false');
    },

    createEmptyState({ icon = 'fa-circle-info', title = 'Nenhum dado encontrado', description = '', actionHtml = '' } = {}) {
        return `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <i class="fas ${icon}"></i>
                </div>
                <h5 class="empty-state-title">${OpenMonitor.utils.escapeHtml(title)}</h5>
                <p class="empty-state-text">${OpenMonitor.utils.escapeHtml(description)}</p>
                ${actionHtml}
            </div>
        `;
    }
};

// =============================================================================
// FORM UTILITIES
// =============================================================================

OpenMonitor.forms = {
    /**
     * Serialize form to object
     */
    serialize(form) {
        const formData = new FormData(form);
        const data = {};
        
        for (const [key, value] of formData.entries()) {
            if (data[key]) {
                if (!Array.isArray(data[key])) {
                    data[key] = [data[key]];
                }
                data[key].push(value);
            } else {
                data[key] = value;
            }
        }
        
        return data;
    },

    /**
     * Validate form
     */
    validate(form) {
        const inputs = form.querySelectorAll('[required]');
        let isValid = true;
        
        inputs.forEach(input => {
            if (!input.value.trim()) {
                this.showError(input, 'This field is required');
                isValid = false;
            } else {
                this.clearError(input);
            }
        });
        
        return isValid;
    },

    /**
     * Show field error
     */
    showError(input, message) {
        input.classList.add('error');
        const group = input.closest('.form-group');
        if (group) {
            let errorEl = group.querySelector('.form-error');
            if (!errorEl) {
                errorEl = document.createElement('div');
                errorEl.className = 'form-error';
                group.appendChild(errorEl);
            }
            errorEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
        }
    },

    /**
     * Clear field error
     */
    clearError(input) {
        input.classList.remove('error');
        const group = input.closest('.form-group');
        if (group) {
            const errorEl = group.querySelector('.form-error');
            if (errorEl) errorEl.remove();
        }
    },

    /**
     * Clear all form errors
     */
    clearAllErrors(form) {
        form.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
        form.querySelectorAll('.form-error').forEach(el => el.remove());
    }
};

// =============================================================================
// THEME MANAGER
// =============================================================================

OpenMonitor.theme = {
    /**
     * Initialize theme from localStorage
     */
    init() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        this.set(savedTheme);
        
        // Listen for toggle button
        const toggleBtn = document.querySelector('[data-theme-toggle]');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggle());
        }
    },

    /**
     * Set theme
     */
    set(theme) {
        document.documentElement.dataset.theme = theme;
        localStorage.setItem('theme', theme);
        
        // Update toggle button icon
        const toggleBtn = document.querySelector('[data-theme-toggle]');
        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            }
        }
    },

    /**
     * Toggle theme
     */
    toggle() {
        const current = document.documentElement.dataset.theme || 'dark';
        this.set(current === 'dark' ? 'light' : 'dark');
    },

    /**
     * Get current theme
     */
    get() {
        return document.documentElement.dataset.theme || 'dark';
    }
};

// =============================================================================
// SIDEBAR MANAGER
// =============================================================================

OpenMonitor.sidebar = {
    _overlay: null,
    _sidebar: null,
    _toggle: null,

    /**
     * Initialize sidebar
     */
    init() {
        this._toggle = document.querySelector('.menu-toggle');
        this._sidebar = document.querySelector('.sidebar');

        if (!this._sidebar) return;

        // Create overlay for mobile
        this._overlay = document.createElement('div');
        this._overlay.className = 'sidebar-overlay';
        document.body.appendChild(this._overlay);

        // Toggle button
        if (this._toggle) {
            this._toggle.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggle();
            });
        }

        // Click overlay to close
        this._overlay.addEventListener('click', () => this.close());

        // ESC key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen()) this.close();
        });

        // Close on nav link click (mobile)
        this._sidebar.querySelectorAll('.nav-item').forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 1024) this.close();
            });
        });

        // Handle resize: close mobile sidebar when going to desktop
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                if (window.innerWidth > 1024) this.close();
            }, 100);
        });

        // Init nav group dropdowns
        this.initGroups();

        // Set active nav item
        this.setActiveNav();
    },

    /**
     * Initialize nav group dropdown toggles
     */
    initGroups() {
        document.querySelectorAll('.nav-group-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const group = btn.closest('.nav-group');
                if (!group) return;
                group.classList.toggle('open');
            });
        });
    },

    isOpen() {
        return this._sidebar && this._sidebar.classList.contains('open');
    },

    toggle() {
        if (this.isOpen()) {
            this.close();
        } else {
            this.open();
        }
    },

    open() {
        if (!this._sidebar) return;
        this._sidebar.classList.add('open');
        if (this._overlay) this._overlay.classList.add('visible');
        if (this._toggle) this._toggle.setAttribute('aria-expanded', 'true');
        document.body.style.overflow = 'hidden';
    },

    close() {
        if (!this._sidebar) return;
        this._sidebar.classList.remove('open');
        if (this._overlay) this._overlay.classList.remove('visible');
        if (this._toggle) this._toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
    },

    /**
     * Set active navigation item based on current URL
     */
    setActiveNav() {
        const currentPath = window.location.pathname;
        document.querySelectorAll('.nav-item').forEach(item => {
            const href = item.getAttribute('href');
            if (href && currentPath.startsWith(href)) {
                item.classList.add('active');
            }
        });
    }
};

// =============================================================================
// GLOBAL SEARCH
// =============================================================================

OpenMonitor.search = {
    /**
     * Initialize global event listeners
     */
    initGlobalListeners() {
        // Go back button
        document.body.addEventListener('click', (e) => {
            const btn = e.target.closest('#go-back-btn, .js-go-back');
            if (btn) {
                e.preventDefault();
                window.history.back();
            }
        });
    },

    /**
     * Initialize global search
     */
    init() {
        this.initGlobalListeners();

        const searchInput = document.querySelector('.search-box input');
        if (!searchInput) return;

        const debouncedSearch = OpenMonitor.utils.debounce((query) => {
            if (query.length >= 3) {
                this.performSearch(query);
            }
        }, 300);

        searchInput.addEventListener('input', (e) => {
            debouncedSearch(e.target.value);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const query = e.target.value.trim();
                if (query) {
                    window.location.href = `/vulnerabilities?search=${encodeURIComponent(query)}`;
                }
            }
        });
    },

    /**
     * Perform search (could show dropdown results)
     */
    async performSearch(query) {
        try {
            const results = await OpenMonitor.api.get('/vulnerabilities/api/search', { q: query, limit: 5 });
            // Could show dropdown with results here
            console.log('Search results:', results);
        } catch (error) {
            console.error('Search error:', error);
        }
    }
};

// =============================================================================
// DECLARATIVE ACTIONS
// =============================================================================

OpenMonitor.actions = {
    init() {
        document.addEventListener('click', (event) => {
            const trigger = event.target.closest('[data-action]');
            if (!trigger) {
                return;
            }

            const action = trigger.dataset.action;
            if (action === 'reload-page') {
                event.preventDefault();
                window.location.reload();
            }

            if (action === 'print-page') {
                event.preventDefault();
                window.print();
            }

            if (action === 'reset-form') {
                event.preventDefault();
                const form = trigger.closest('form') || document.querySelector(trigger.dataset.formTarget);
                form?.reset();
                form?.classList.remove('was-validated');
            }

            if (action === 'hide-target') {
                event.preventDefault();
                document.querySelector(trigger.dataset.target)?.classList.add('is-hidden');
            }

            if (action === 'copy-text') {
                event.preventDefault();
                this.copyText(trigger.dataset.copyText || '');
            }

            if (action === 'copy-element-text') {
                event.preventDefault();
                const element = document.getElementById(trigger.dataset.copyTarget || '');
                this.copyText(element?.innerText || element?.textContent || '');
            }
        });

        document.addEventListener('submit', (event) => {
            const form = event.target.closest('form[data-confirm]');
            if (!form) {
                return;
            }

            const message = form.dataset.confirm;
            if (message && !window.confirm(message)) {
                event.preventDefault();
            }
        });

        document.addEventListener('change', (event) => {
            const select = event.target.closest('[data-pagination-per-page]');
            if (!select) {
                return;
            }

            const url = new URL(window.location);
            url.searchParams.set('per_page', select.value);
            url.searchParams.set('page', '1');
            window.location.href = url.toString();
        });

        document.querySelectorAll('[data-progress-width]').forEach(element => {
            element.style.setProperty('--progress-width', element.dataset.progressWidth);
        });
    },

    async copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            const toastElement = document.getElementById('copyToast');
            if (toastElement && window.bootstrap) {
                bootstrap.Toast.getOrCreateInstance(toastElement).show();
                return;
            }
            window.OpenMonitor?.showToast?.('Texto copiado', 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            window.OpenMonitor?.showToast?.('Erro ao copiar', 'error');
        }
    }
};

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    OpenMonitor.theme.init();
    
    // Initialize sidebar
    OpenMonitor.sidebar.init();
    
    // Initialize UI components
    OpenMonitor.ui.initModals();
    OpenMonitor.ui.initDropdowns();
    OpenMonitor.ui.initTabs();
    OpenMonitor.ui.initTooltips();
    OpenMonitor.ui.initShortcuts();
    
    // Global "Go Back" button handler
    document.addEventListener('click', (e) => {
        const goBackBtn = e.target.closest('#go-back-btn, .js-go-back');
        if (goBackBtn) {
            e.preventDefault();
            window.history.back();
        }
    });
    
    // Initialize global search
    OpenMonitor.search.init();

    // Initialize declarative actions
    OpenMonitor.actions.init();
    
    // Handle flash messages auto-dismiss
    document.querySelectorAll('.flash-messages .alert, .flash-message').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            setTimeout(() => flash.remove(), 300);
        }, 5000);
    });

    // Handle AJAX form submissions
    document.querySelectorAll('form[data-ajax]').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!OpenMonitor.forms.validate(form)) return;
            
            const submitBtn = form.querySelector('[type="submit"]');
            OpenMonitor.ui.setButtonLoading(submitBtn, true);
            
            try {
                const data = OpenMonitor.forms.serialize(form);
                const method = form.method?.toUpperCase() || 'POST';
                const action = form.action || window.location.href;
                
                const response = await OpenMonitor.api.request(action, {
                    method,
                    body: data
                });
                
                if (response.redirect) {
                    window.location.href = response.redirect;
                } else {
                    OpenMonitor.ui.toast(response.message || 'Success!', 'success');
                    if (form.dataset.reset !== 'false') {
                        form.reset();
                    }
                }
            } catch (error) {
                OpenMonitor.ui.toast(error.message || 'An error occurred', 'error');
            } finally {
                OpenMonitor.ui.setButtonLoading(submitBtn, false);
            }
        });
    });

    console.log('SOC360 v3.0 initialized');
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OpenMonitor;
}
