/**
 * SOC360 Rule Form Module
 * Handles create/edit rule page logic.
 */

class RuleFormModule {
    constructor() {
        this.ruleId = document.getElementById('rule-id')?.value || null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadVendors();
    }

    bindEvents() {
        // Type selector cards
        document.getElementById('type-selector')?.addEventListener('click', (e) => {
            const card = e.target.closest('.type-option');
            if (!card) return;
            const type = card.dataset.type;
            this.selectType(type);
        });

        // Channel selector cards
        document.getElementById('channel-selector')?.addEventListener('click', (e) => {
            const card = e.target.closest('.channel-option');
            if (!card) return;
            const channel = card.dataset.channel;
            this.selectChannel(channel);
        });

        // Save
        document.getElementById('save-rule-btn')?.addEventListener('click', () => {
            this.saveRule();
        });

        // Test
        document.getElementById('test-rule-btn')?.addEventListener('click', () => {
            this.testRule();
        });

        // Vendor change -> load products
        document.getElementById('rule-vendor')?.addEventListener('change', (e) => {
            this.loadProducts(e.target.value);
        });
    }

    selectType(type) {
        document.querySelectorAll('.type-option').forEach(el => el.classList.remove('active'));
        const card = document.querySelector(`.type-option[data-type="${type}"]`);
        if (card) card.classList.add('active');
        document.getElementById('rule-type').value = type;

        // Show/hide config sections
        const severityOpts = document.getElementById('severity-options');
        const vendorOpts = document.getElementById('vendor-options');

        if (severityOpts) {
            severityOpts.style.display = (type === 'SEVERITY_THRESHOLD' || type === 'CISA_KEV') ? 'block' : 'none';
        }
        if (vendorOpts) {
            vendorOpts.style.display = type === 'VENDOR_SPECIFIC' ? 'block' : 'none';
        }
    }

    selectChannel(channel) {
        document.querySelectorAll('.channel-option').forEach(el => el.classList.remove('active'));
        const card = document.querySelector(`.channel-option[data-channel="${channel}"]`);
        if (card) card.classList.add('active');
        document.getElementById('rule-channel').value = channel;

        // Show/hide channel config
        const emailOpts = document.getElementById('email-options');
        const webhookOpts = document.getElementById('webhook-options');
        const slackOpts = document.getElementById('slack-options');

        if (emailOpts) emailOpts.style.display = channel === 'EMAIL' ? 'block' : 'none';
        if (webhookOpts) webhookOpts.style.display = channel === 'WEBHOOK' ? 'block' : 'none';
        if (slackOpts) slackOpts.style.display = channel === 'SLACK' ? 'block' : 'none';
    }

    loadRuleData(rule) {
        if (!rule) return;

        this.ruleId = rule.id;

        document.getElementById('rule-name').value = rule.name || '';
        document.getElementById('rule-description').value = rule.description || '';
        document.getElementById('rule-cooldown').value = rule.cooldown_minutes || 60;
        document.getElementById('rule-max-alerts').value = rule.max_alerts_per_day || 10;
        document.getElementById('rule-enabled').checked = rule.enabled;

        // Select type
        if (rule.rule_type) {
            this.selectType(rule.rule_type);
        }

        // Select channel
        const channel = rule.notification_channels && rule.notification_channels.length > 0
            ? rule.notification_channels[0] : '';
        if (channel) {
            this.selectChannel(channel);
        }

        // Fill type-specific params
        if (rule.parameters) {
            if (rule.parameters.min_severity) {
                const el = document.getElementById('rule-min-severity');
                if (el) el.value = rule.parameters.min_severity;
            }
            if (rule.parameters.vendors && rule.parameters.vendors.length > 0) {
                const el = document.getElementById('rule-vendor');
                if (el) el.value = rule.parameters.vendors[0];
            }
        }

        // Fill channel-specific config
        if (rule.notification_config) {
            if (rule.notification_config.recipients) {
                const el = document.getElementById('rule-recipients');
                if (el) el.value = rule.notification_config.recipients.join(', ');
            }
            if (rule.notification_config.webhook_url) {
                const el = document.getElementById('rule-webhook-url');
                if (el) el.value = rule.notification_config.webhook_url;
            }
            if (rule.notification_config.slack_url) {
                const el = document.getElementById('rule-slack-url');
                if (el) el.value = rule.notification_config.slack_url;
            }
            if (rule.notification_config.slack_channel) {
                const el = document.getElementById('rule-slack-channel');
                if (el) el.value = rule.notification_config.slack_channel;
            }
        }
    }

    async saveRule() {
        const name = document.getElementById('rule-name').value;
        const type = document.getElementById('rule-type').value;
        const channel = document.getElementById('rule-channel').value;

        if (!name) {
            window.OpenMonitor?.showToast('Rule name is required', 'warning');
            return;
        }
        if (!type) {
            window.OpenMonitor?.showToast('Please select a rule type', 'warning');
            return;
        }
        if (!channel) {
            window.OpenMonitor?.showToast('Please select an alert channel', 'warning');
            return;
        }

        const payload = {
            name: name,
            description: document.getElementById('rule-description').value,
            rule_type: type,
            notification_channels: [channel],
            cooldown_minutes: parseInt(document.getElementById('rule-cooldown').value) || 60,
            max_alerts_per_day: parseInt(document.getElementById('rule-max-alerts').value) || 10,
            enabled: document.getElementById('rule-enabled').checked,
            parameters: {},
            notification_config: {}
        };

        // Type-specific params
        if (type === 'SEVERITY_THRESHOLD' || type === 'CISA_KEV') {
            payload.parameters.min_severity = document.getElementById('rule-min-severity').value;
        }
        if (type === 'VENDOR_SPECIFIC') {
            const vendor = document.getElementById('rule-vendor').value;
            if (vendor) payload.parameters.vendors = [vendor];
            const product = document.getElementById('rule-product').value;
            if (product) payload.parameters.products = [product];
        }
        if (type === 'CISA_KEV') {
            payload.parameters.cisa_kev_only = true;
        }

        // Channel-specific config
        if (channel === 'EMAIL') {
            const recipients = document.getElementById('rule-recipients').value;
            if (recipients) {
                payload.notification_config.recipients = recipients.split(',').map(e => e.trim()).filter(e => e);
            }
        } else if (channel === 'WEBHOOK') {
            payload.notification_config.webhook_url = document.getElementById('rule-webhook-url').value;
        } else if (channel === 'SLACK') {
            payload.notification_config.slack_url = document.getElementById('rule-slack-url').value;
            payload.notification_config.slack_channel = document.getElementById('rule-slack-channel').value;
        }

        const btn = document.getElementById('save-rule-btn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

        try {
            if (this.ruleId) {
                await OpenMonitor.api.put(`/monitoring/api/rules/${this.ruleId}`, payload);
            } else {
                const result = await OpenMonitor.api.post('/monitoring/api/rules', payload);
                // Redirect to edit page after creation
                if (result.rule && result.rule.id) {
                    window.OpenMonitor?.showToast('Rule created successfully', 'success');
                    window.location.href = `/monitoring/rules/${result.rule.id}/edit`;
                    return;
                }
            }
            window.OpenMonitor?.showToast('Rule saved successfully', 'success');
        } catch (error) {
            console.error('Save failed:', error);
            window.OpenMonitor?.showToast(error.message || 'Failed to save rule', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    async testRule() {
        if (!this.ruleId) {
            window.OpenMonitor?.showToast('Save the rule first before testing', 'warning');
            return;
        }

        const btn = document.getElementById('test-rule-btn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';

        try {
            const data = await OpenMonitor.api.post(`/monitoring/api/rules/${this.ruleId}/test`, {
                cve_id: 'CVE-2021-44228'
            });

            const matched = data.matches ? 'MATCHED' : 'DID NOT MATCH';
            const type = data.matches ? 'success' : 'info';
            window.OpenMonitor?.showToast(`Test: Rule ${matched} test CVE (${data.test_cve})`, type);
        } catch (error) {
            console.error('Test failed:', error);
            window.OpenMonitor?.showToast(error.message || 'Test failed', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    async loadVendors() {
        const select = document.getElementById('rule-vendor');
        if (!select) return;

        try {
            const response = await fetch('/vulnerabilities/api/vendors');
            if (!response.ok) return;
            const data = await response.json();

            if (data.vendors) {
                const currentVal = select.value;
                const firstOption = select.querySelector('option');
                select.innerHTML = '';
                if (firstOption) select.appendChild(firstOption);

                data.vendors.forEach(v => {
                    const opt = document.createElement('option');
                    opt.value = v.name;
                    opt.textContent = `${v.name} (${v.count})`;
                    select.appendChild(opt);
                });

                if (currentVal) select.value = currentVal;
            }
        } catch (error) {
            console.error('Failed to load vendors:', error);
        }
    }

    async loadProducts(vendor) {
        const select = document.getElementById('rule-product');
        if (!select) return;

        select.innerHTML = '<option value="">All Products</option>';
        if (!vendor) return;

        try {
            const response = await fetch(`/vulnerabilities/api/products?vendor=${encodeURIComponent(vendor)}`);
            if (!response.ok) return;
            const data = await response.json();

            if (data.products) {
                data.products.forEach(p => {
                    const opt = document.createElement('option');
                    opt.value = p.name;
                    opt.textContent = `${p.name} (${p.count})`;
                    select.appendChild(opt);
                });
            }
        } catch (error) {
            console.error('Failed to load products:', error);
        }
    }
}

// Initialize
const ruleFormModule = new RuleFormModule();
window.ruleFormModule = ruleFormModule;

const ruleDataElement = document.getElementById('rule-data');
if (ruleDataElement?.dataset.rule) {
    try {
        ruleFormModule.loadRuleData(JSON.parse(ruleDataElement.dataset.rule));
    } catch (error) {
        console.error('Failed to parse rule data:', error);
    }
}
