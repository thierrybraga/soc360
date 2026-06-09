/**
 * Inventory Form Management JavaScript
 * Handles asset creation/editing
 */

'use strict';

let vendorProfiles = {};

document.addEventListener('DOMContentLoaded', function() {
    console.log('Inventory Form module loaded');
    
    // Add software button
    document.getElementById('add-software-btn')?.addEventListener('click', function() {
        addSoftwareRow();
    });

    // Form submission
    document.getElementById('asset-form')?.addEventListener('submit', saveAsset);

    // Event delegation for software list removal
    document.getElementById('software-list')?.addEventListener('click', function(e) {
        const removeBtn = e.target.closest('.btn-remove-software');
        if (removeBtn) {
            removeBtn.closest('.software-row').remove();
        }
    });

    // Handle vendor profile change to update product options
    document.getElementById('asset-vendor-profile')?.addEventListener('change', function() {
        updateProductOptions();
        applyVendorProfile();
    });

    document.getElementById('asset-model')?.addEventListener('input', applyVendorProfile);
    
    loadVendorProfiles();
    loadCategories();
    loadParentAssets();
});

function updateProductOptions() {
    const profileKey = document.getElementById('asset-vendor-profile')?.value;
    const productInput = document.getElementById('asset-product-name');
    const profile = vendorProfiles[profileKey];
    
    // If we have a product list for this profile, we could turn the input into a datalist or just suggest
    // For now, let's keep it as an input but maybe add a datalist
    let datalist = document.getElementById('product-suggestions');
    if (!datalist) {
        datalist = document.createElement('datalist');
        datalist.id = 'product-suggestions';
        document.body.appendChild(datalist);
        productInput.setAttribute('list', 'product-suggestions');
    }
    
    datalist.innerHTML = '';
    if (profile && profile.products) {
        profile.products.forEach(product => {
            const option = document.createElement('option');
            option.value = product.key;
            option.textContent = product.label;
            datalist.appendChild(option);
        });
    }
}

function addSoftwareRow(vendor = '', product = '', version = '') {
    const container = document.getElementById('software-list');
    const row = document.createElement('div');
    row.className = 'software-row d-flex gap-2 mb-2 align-items-center';
    row.innerHTML = `
        <div class="flex-grow-1 row g-2">
            <div class="col-md-4">
                <input type="text" class="form-input software-vendor" placeholder="Fabricante" value="${vendor}" required>
            </div>
            <div class="col-md-4">
                <input type="text" class="form-input software-product" placeholder="Produto" value="${product}" required>
            </div>
            <div class="col-md-4">
                <input type="text" class="form-input software-version" placeholder="Versão" value="${version}">
            </div>
        </div>
        <button type="button" class="btn btn-icon btn-ghost text-danger btn-remove-software" title="Remover">
            <i class="fas fa-trash"></i>
        </button>
    `;
    container.appendChild(row);
}

async function saveAsset(e) {
    e.preventDefault();
    
    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.innerHTML;
    
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
    
    // Collect software data
    const software = [];
    document.querySelectorAll('.software-row').forEach(row => {
        const vendor = row.querySelector('.software-vendor').value;
        const product = row.querySelector('.software-product').value;
        if (vendor && product) {
            software.push({
                vendor: vendor,
                product: product,
                version: row.querySelector('.software-version').value
            });
        }
    });
    
    const data = {
        name: document.getElementById('asset-name').value,
        asset_type: document.getElementById('asset-type').value,
        ip_address: document.getElementById('asset-ip').value,
        hostname: document.getElementById('asset-hostname').value,
        vendor_profile: document.getElementById('asset-vendor-profile')?.value || '',
        vendor_name: document.getElementById('asset-vendor-name')?.value || '',
        product_name: document.getElementById('asset-product-name')?.value || '',
        model: document.getElementById('asset-model')?.value || '',
        version: document.getElementById('asset-version')?.value || '',
        os_name: document.getElementById('asset-os-name')?.value || '',
        os_version: document.getElementById('asset-os-version')?.value || '',
        criticality: document.getElementById('asset-criticality').value,
        category_id: document.getElementById('asset-category')?.value || null,
        parent_id: document.getElementById('asset-parent')?.value || null,
        client_id: document.getElementById('asset-client')?.value || '',
        environment: document.getElementById('asset-environment')?.value || 'PRODUCTION',
        exposure: document.getElementById('asset-exposure')?.value || 'INTERNAL',
        description: document.getElementById('asset-description').value,
        rto_hours: document.getElementById('asset-rto').value ? parseFloat(document.getElementById('asset-rto').value) : null,
        rpo_hours: document.getElementById('asset-rpo').value ? parseFloat(document.getElementById('asset-rpo').value) : null,
        operational_cost_per_hour: document.getElementById('asset-cost').value ? parseFloat(document.getElementById('asset-cost').value) : null,
        installed_software: software
    };
    
    try {
        // Assume creation for now as we are on the Add page
        const url = '/assets/api/create';
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        
        console.log('Sending asset data:', data);
        
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            const cvesFound = result.correlation?.matched_cves || 0;
            const msg = cvesFound > 0
                ? `Ativo criado com sucesso! ${cvesFound} CVE(s) correlacionada(s).`
                : (result.message || 'Ativo criado com sucesso!');
            window.OpenMonitor?.showToast(msg, 'success');

            // Redirect to asset detail so the user immediately sees the
            // correlated CVEs — fall back to list if no asset id returned.
            const assetId = result.asset?.id;
            setTimeout(() => {
                window.location.href = assetId ? `/assets/${assetId}` : '/assets/';
            }, 1200);
        } else {
            throw new Error(result.error || result.message || 'Falha ao criar ativo.');
        }
    } catch (error) {
        console.error('Error saving asset:', error);
        window.OpenMonitor?.showToast(error.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;
    }
}

async function loadVendorProfiles() {
    try {
        const response = await fetch('/assets/api/vendor-profiles');
        if (!response.ok) return;
        const data = await response.json();
        const select = document.getElementById('asset-vendor-profile');
        if (!select || !Array.isArray(data.profiles)) return;
        data.profiles.forEach(profile => {
            vendorProfiles[profile.key] = profile;
            const option = document.createElement('option');
            option.value = profile.key;
            option.textContent = profile.label;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load vendor profiles:', error);
    }
}

async function loadCategories() {
    try {
        const response = await fetch('/assets/api/categories');
        if (!response.ok) return;
        const data = await response.json();
        const select = document.getElementById('asset-category');
        if (!select || !Array.isArray(data)) return;
        data.forEach(cat => {
            const option = document.createElement('option');
            option.value = cat.id;
            option.textContent = cat.name;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load categories:', error);
    }
}

async function loadParentAssets() {
    try {
        const response = await fetch('/assets/api/list?per_page=100');
        if (!response.ok) return;
        const data = await response.json();
        const select = document.getElementById('asset-parent');
        if (!select || !Array.isArray(data.items)) return;
        data.items.forEach(asset => {
            const option = document.createElement('option');
            option.value = asset.id;
            option.textContent = asset.name;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load parent assets:', error);
    }
}

// Per-profile heuristics: model token → { product, osName }
// Each entry is [tokenSubstring, productKey, osNameHint]
const PROFILE_MODEL_RULES = {
    fortinet: [
        [['fg', 'fortigate'],             'fortigate',     'FortiOS'],
        [['fmg', 'fortimanager'],         'fortimanager',  'FortiOS'],
        [['faz', 'fortianalyzer'],        'fortianalyzer', 'FortiOS'],
        [['fsw', 'fortiswitch'],          'fortiswitch',   'FortiOS'],
        [['fap', 'fortiap'],              'fortiap',       'FortiOS'],
        [['fml', 'fortimail'],            'fortimail',     'FortiOS'],
        [['fwb', 'fortiweb'],             'fortiweb',      'FortiOS'],
        [['fsb', 'fortisandbox'],         'fortisandbox',  'FortiOS'],
    ],
    cisco_meraki: [
        [['mx'],  'meraki_mx',        'Meraki Firmware'],
        [['mr'],  'meraki_mr',        'Meraki Firmware'],
        [['ms'],  'meraki_ms',        'Meraki Firmware'],
        [['mv'],  'meraki_mv',        'Meraki Firmware'],
    ],
    sophos: [
        [['xg', 'sfos'],              'xg_firewall',    'SFOS'],
        [['central'],                 'sophos_central', null],
        [['intercept', 'endpoint'],   'intercept_x',    null],
    ],
    wazuh: [
        [['manager'],  'wazuh_manager',   null],
        [['agent'],    'wazuh_agent',     null],
        [['dashboard'],'wazuh_dashboard', null],
    ],
    umbrella: [
        [['roaming', 'client'],        'umbrella_roaming_client', null],
        [['va', 'virtual appliance'],  'umbrella_va',             null],
        [['dashboard'],                'umbrella_dashboard',      null],
    ],
    zabbix: [
        [['server'],  'zabbix_server',  null],
        [['agent'],   'zabbix_agent',   null],
        [['proxy'],   'zabbix_proxy',   null],
    ],
    palo_alto: [
        [['pa-', 'pa', 'panos', 'pan-os'], 'pan_os',        'PAN-OS'],
        [['globalprotect', 'gp'],          'globalprotect', null],
        [['prisma'],                       'prisma_access', null],
    ],
    cisco_secure: [
        [['asa'],            'adaptive_security_appliance', null],
        [['ftd', 'firepower'],'firepower_threat_defense',   null],
        [['nexus', 'nx'],    'nx_os',                       'NX-OS'],
        [['xe'],             'ios_xe',                      'IOS XE'],
        [['xr'],             'ios_xr',                      'IOS XR'],
        [['isr', 'asr', 'catalyst', 'ios'], 'ios',         'IOS'],
    ],
    check_point: [
        [['quantum', 'sg'],  'quantum_security_gateway', 'Gaia OS'],
        [['gaia'],           'gaia_os',                  'Gaia OS'],
    ],
    juniper: [
        [['evolved'],              'junos_os_evolved', 'Junos OS Evolved'],
        [['srx', 'mx', 'ex', 'qfx', 'junos'], 'junos', 'Junos OS'],
    ],
    sonicwall: [
        [['tz', 'nsa', 'nsv', 'soho'], 'sonicos',                  'SonicOS'],
        [['gms'],                      'global_management_system', null],
    ],
    watchguard: [
        [['firebox', 't', 'm'], 'fireware', 'Fireware OS'],
    ],
    barracuda: [
        [['cgf', 'cloudgen'], 'cloudgen_firewall',       null],
        [['waf'],             'web_application_firewall', null],
    ],
    forcepoint: [
        [['ngfw'], 'next_generation_firewall', null],
        [['smc'],  'ngfw_security_management_center', null],
    ],
    pfsense: [
        [['plus'],    'pfsense_plus', 'pfSense Plus'],
        [['pfsense'], 'pfsense',      'pfSense'],
    ],
    mikrotik: [
        [['ccr', 'crs', 'hap', 'rb', 'routeros'], 'routeros', 'RouterOS'],
    ],
    ubiquiti: [
        [['edgerouter', 'er-', 'edgeos'], 'edgeos', 'EdgeOS'],
        [['udm', 'usg', 'unifi', 'dream'],'unifi',  'UniFi OS'],
        [['airos', 'airmax'],             'airos',  'airOS'],
    ],
    arista: [
        [['cloudvision', 'cvp'], 'cloudvision', null],
        [['eos'],                'eos',         'Arista EOS'],
    ],
    aruba: [
        [['cx', 'aoscx'],     'arubaos_cx',              'ArubaOS-CX'],
        [['iap', 'instant'],  'instant',                 'Instant'],
        [['clearpass', 'cppm'],'clearpass_policy_manager', null],
        [['arubaos', 'aos'],  'arubaos',                 'ArubaOS'],
    ],
    huawei: [
        [['usg'], 'usg', 'VRP'],
        [['ar', 'ne', 'vrp'], 'vrp', 'VRP'],
    ],
    zyxel: [
        [['usg', 'flex'], 'usg_flex', 'ZLD'],
        [['atp'],         'atp',      'ZLD'],
        [['zld'],         'zld',      'ZLD'],
    ],
    netgear: [
        [['rax', 'r7000', 'r8000', 'nighthawk'], 'nighthawk', null],
        [['fvs', 'prosafe'],                     'prosafe',   null],
    ],
    tp_link: [
        [['archer', 'ax'], 'archer', null],
        [['omada', 'er', 'tl'], 'omada', null],
    ],
    dlink: [
        [['dir'], 'dir', null],
        [['dsr'], 'dsr', null],
    ],
    asus: [
        [['merlin', 'asuswrt'], 'asuswrt', 'AsusWRT'],
        [['rt-', 'rt'],         'rt',      'AsusWRT'],
    ],
};

// Default OS name per profile when no model-specific rule matches
const PROFILE_DEFAULT_OS = {
    fortinet:     'FortiOS',
    cisco_meraki: 'Meraki Firmware',
    sophos:       'SFOS',
    wazuh:        null,
    umbrella:     null,
    zabbix:       null,
    palo_alto:    'PAN-OS',
    cisco_secure: 'IOS',
    check_point:  'Gaia OS',
    juniper:      'Junos OS',
    sonicwall:    'SonicOS',
    watchguard:   'Fireware OS',
    barracuda:    null,
    forcepoint:   null,
    pfsense:      'pfSense',
    mikrotik:     'RouterOS',
    ubiquiti:     null,
    arista:       'Arista EOS',
    aruba:        'ArubaOS',
    huawei:       'VRP',
    zyxel:        'ZLD',
    netgear:      null,
    tp_link:      null,
    dlink:        null,
    asus:         'AsusWRT',
};

function applyVendorProfile() {
    const profileKey = document.getElementById('asset-vendor-profile')?.value;
    const profile = vendorProfiles[profileKey];
    if (!profile) return;

    const vendorInput  = document.getElementById('asset-vendor-name');
    const productInput = document.getElementById('asset-product-name');
    const modelInput   = document.getElementById('asset-model');
    const osNameInput  = document.getElementById('asset-os-name');
    const modelValue   = (modelInput?.value || '').toLowerCase();

    // Always fill vendor name if blank
    if (vendorInput && !vendorInput.value) {
        vendorInput.value = profile.vendor_name;
    }

    const rules = PROFILE_MODEL_RULES[profileKey] || [];
    let matchedProduct = null;
    let matchedOsName  = null;

    for (const [tokens, productKey, osName] of rules) {
        if (tokens.some(t => modelValue.includes(t))) {
            matchedProduct = productKey;
            matchedOsName  = osName;
            break;
        }
    }

    // Fallback: first product in profile
    if (!matchedProduct && Array.isArray(profile.products) && profile.products.length > 0) {
        matchedProduct = profile.products[0].key;
    }
    if (!matchedOsName) {
        matchedOsName = PROFILE_DEFAULT_OS[profileKey] || null;
    }

    if (productInput && !productInput.value && matchedProduct) {
        productInput.value = matchedProduct;
    }
    if (osNameInput && !osNameInput.value && matchedOsName) {
        osNameInput.value = matchedOsName;
    }
}
