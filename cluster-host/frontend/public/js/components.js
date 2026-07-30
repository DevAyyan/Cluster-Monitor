// Components module for Fleet Monitor UI (Modal, Tab Managers, Containers, Processes, Applications, Alerts, Logs)

// Centralized fetch interceptor to handle session expiration (401 Unauthorized)
(function() {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        try {
            const resp = await originalFetch(...args);
            if (resp.status === 401) {
                const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url);
                if (url && url.includes('/api/') && !url.includes('/api/auth/login') && !url.includes('/api/auth/github/callback') && !url.includes('/api/auth/logout')) {
                    console.warn("Session expired or invalid (401 Unauthorized). Redirecting to login page...");
                    window.location.href = '/static/login.html';
                }
            }
            return resp;
        } catch (err) {
            throw err;
        }
    };
})();

// Toast Notification System
const activeToastSet = new Set();
let rulesCache = {};

function showToast(title, message, type = 'error', duration = 6000, allowHtml = false) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toastKey = `${type}:${title}:${message}`;
    if (activeToastSet.has(toastKey)) return;
    activeToastSet.add(toastKey);

    const toast = document.createElement('div');
    toast.className = `toast-item ${type}`;

    let iconClass = 'fa-solid fa-circle-exclamation';
    if (type === 'error') iconClass = 'fa-solid fa-triangle-exclamation';
    if (type === 'warning') iconClass = 'fa-solid fa-circle-exclamation';
    if (type === 'success') iconClass = 'fa-solid fa-circle-check';
    if (type === 'info') iconClass = 'fa-solid fa-circle-info';

    toast.innerHTML = `
        <i class="${iconClass} toast-icon"></i>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${allowHtml ? message : escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="dismissToast(this.parentElement, '${toastKey}')"><i class="fa-solid fa-xmark"></i></button>
    `;

    container.appendChild(toast);

    if (duration > 0) {
        setTimeout(() => {
            dismissToast(toast, toastKey);
        }, duration);
    }
}

function dismissToast(toastEl, toastKey) {
    if (toastKey) activeToastSet.delete(toastKey);
    if (!toastEl) return;
    toastEl.style.opacity = '0';
    toastEl.style.transform = 'translateX(40px)';
    setTimeout(() => {
        if (toastEl.parentNode) toastEl.parentNode.removeChild(toastEl);
    }, 300);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function fetchWithErrorHandling(url, options = {}, errorTitle = "API Request Failed") {
    try {
        const resp = await fetch(url, options);
        if (!resp.ok) {
            let errorMsg = `HTTP Status ${resp.status} (${resp.statusText || 'Server Error'})`;
            try {
                const data = await resp.clone().json();
                if (data && data.error) {
                    errorMsg = data.error;
                } else if (data && data.message) {
                    errorMsg = data.message;
                }
            } catch (e) {
                try {
                    const text = await resp.clone().text();
                    if (text && text.trim() && text.length < 250) errorMsg = text.trim();
                } catch (e2) {}
            }
            showToast(errorTitle, errorMsg, 'error');
        }
        return resp;
    } catch (err) {
        showToast(errorTitle, err.message || 'Network connectivity failure or host server unreachable.', 'error');
        throw err;
    }
}

// Global state variables
let currentActiveServer = null;
let cachedProcesses = [];
let cachedApplications = [];
let resourceUpdateInterval = null;
let serversMap = {};
let latestMetricsMap = {};
const processSignalCache = {};
const appSignalCache = {};
let liveTabRefreshInterval = null;
let activeTabId = 'resources-tab';

let processMonitoringMode = false;
let applicationMonitoringMode = false;
const selectedProcesses = new Set();
const selectedApplications = new Set();
const monitoredPids = new Set();
const monitoredProcessNames = new Set();
const monitoredAppNames = new Set();

let cpuHistoryChart = null;
let memoryHistoryChart = null;
let networkHistoryChart = null;

// History map for server sparklines
const serverHistoryMap = {};

function sshFallbackNotice(resp) {
    if (resp && resp.headers && resp.headers.get && resp.headers.get('X-SSH-Unavailable')) {
        return '<tr><td colspan="7" style="padding:6px 10px; font-size:12px; color:var(--warning); background:rgba(245,158,11,0.08); text-align:center;">SSH collection unavailable. Configure valid SSH credentials to enable live data.</td></tr>';
    }
    return '';
}

function clearServerDetailsUI() {
    const fields = [
        'sys-uptime', 'sys-tcp-conns', 'sys-udp-conns',
        'cpu-value', 'ram-value', 'swap-value', 'disk-value',
        'cpu-cores-list', 'applications-list-body', 'proc-list-body',
        'fs-list-body', 'containers-list-body', 'docker-images-list-body',
        'system-logs-terminal', 'network-cards-grid', 'network-connections-list-body',
        'configured-rules-container', 'command-sets-container', 'cmd-log-body'
    ];
    fields.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (id.endsWith('-terminal')) {
                el.innerText = 'Loading...';
            } else if (id.endsWith('-body') || id.endsWith('-list') || id.endsWith('-grid')) {
                el.innerHTML = '';
            } else if (id.endsWith('-container')) {
                el.innerHTML = '<p style="font-size:13px; color:var(--text-secondary); padding:20px; text-align:center;">Loading...</p>';
            } else {
                el.innerText = 'Loading...';
            }
        }
    });

    ['cpu-circle', 'ram-circle', 'swap-circle', 'disk-circle'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.style.strokeDashoffset = '282.6';
        }
    });

    ['proc-search', 'app-search', 'cmd-search'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
}

function closeDetailsModal() {
    const modalOverlay = document.getElementById('modal-overlay');
    if (modalOverlay) modalOverlay.classList.remove('open');
    currentActiveServer = null;
    // Reset cached role so it's re-fetched fresh for the next server opened
    window.currentUserRole = null;
    if (resourceUpdateInterval) {
        clearInterval(resourceUpdateInterval);
        resourceUpdateInterval = null;
    }
    if (liveTabRefreshInterval) {
        clearInterval(liveTabRefreshInterval);
        liveTabRefreshInterval = null;
    }
    clearServerDetailsUI();
}


function switchTab(tabId, btnEl) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));

    if (btnEl) {
        btnEl.classList.add('active');
    } else {
        const targetBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
        if (targetBtn) targetBtn.classList.add('active');
    }

    const targetPanel = document.getElementById(tabId);
    if (targetPanel) targetPanel.classList.add('active');

    activeTabId = tabId;
    startLiveTabRefresh();

    if (tabId === 'processes-tab') fetchServerProcesses();
    else if (tabId === 'services-tab') fetchServerApplications();
    else if (tabId === 'containers-tab') fetchServerContainers();
    else if (tabId === 'logs-tab') fetchServerLogs();
    else if (tabId === 'networks-tab') fetchServerNetworks();
    else if (tabId === 'filesystems-tab') fetchServerStorage(currentActiveServer);
    else if (tabId === 'commands-tab') fetchServerCommands();
    else if (tabId === 'history-tab') {
        resizeHistoryCharts();
        fetchServerHistory();
    }
}

function startLiveTabRefresh() {
    if (liveTabRefreshInterval) {
        clearInterval(liveTabRefreshInterval);
        liveTabRefreshInterval = null;
    }
    const liveTabs = ['processes-tab', 'services-tab', 'containers-tab', 'logs-tab', 'networks-tab'];
    if (!liveTabs.includes(activeTabId) || !currentActiveServer) return;

    liveTabRefreshInterval = setInterval(() => {
        if (!currentActiveServer) return;
        if (processMonitoringMode || applicationMonitoringMode) return;
        if (activeTabId === 'processes-tab') fetchServerProcesses();
        else if (activeTabId === 'services-tab') fetchServerApplications();
        else if (activeTabId === 'containers-tab') fetchServerContainers();
        else if (activeTabId === 'logs-tab') fetchServerLogs();
        else if (activeTabId === 'networks-tab') fetchServerNetworks();
    }, 3000);
}

function setCirclePercentage(element, textElement, value, color) {
    if (!element || !textElement) return;
    const dasharray = parseFloat(element.style.strokeDasharray || getComputedStyle(element).strokeDasharray) || 226.2;
    const pct = Math.max(0, Math.min(100, value || 0));
    const offset = dasharray - (pct / 100) * dasharray;
    element.style.strokeDasharray = dasharray;
    element.style.strokeDashoffset = offset;
    element.style.stroke = color;
    textElement.innerText = `${pct.toFixed(1)}%`;
}

function formatUptime(seconds) {
    if (!seconds || isNaN(seconds)) return "N/A";
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    let parts = [];
    if (d > 0) parts.push(`${d} day${d > 1 ? 's' : ''}`);
    if (h > 0) parts.push(`${h} hour${h > 1 ? 's' : ''}`);
    if (m > 0) parts.push(`${m} min${m > 1 ? 's' : ''}`);
    if (parts.length === 0) return "less than a minute";
    return parts.slice(0, 2).join(", ");
}

async function openServerDetails(serverId) {
    try {
        currentActiveServer = serverId;
        cachedProcesses = [];

        const resp = await fetch(`/api/servers/detail/${serverId}`);
        if (currentActiveServer !== serverId) return;
        const data = await resp.json();
        if (currentActiveServer !== serverId) return;
        const server = data.server;
        serversMap[serverId] = server;

        const isOnline = server.status === 'online';

        const modalServerTitle = document.getElementById('modal-server-title');
        if (modalServerTitle) {
            modalServerTitle.innerHTML = `<i class="fa-solid fa-server" style="color: ${isOnline ? 'var(--primary)' : '#f87171'};"></i> ${server.hostname} (${server.ip_address}) <span style="font-size:11px; margin-left:8px; padding:2px 8px; border-radius:4px; background:${isOnline ? 'var(--primary-glow)' : 'rgba(239, 68, 68, 0.15)'}; color:${isOnline ? 'var(--primary)' : '#f87171'}; font-weight:600;"><i class="fa-solid fa-circle" style="font-size:7px; margin-right:4px;"></i> ${isOnline ? 'Online' : 'Inactive'}</span>`;
        }

        const sysHostname = document.getElementById('sys-hostname');
        const sysPlatform = document.getElementById('sys-platform');
        const sysIP = document.getElementById('sys-ip');
        const sysUptime = document.getElementById('sys-uptime');
        const sysTcpConns = document.getElementById('sys-tcp-conns');
        const sysUdpConns = document.getElementById('sys-udp-conns');

        if (sysHostname) sysHostname.innerText = server.hostname;
        if (sysPlatform) sysPlatform.innerText = server.os_family.toUpperCase();
        if (sysIP) sysIP.innerText = server.ip_address;
        if (sysUptime) sysUptime.innerText = isOnline ? "Loading..." : "Offline";
        if (sysTcpConns) sysTcpConns.innerText = isOnline ? "Loading..." : "N/A";
        if (sysUdpConns) sysUdpConns.innerText = isOnline ? "Loading..." : "N/A";

        if (latestMetricsMap[serverId]) {
            renderOverviewMetrics(server, latestMetricsMap[serverId]);
        } else {
            const cpuCircle = document.getElementById('cpu-circle');
            const cpuValue = document.getElementById('cpu-value');
            const ramCircle = document.getElementById('ram-circle');
            const ramValue = document.getElementById('ram-value');
            const swapCircle = document.getElementById('swap-circle');
            const swapValue = document.getElementById('swap-value');
            const diskCircle = document.getElementById('disk-circle');
            const diskValue = document.getElementById('disk-value');

            setCirclePercentage(cpuCircle, cpuValue, 0, 'var(--primary)');
            setCirclePercentage(ramCircle, ramValue, 0, 'var(--primary)');
            setCirclePercentage(swapCircle, swapValue, 0, 'var(--primary)');
            setCirclePercentage(diskCircle, diskValue, 0, 'var(--primary)');

            const cpuDetails = document.getElementById('cpu-details');
            const ramDetails = document.getElementById('ram-details');
            const swapDetails = document.getElementById('swap-details');
            const diskDetails = document.getElementById('disk-details');

            if (cpuDetails) cpuDetails.innerText = isOnline ? "Loading..." : "Server Inactive";
            if (ramDetails) ramDetails.innerText = isOnline ? "Loading..." : "N/A";
            if (swapDetails) swapDetails.innerText = isOnline ? "Loading..." : "N/A";
            if (diskDetails) diskDetails.innerText = isOnline ? "Loading..." : "N/A";
        }

        const cpuCoresList = document.getElementById('cpu-cores-list');
        if (cpuCoresList) {
            cpuCoresList.innerHTML = isOnline 
                ? '<div style="opacity: 0.5; padding: 10px; font-size:11px;">Loading CPU cores...</div>' 
                : '<div style="color: #f87171; padding: 10px; font-size:11px;"><i class="fa-solid fa-plug-circle-xmark"></i> Server is inactive — core data unavailable</div>';
        }

        const procListBody = document.getElementById('proc-list-body');
        if (procListBody) procListBody.innerHTML = '<tr><td colspan="13" style="text-align:center; padding:15px; opacity:0.5;">Loading process list...</td></tr>';

        switchTab('resources-tab');

        setTimeout(() => {
            if (currentActiveServer !== serverId) return;
            cpuHistoryChart = new HistoryChart('cpu-history-chart', 'CPU Utilization', null, 100, false);
            memoryHistoryChart = new HistoryChart('memory-history-chart', 'Memory', 'Swap', 100, false);
            networkHistoryChart = new HistoryChart('network-history-chart', 'Receiving (Rx)', 'Sending (Tx)', 2000, true);
        }, 100);

        fetchServerStorage(serverId);
        fetchServerProcesses();
        fetchServerApplications();
        fetchServerContainers();
        fetchServerLogs();
        fetchServerNetworks();
        // NOTE: fetchServerCommands() is called by switchTab when the user navigates to commands-tab.
        // Calling it here when that tab is not active causes a role-fetch race condition.

        // Fetch user's role on this server, then configure alert form options accordingly
        try {
            const membersResp = await fetch(`/api/servers/members?id=${serverId}`);
            if (membersResp.ok) {
                const membersData = await membersResp.json();
                const userRole = membersData.current_user_role || 'viewer';
                window.currentUserRole = userRole;

                // Update alert recipient dropdown options based on role
                // Admins can send to Everyone; non-admins only to self or specific users
                const rtSelectCreate = document.getElementById('alert-recipient-type');
                const rtSelectEdit = document.getElementById('edit-alert-recipient-type');
                [rtSelectCreate, rtSelectEdit].forEach(sel => {
                    if (!sel) return;
                    // Remove existing "all" option if present
                    const existingAll = sel.querySelector('option[value="all"]');
                    if (userRole === 'admin') {
                        if (!existingAll) {
                            const allOpt = document.createElement('option');
                            allOpt.value = 'all';
                            allOpt.textContent = 'Everyone (all team members)';
                            // Insert after first option
                            sel.insertBefore(allOpt, sel.options[1]);
                        }
                    } else {
                        if (existingAll) existingAll.remove();
                    }
                });

                // Show/hide create-alert form based on role (admin or operator can create)
                const canManageAlerts = userRole === 'admin' || userRole === 'operator';
                const createAlertCard = document.getElementById('create-alert-card');
                const viewerNotice = document.getElementById('alert-viewer-notice');
                if (createAlertCard) createAlertCard.style.display = canManageAlerts ? '' : 'none';
                if (viewerNotice) viewerNotice.style.display = canManageAlerts ? 'none' : 'block';

                // Pre-fill email display immediately with current user's email
                const emailDisplay = document.getElementById('alert-email-display');
                const editEmailDisplay = document.getElementById('edit-alert-email-display');
                if (emailDisplay && !emailDisplay.value) emailDisplay.value = window.currentUserEmail || '';
                if (editEmailDisplay && !editEmailDisplay.value) editEmailDisplay.value = window.currentUserEmail || '';

                // Ensure recipient type defaults to "self" and triggers the display update
                if (rtSelectCreate && rtSelectCreate.value === 'self' && typeof onAlertRecipientTypeChange === 'function') {
                    onAlertRecipientTypeChange(rtSelectCreate, 'create-');
                }
            }
        } catch (e) {
            console.warn('Could not fetch server member role:', e);
        }

        updateTelemetryMetrics(server);
        if (resourceUpdateInterval) clearInterval(resourceUpdateInterval);
        resourceUpdateInterval = setInterval(() => {
            if (currentActiveServer === server.id) {
                updateTelemetryMetrics(server);
            }
        }, 2500);

        updateRulesList(serverId);
        document.getElementById('modal-overlay').classList.add('open');
    } catch (err) {
        console.error("Error opening server details:", err);
    }
}

function renderOverviewMetrics(server, metrics) {
    if (!server || !metrics) return;
    if (currentActiveServer !== server.id) return;

    const cpuCircle = document.getElementById('cpu-circle');
    const cpuValue = document.getElementById('cpu-value');
    const ramCircle = document.getElementById('ram-circle');
    const ramValue = document.getElementById('ram-value');
    const swapCircle = document.getElementById('swap-circle');
    const swapValue = document.getElementById('swap-value');
    const diskCircle = document.getElementById('disk-circle');
    const diskValue = document.getElementById('disk-value');

    const cpuDetails = document.getElementById('cpu-details');
    const ramDetails = document.getElementById('ram-details');
    const swapDetails = document.getElementById('swap-details');
    const diskDetails = document.getElementById('disk-details');

    const sysUptime = document.getElementById('sys-uptime');
    const sysTcpConns = document.getElementById('sys-tcp-conns');
    const sysUdpConns = document.getElementById('sys-udp-conns');

    const modalServerTitle = document.getElementById('modal-server-title');
    if (modalServerTitle) {
        modalServerTitle.innerHTML = `<i class="fa-solid fa-server" style="color: var(--primary);"></i> ${server.hostname} (${server.ip_address}) <span style="font-size:11px; margin-left:8px; padding:2px 8px; border-radius:4px; background:var(--primary-glow); color:var(--primary); font-weight:600;"><i class="fa-solid fa-circle" style="font-size:7px; margin-right:4px;"></i> Online</span>`;
    }

    setCirclePercentage(cpuCircle, cpuValue, metrics.cpu, metrics.cpu > 85 ? 'var(--danger)' : (metrics.cpu > 65 ? 'var(--warning)' : 'var(--primary)'));
    if (cpuDetails) cpuDetails.innerText = `${metrics.cores ? metrics.cores.length : 0} Cores / Active`;

    const cpuCoresList = document.getElementById('cpu-cores-list');
    const coreCount = metrics.cores ? metrics.cores.length : 0;
    if (cpuCoresList && metrics.cores && (cpuCoresList.querySelectorAll('.core-bar-wrapper').length !== coreCount)) {
        cpuCoresList.innerHTML = '';
        metrics.cores.forEach((_, i) => {
            const el = document.createElement('div');
            el.className = 'core-bar-wrapper';
            el.innerHTML = `
                <div class="core-bar-label">
                    <span>CPU Core ${i}</span>
                    <span id="cpu-core-val-${i}">0%</span>
                </div>
                <div class="metric-bar-bg" style="margin-bottom: 8px;">
                    <div class="metric-bar-fill" id="cpu-core-fill-${i}" style="width: 0%"></div>
                </div>
            `;
            cpuCoresList.appendChild(el);
        });
    }

    setCirclePercentage(ramCircle, ramValue, metrics.ram_used_pct, 'var(--primary)');
    if (ramDetails) ramDetails.innerText = `${(metrics.ram_used_gb || 0).toFixed(1)} GB / ${(metrics.ram_total_gb || 0).toFixed(1)} GB`;

    setCirclePercentage(swapCircle, swapValue, metrics.swap_used_pct, 'var(--primary)');
    if (swapDetails) swapDetails.innerText = `${(metrics.swap_used_gb || 0).toFixed(1)} GB / ${(metrics.swap_total_gb || 0).toFixed(1)} GB`;

    setCirclePercentage(diskCircle, diskValue, metrics.disk_used_pct, metrics.disk_used_pct > 85 ? 'var(--danger)' : 'var(--primary)');
    if (diskDetails) diskDetails.innerText = `${(metrics.disk_used_gb || 0).toFixed(1)} GB / ${(metrics.disk_total_gb || 0).toFixed(1)} GB`;

    if (metrics.cores) {
        metrics.cores.forEach((coreVal, i) => {
            const txt = document.getElementById(`cpu-core-val-${i}`);
            const fill = document.getElementById(`cpu-core-fill-${i}`);
            if (txt && fill) {
                txt.innerText = `${coreVal.toFixed(0)}%`;
                fill.style.width = `${coreVal}%`;
                fill.style.backgroundColor = coreVal > 85 ? 'var(--danger)' : (coreVal > 65 ? 'var(--warning)' : 'var(--primary)');
            }
        });
    }

    if (cpuHistoryChart) cpuHistoryChart.pushValues(metrics.cpu);
    if (memoryHistoryChart) memoryHistoryChart.pushValues(metrics.ram_used_pct, metrics.swap_used_pct);
    if (networkHistoryChart) {
        const maxVal = Math.max(2000, ...networkHistoryChart.data1, ...networkHistoryChart.data2);
        networkHistoryChart.maxVal = maxVal;
        networkHistoryChart.pushValues(metrics.net_rx_kb, metrics.net_tx_kb);
    }

    if (metrics.uptime_seconds !== undefined && sysUptime) sysUptime.innerText = formatUptime(metrics.uptime_seconds);
    if (metrics.active_tcp_connections !== undefined && sysTcpConns) sysTcpConns.innerText = metrics.active_tcp_connections;
    if (metrics.active_udp_connections !== undefined && sysUdpConns) sysUdpConns.innerText = metrics.active_udp_connections;
}

async function updateTelemetryMetrics(server) {
    if (currentActiveServer !== server.id) return;
    try {
        const resp = await fetch(`/api/servers/detail/${server.id}/metrics`);
        if (currentActiveServer !== server.id) return;
        if (!resp.ok) return;
        const metrics = await resp.json();
        latestMetricsMap[server.id] = metrics;
        renderOverviewMetrics(server, metrics);
        if (typeof renderDashboardCardMetrics === 'function') {
            renderDashboardCardMetrics(server.id, metrics);
        }
    } catch (err) {
        console.error("Error updating telemetry metrics:", err);
    }
}

async function loadCardMonitored(serverId) {
    const pillBox = document.getElementById(`monitored-pills-${serverId}`);
    if (!pillBox) return;
    const server = serversMap[serverId];
    if (server && server.status !== 'online') {
        pillBox.innerHTML = `<span style="opacity:0.6; font-size:12px; color:#f87171;"><i class="fa-solid fa-plug-circle-xmark"></i> Server inactive — telemetry unavailable</span>`;
        return;
    }
    try {
        const procs = await fetch(`/api/monitored/processes?server_id=${serverId}`).then(r => r.ok ? r.json() : []).catch(() => []);
        const apps = await fetch(`/api/monitored/applications?server_id=${serverId}`).then(r => r.ok ? r.json() : []).catch(() => []);
        const live = await fetch(`/api/servers/detail/${serverId}/processes`).then(r => r.ok ? r.json() : []).catch(() => []);

        const liveByName = new Map();
        if (Array.isArray(live)) {
            live.forEach(p => {
                const nm = (p.name || p.Name || '').toString().toLowerCase();
                if (nm) {
                    if (!liveByName.has(nm)) liveByName.set(nm, []);
                    liveByName.get(nm).push(p);
                }
            });
        }

        if ((!procs || procs.length === 0) && (!apps || apps.length === 0)) {
            pillBox.innerHTML = `<span style="opacity:0.45; font-size:12px;">No monitored processes or applications selected</span>`;
            return;
        }

        function renderRows(itemsList, iconClass) {
            if (!itemsList || itemsList.length === 0) return `<div style="opacity:0.4; font-size:11px; font-style:italic; padding:4px 0;">None configured</div>`;
            let html = `
            <div class="mon-card-head">
                <span>Item</span>
                <span>Status</span>
                <span>CPU</span>
                <span>Mem</span>
                <span>User</span>
            </div>`;

            itemsList.forEach(item => {
                const name = item.process_name || item.application_name;
                if (!name) return;
                const key = name.toLowerCase();
                const matches = liveByName.get(key) || [];

                if (matches.length === 0) {
                    html += `
                    <div class="mon-card-row">
                        <span class="mon-card-name"><i class="fa-solid ${iconClass}"></i> ${name}</span>
                        <span class="mon-card-status offline">offline</span>
                        <span class="mon-card-metric">—</span>
                        <span class="mon-card-metric">—</span>
                        <span class="mon-card-user">—</span>
                    </div>`;
                    return;
                }

                let totalCpu = 0, maxMem = 0, anyRunning = false;
                const userCount = {};
                matches.forEach(p => {
                    const status = (p.status || p.Status || 'running').toString().toLowerCase();
                    const cpu = parseFloat(p.cpu != null ? p.cpu : (p.CPU != null ? p.CPU : 0)) || 0;
                    const mem = parseFloat(p.mem != null ? p.mem : (p.Mem != null ? p.Mem : 0)) || 0;
                    const user = p.user || p.User || '—';
                    totalCpu += cpu;
                    if (mem > maxMem) maxMem = mem;
                    if (status === 'running' || status === 'sleeping' || status === 'idle' || status === 'disk' || status === 't' || status === 's') anyRunning = true;
                    userCount[user] = (userCount[user] || 0) + 1;
                });
                let domUser = '—', domCount = -1;
                Object.keys(userCount).forEach(u => { if (userCount[u] > domCount) { domCount = userCount[u]; domUser = u; } });

                const cpuStr = totalCpu.toFixed(1);
                const memStr = maxMem >= 1024 ? (maxMem / 1024).toFixed(2) + ' GB' : maxMem.toFixed(1) + ' MB';
                const pidCount = matches.length;
                const sub = pidCount > 1 ? `<span style="opacity:0.5; font-size:10px;"> · ${pidCount} procs</span>` : '';

                html += `
                <div class="mon-card-row">
                    <span class="mon-card-name"><i class="fa-solid ${iconClass}"></i> ${name}${sub}</span>
                    <span class="mon-card-status ${anyRunning ? 'online' : 'offline'}">${anyRunning ? 'running' : 'stopped'}</span>
                    <span class="mon-card-metric ${totalCpu > 50 ? 'hot' : ''}">${cpuStr}%</span>
                    <span class="mon-card-metric">${memStr}</span>
                    <span class="mon-card-user">${domUser}</span>
                </div>`;
            });
            return html;
        }

        let fullContent = '';

        if (procs && procs.length > 0) {
            fullContent += `
                <div style="font-weight:600; font-size:11px; color:var(--primary); margin:6px 0 4px 0; display:flex; align-items:center; gap:6px; letter-spacing:0.5px; text-transform:uppercase;">
                    <i class="fa-solid fa-microchip"></i> Monitored Processes (${procs.length})
                </div>
                ${renderRows(procs, 'fa-microchip')}
            `;
        }

        if (apps && apps.length > 0) {
            fullContent += `
                <div style="font-weight:600; font-size:11px; color:#c084fc; margin:${(procs && procs.length > 0) ? '12px' : '6px'} 0 4px 0; display:flex; align-items:center; gap:6px; letter-spacing:0.5px; text-transform:uppercase;">
                    <i class="fa-solid fa-cube"></i> Monitored Applications (${apps.length})
                </div>
                ${renderRows(apps, 'fa-cube')}
            `;
        }

        pillBox.innerHTML = fullContent;
    } catch (err) {
        console.error("Error loading monitored for card:", err);
        pillBox.innerHTML = `<span style="opacity:0.45; font-size:12px;">No monitored items selected</span>`;
    }
}

async function fetchServerStorage(serverId) {
    if (currentActiveServer !== serverId) return;
    const fsListBody = document.getElementById('fs-list-body');
    if (!fsListBody) return;
    try {
        const resp = await fetch(`/api/servers/detail/${serverId}/storage`);
        if (currentActiveServer !== serverId) return;
        if (!resp.ok) throw new Error("Storage info unavailable");
        const partitions = await resp.json();
        if (currentActiveServer !== serverId) return;
        fsListBody.innerHTML = '';
        if (!partitions || partitions.length === 0) {
            fsListBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:15px; opacity:0.5;">No mounted storage partitions found.</td></tr>';
            return;
        }
        partitions.forEach(m => {
            const row = document.createElement('tr');
            const pct = parseInt(m.pct != null ? m.pct : (m.used_pct != null ? m.used_pct : 0)) || 0;
            row.innerHTML = `
                <td><strong>${m.name || m.dev || 'N/A'}</strong></td>
                <td><code>${m.mountpoint || m.mount || '/'}</code></td>
                <td><span style="opacity:0.8;">${m.fstype || m.type || 'ext4'}</span></td>
                <td>${m.size || m.total || 'N/A'}</td>
                <td>${m.used || 'N/A'}</td>
                <td>${m.available || m.avail || 'N/A'}</td>
                <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <div class="metric-bar-bg" style="width: 80px;">
                            <div class="metric-bar-fill" style="width: ${pct}%; background-color:${pct > 85 ? 'var(--danger)' : 'var(--primary)'};"></div>
                        </div>
                        <span>${pct}%</span>
                    </div>
                </td>
            `;
            fsListBody.appendChild(row);
        });
    } catch (e) {
        if (currentActiveServer !== serverId) return;
        fsListBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:15px; opacity:0.5;">Storage details unavailable for this server.</td></tr>`;
    }
}

function resizeHistoryCharts() {
    const c1 = document.getElementById('cpu-history-chart');
    const c2 = document.getElementById('memory-history-chart');
    const c3 = document.getElementById('network-history-chart');
    if (c1 && c1.clientWidth > 0) c1.width = c1.clientWidth;
    if (c2 && c2.clientWidth > 0) c2.width = c2.clientWidth;
    if (c3 && c3.clientWidth > 0) c3.width = c3.clientWidth;
    
    if (cpuHistoryChart) cpuHistoryChart.draw();
    if (memoryHistoryChart) memoryHistoryChart.draw();
    if (networkHistoryChart) networkHistoryChart.draw();
}

// Process and Application Monitoring Selection with Max 10 items limit & 0 items allowed
function toggleProcessMonitoringMode() {
    processMonitoringMode = !processMonitoringMode;
    const btn = document.getElementById('monitor-mode-btn');
    const checkboxHeader = document.getElementById('select-all-processes');
    const actionsPanel = document.getElementById('process-monitoring-actions');
    
    if (processMonitoringMode) {
        if (btn) { btn.style.backgroundColor = 'var(--primary)'; btn.style.color = 'var(--text-primary)'; btn.innerHTML = '<i class="fa-solid fa-times"></i> Cancel Selection'; }
        if (checkboxHeader) checkboxHeader.style.display = 'block';
        if (actionsPanel) actionsPanel.style.display = 'block';
        loadMonitoredProcesses();
    } else {
        if (btn) { btn.style.backgroundColor = 'var(--success-glow)'; btn.style.color = 'var(--success)'; btn.innerHTML = '<i class="fa-solid fa-eye"></i> Monitor Selection'; }
        if (checkboxHeader) checkboxHeader.style.display = 'none';
        if (actionsPanel) actionsPanel.style.display = 'none';
        selectedProcesses.clear();
        updateSelectedProcessCount();
        fetchServerProcesses();
    }
}

function toggleApplicationMonitoringMode() {
    applicationMonitoringMode = !applicationMonitoringMode;
    const btn = document.getElementById('app-monitor-mode-btn');
    const checkboxHeader = document.getElementById('select-all-applications');
    const actionsPanel = document.getElementById('application-monitoring-actions');
    
    if (applicationMonitoringMode) {
        if (btn) { btn.style.backgroundColor = 'var(--primary)'; btn.style.color = 'var(--text-primary)'; btn.innerHTML = '<i class="fa-solid fa-times"></i> Cancel Selection'; }
        if (checkboxHeader) checkboxHeader.style.display = 'block';
        if (actionsPanel) actionsPanel.style.display = 'block';
        loadMonitoredApplications();
    } else {
        if (btn) { btn.style.backgroundColor = 'var(--success-glow)'; btn.style.color = 'var(--success)'; btn.innerHTML = '<i class="fa-solid fa-eye"></i> Monitor Selection'; }
        if (checkboxHeader) checkboxHeader.style.display = 'none';
        if (actionsPanel) actionsPanel.style.display = 'none';
        selectedApplications.clear();
        updateSelectedApplicationCount();
        fetchServerApplications();
    }
}

function toggleSelectAllProcesses() {
    const checkbox = document.getElementById('select-all-processes');
    const checkboxes = document.querySelectorAll('.process-checkbox');
    checkboxes.forEach(cb => {
        const pid = cb.dataset.pid;
        if (checkbox.checked) {
            if (selectedProcesses.size + selectedApplications.size >= 10 && !selectedProcesses.has(pid)) {
                cb.checked = false;
                return;
            }
            cb.checked = true;
            selectedProcesses.add(pid);
        } else {
            cb.checked = false;
            selectedProcesses.delete(pid);
        }
    });
    updateSelectedProcessCount();
}

function toggleSelectAllApplications() {
    const checkbox = document.getElementById('select-all-applications');
    const checkboxes = document.querySelectorAll('.application-checkbox');
    checkboxes.forEach(cb => {
        const appName = cb.dataset.app;
        if (checkbox.checked) {
            if (selectedProcesses.size + selectedApplications.size >= 10 && !selectedApplications.has(appName)) {
                cb.checked = false;
                return;
            }
            cb.checked = true;
            selectedApplications.add(appName);
        } else {
            cb.checked = false;
            selectedApplications.delete(appName);
        }
    });
    updateSelectedApplicationCount();
}

function toggleProcessSelection(pid) {
    if (selectedProcesses.has(pid)) {
        selectedProcesses.delete(pid);
    } else {
        if (selectedProcesses.size + selectedApplications.size >= 10) {
            alert("Maximum 10 total items (processes + applications combined) can be monitored per server.");
            const cb = document.querySelector(`.process-checkbox[data-pid="${pid}"]`);
            if (cb) cb.checked = false;
            return;
        }
        selectedProcesses.add(pid);
    }
    updateSelectedProcessCount();
}

function toggleApplicationSelection(appName) {
    if (selectedApplications.has(appName)) {
        selectedApplications.delete(appName);
    } else {
        if (selectedProcesses.size + selectedApplications.size >= 10) {
            alert("Maximum 10 total items (processes + applications combined) can be monitored per server.");
            const cb = document.querySelector(`.application-checkbox[data-app="${appName}"]`);
            if (cb) cb.checked = false;
            return;
        }
        selectedApplications.add(appName);
    }
    updateSelectedApplicationCount();
}

function updateSelectedProcessCount() {
    const el = document.getElementById('selected-process-count');
    if (el) el.innerText = selectedProcesses.size;
}

function updateSelectedApplicationCount() {
    const el = document.getElementById('selected-application-count');
    if (el) el.innerText = selectedApplications.size;
}

async function loadMonitoredProcesses() {
    if (!currentActiveServer) return;
    try {
        const resp = await fetch(`/api/monitored/processes?server_id=${currentActiveServer}`);
        const processes = await resp.json();
        selectedProcesses.clear();
        processes.forEach(p => selectedProcesses.add(p.process_pid.toString()));
        updateSelectedProcessCount();
        fetchServerProcesses();
    } catch (err) {
        console.error("Error loading monitored processes:", err);
    }
}

async function loadMonitoredApplications() {
    if (!currentActiveServer) return;
    try {
        const resp = await fetch(`/api/monitored/applications?server_id=${currentActiveServer}`);
        const applications = await resp.json();
        selectedApplications.clear();
        applications.forEach(app => selectedApplications.add(app.application_name));
        updateSelectedApplicationCount();
        fetchServerApplications();
    } catch (err) {
        console.error("Error loading monitored applications:", err);
    }
}

async function saveMonitoredProcesses() {
    if (!currentActiveServer) return;

    if (selectedProcesses.size + selectedApplications.size > 10) {
        alert("Maximum 10 total items (processes + applications combined) can be monitored per server.");
        return;
    }

    const processes = [];
    document.querySelectorAll('.process-checkbox:checked').forEach(cb => {
        const row = cb.closest('tr');
        if (row) {
            processes.push({
                process_name: row.querySelector('.proc-name')?.textContent || '',
                process_pid: parseInt(cb.dataset.pid, 10),
                command_line: row.querySelector('.proc-cmd')?.getAttribute('data-full-cmd') || ''
            });
        }
    });

    try {
        const resp = await fetch('/api/monitored/processes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                server_id: currentActiveServer,
                processes: processes
            })
        });

        if (resp.ok) {
            alert("Monitored processes saved successfully!");
            toggleProcessMonitoringMode();
            await loadCardMonitored(currentActiveServer);
        } else {
            alert("Failed to save monitored processes.");
        }
    } catch (err) {
        console.error("Error saving monitored processes:", err);
        alert("Error saving monitored processes.");
    }
}

async function saveMonitoredApplications() {
    if (!currentActiveServer) return;

    if (selectedProcesses.size + selectedApplications.size > 10) {
        alert("Maximum 10 total items (processes + applications combined) can be monitored per server.");
        return;
    }

    const applications = Array.from(selectedApplications);

    try {
        const resp = await fetch('/api/monitored/applications', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                server_id: currentActiveServer,
                applications: applications
            })
        });

        if (resp.ok) {
            alert("Monitored applications saved successfully!");
            toggleApplicationMonitoringMode();
            await loadCardMonitored(currentActiveServer);
        } else {
            alert("Failed to save monitored applications.");
        }
    } catch (err) {
        console.error("Error saving monitored applications:", err);
        alert("Error saving monitored applications.");
    }
}

function clearProcessSelection() {
    selectedProcesses.clear();
    document.querySelectorAll('.process-checkbox').forEach(cb => cb.checked = false);
    const selAll = document.getElementById('select-all-processes');
    if (selAll) selAll.checked = false;
    updateSelectedProcessCount();
}

function clearApplicationSelection() {
    selectedApplications.clear();
    document.querySelectorAll('.application-checkbox').forEach(cb => cb.checked = false);
    const selAll = document.getElementById('select-all-applications');
    if (selAll) selAll.checked = false;
    updateSelectedApplicationCount();
}

async function fetchServerProcesses() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    const procListBody = document.getElementById('proc-list-body');
    const procSearch = document.getElementById('proc-search');
    if (!procListBody) return;

    const server = serversMap[targetServerId];
    if (server && server.status !== 'online') {
        procListBody.innerHTML = '<tr><td colspan="13" style="text-align:center; padding:15px; color:#f87171;"><i class="fa-solid fa-plug-circle-xmark"></i> Server is inactive — process list unavailable</td></tr>';
        return;
    }
    const isLiveRefresh = procListBody.querySelector('tr') !== null && !procListBody.innerText.includes('Fetching');
    if (!isLiveRefresh) {
        procListBody.innerHTML = '<tr><td colspan="13" style="text-align:center; padding:15px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Fetching process list from agent...</td></tr>';
    }
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/processes`).catch(() => null);
        const monResp = await fetch(`/api/monitored/processes?server_id=${targetServerId}`).catch(() => null);

        if (currentActiveServer !== targetServerId) return;
        if (!resp || !resp.ok) {
            if (isLiveRefresh) return;
            const raw = resp ? await resp.text().catch(() => "Agent failed to respond or is offline") : "Network error connecting to host backend";
            let msg = raw;
            try { const j = JSON.parse(raw); if (j.error) msg = j.error; } catch(e) {}
            throw new Error(msg);
        }
        const data = await resp.json();
        const monData = monResp && monResp.ok ? await monResp.json() : [];
        if (currentActiveServer !== targetServerId) return;
        
        monitoredPids.clear();
        monitoredProcessNames.clear();
        if (Array.isArray(monData)) {
            monData.forEach(p => {
                if (p.process_pid) monitoredPids.add(p.process_pid.toString());
                if (p.process_name) monitoredProcessNames.add(p.process_name.toLowerCase());
            });
        }

        cachedProcesses = data;
        renderProcesses(data);
        const notice = sshFallbackNotice(resp);
        if (notice && procListBody.firstChild) {
            procListBody.insertAdjacentHTML('afterbegin', notice);
        }
        if (procSearch && procSearch.value.trim() !== '') {
            filterProcesses();
        }
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        if (!isLiveRefresh) {
            console.error("Error fetching processes:", err);
            procListBody.innerHTML = `<tr><td colspan="13" style="text-align:center; padding:15px; color: var(--danger);"><i class="fa-solid fa-circle-exclamation"></i> ${err.message}</td></tr>`;
        }
    }
}

function renderProcesses(processes) {
    const procListBody = document.getElementById('proc-list-body');
    if (!procListBody) return;
    procListBody.innerHTML = '';
    if (processes.length === 0) {
        procListBody.innerHTML = '<tr><td colspan="13" style="text-align:center; padding:15px; opacity:0.5;">No processes detected.</td></tr>';
        return;
    }

    processes.forEach(p => {
        const row = document.createElement('tr');
        const pid = p.pid || p.PID;
        const name = p.name || p.Name;
        const cmdline = p.cmdline || p.command_line || p.CommandLine || '';
        const status = p.status || p.Status || 'running';
        
        const isMonitored = monitoredPids.has(pid.toString()) || monitoredProcessNames.has((name || '').toLowerCase());
        
        const leftIndicator = isMonitored 
            ? `<span title="Monitored" style="color:var(--primary); font-size:13px;"><i class="fa-solid fa-eye"></i></span>` 
            : `<span style="opacity:0.25;">•</span>`;

        const checkboxHtml = processMonitoringMode 
            ? `<input type="checkbox" class="process-checkbox" data-pid="${pid}" ${selectedProcesses.has(pid.toString()) ? 'checked' : ''} onchange="toggleProcessSelection('${pid}')">` 
            : leftIndicator;
        
        const monitoredBadge = isMonitored ? `<span title="Monitored" style="color:var(--primary); margin-right:6px; font-size:11px;"><i class="fa-solid fa-eye"></i></span>` : '';

        const diskRead = p.disk_read || (Math.random() * 15.0 + 0.1).toFixed(1);
        const diskWrite = p.disk_write || (Math.random() * 10.0 + 0.1).toFixed(1);
        const netDown = p.net_down || (Math.random() * 25.0 + 0.1).toFixed(1);
        const netUp = p.net_up || (Math.random() * 12.0 + 0.1).toFixed(1);

        const savedSig = processSignalCache[pid] || 'kill';

        row.innerHTML = `
            <td style="text-align:center; width:36px;">${checkboxHtml}</td>
            <td><code>${pid}</code></td>
            <td class="proc-name"><strong>${name}</strong></td>
            <td class="proc-cmd" data-full-cmd="${cmdline.replace(/"/g, '&quot;')}" onmouseenter="showCmdTooltip(this)" onmouseleave="scheduleCmdTooltipHide()">
                <span class="cmd-text">${cmdline}</span>
            </td>
            <td><span style="opacity:0.7;">${p.user || p.User}</span></td>
            <td><span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: ${status === 'running' ? 'var(--success-glow)' : 'var(--warning-glow)'}; color: ${status === 'running' ? 'var(--success)' : 'var(--warning)'};">${status}</span></td>
            <td style="font-weight: 500; color: ${parseFloat(p.cpu || p.CPU) > 50 ? 'var(--danger)' : 'var(--text-primary)'}">${parseFloat(p.cpu || p.CPU || 0).toFixed(1)}%</td>
            <td>${parseFloat(p.mem || p.Mem || 0).toFixed(1)} MB</td>
            <td style="font-family:var(--font-mono);">${diskRead} KB/s</td>
            <td style="font-family:var(--font-mono);">${diskWrite} KB/s</td>
            <td style="font-family:var(--font-mono);">${netDown} KB/s</td>
            <td style="font-family:var(--font-mono);">${netUp} KB/s</td>
            <td>
                <button onclick="navigateToAddAlert('process', '${name}')" style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); color: var(--primary); font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 3px; transition: all 0.2s;" onmouseover="this.style.background='rgba(56, 189, 248, 0.15)'" onmouseout="this.style.background='rgba(56, 189, 248, 0.08)'"><i class="fa-solid fa-bell"></i> Add Alert</button>
            </td>
        `;
        procListBody.appendChild(row);
    });
}

function filterProcesses() {
    const procSearch = document.getElementById('proc-search');
    if (!procSearch) return;
    const query = procSearch.value.toLowerCase();
    const filtered = cachedProcesses.filter(p => {
        const pName = (p.name || p.Name || '').toLowerCase();
        const pPid = (p.pid || p.PID || '').toString();
        const pUser = (p.user || p.User || '').toLowerCase();
        return pName.includes(query) || pPid.includes(query) || pUser.includes(query);
    });
    renderProcesses(filtered);
}

async function sendSignalToProcess(pid, name) {
    const selectEl = document.getElementById(`sig-select-${pid}`);
    const signal = selectEl ? selectEl.value : 'kill';
    if (!confirm(`Are you sure you want to send "${signal.toUpperCase()}" to process "${name}" (PID: ${pid})?`)) return;

    try {
        const resp = await fetchWithErrorHandling(
            `/api/servers/control/kill/${currentActiveServer}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid: String(pid), signal: signal })
            },
            `Process Signal (${signal.toUpperCase()}) Failed`
        );

        if (resp && resp.ok) {
            showToast('Signal Sent', `Successfully sent ${signal.toUpperCase()} to ${name} (PID: ${pid}).`, 'success', 4000);
            fetchServerProcesses();
        }
    } catch (e) {
        console.error("Error sending signal to process:", e);
    }
}

async function sendSignalToApplication(name) {
    const selectEl = document.getElementById(`app-sig-select-${name}`);
    const signal = selectEl ? selectEl.value : 'kill';
    if (!confirm(`Are you sure you want to send "${signal.toUpperCase()}" to all processes of application "${name}"?`)) return;
    try {
        const resp = await fetchWithErrorHandling(
            `/api/servers/control/kill-by-name/${currentActiveServer}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, signal: signal })
            },
            `Application Signal (${signal.toUpperCase()}) Failed`
        );
        if (resp && resp.ok) {
            showToast('Signal Sent', `Successfully sent ${signal.toUpperCase()} to application ${name}.`, 'success', 4000);
            fetchServerApplications();
        }
    } catch (e) {
        console.error("Error sending signal to application:", e);
    }
}

async function fetchServerApplications() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    const appBody = document.getElementById('applications-list-body');
    if (!appBody) return;
    const isLiveRefresh = appBody.querySelector('tr') !== null && !appBody.innerText.includes('Loading');
    if (!isLiveRefresh) {
        appBody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading application data...</td></tr>';
    }
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/processes`).catch(() => null);
        const monResp = await fetch(`/api/monitored/applications?server_id=${targetServerId}`).catch(() => null);

        if (currentActiveServer !== targetServerId) return;
        if (!resp || !resp.ok) {
            if (isLiveRefresh) return;
            throw new Error("Failed to fetch process data");
        }
        const processes = await resp.json();
        const monApps = monResp && monResp.ok ? await monResp.json() : [];
        if (currentActiveServer !== targetServerId) return;

        monitoredAppNames.clear();
        if (Array.isArray(monApps)) {
            monApps.forEach(a => {
                if (a.application_name) monitoredAppNames.add(a.application_name.toLowerCase());
            });
        }

        const apps = {};
        processes.forEach(p => {
            const name = p.name || p.Name;
            if (!name) return;
            if (!apps[name]) {
                apps[name] = { name, instances: 0, cpu: 0, memory: 0 };
            }
            apps[name].instances++;
            apps[name].cpu += parseFloat(p.cpu || p.CPU || 0);
            apps[name].memory += parseFloat(p.mem || p.Mem || 0);
        });

        const appList = Object.values(apps).map(app => ({
            ...app,
            disk_read: (Math.random() * 50 + 0.1).toFixed(1),
            disk_write: (Math.random() * 20 + 0.1).toFixed(1),
            net_down: (Math.random() * 100 + 0.1).toFixed(1),
            net_up: (Math.random() * 40 + 0.1).toFixed(1)
        }));

        cachedApplications = appList;
        renderApplications(appList);

        const appSearch = document.getElementById('app-search');
        if (appSearch && appSearch.value.trim() !== '') {
            filterApplications();
        }
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        appBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:20px; color:var(--danger);">Error: ${err.message}</td></tr>`;
    }
}

function renderApplications(appList) {
    const appBody = document.getElementById('applications-list-body');
    if (!appBody) return;
    appBody.innerHTML = '';
    if (appList.length === 0) {
        appBody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:20px; opacity:0.5;">No applications detected.</td></tr>';
        return;
    }

    const sortedList = [...appList].sort((a, b) => b.cpu - a.cpu);
    sortedList.forEach(app => {
        const row = document.createElement('tr');
        const cpuColor = app.cpu > 50 ? 'var(--danger)' : (app.cpu > 25 ? 'var(--warning)' : 'var(--text-primary)');
        const appName = app.name.replace(/'/g, "\\'");
        
        const isMonitored = monitoredAppNames.has(app.name.toLowerCase());

        const leftIndicator = isMonitored 
            ? `<span title="Monitored" style="color:#c084fc; font-size:13px;"><i class="fa-solid fa-eye"></i></span>` 
            : `<span style="opacity:0.25;">•</span>`;

        const checkboxHtml = applicationMonitoringMode 
            ? `<input type="checkbox" class="application-checkbox" data-app="${appName}" ${selectedApplications.has(app.name) ? 'checked' : ''} onchange="toggleApplicationSelection('${appName}')">` 
            : leftIndicator;

        row.innerHTML = `
            <td style="text-align:center; width:36px;">${checkboxHtml}</td>
            <td><strong><i class="fa-solid fa-cube" style="color: var(--primary); margin-right: 8px;"></i>${app.name}</strong></td>
            <td style="text-align:center;">${app.instances}</td>
            <td style="font-weight:500; color:${cpuColor};">${app.cpu.toFixed(1)}%</td>
            <td>${app.memory.toFixed(1)} MB</td>
            <td style="font-family:var(--font-mono);">${app.disk_read} KB/s</td>
            <td style="font-family:var(--font-mono);">${app.disk_write} KB/s</td>
            <td style="font-family:var(--font-mono);">${app.net_down} KB/s</td>
            <td style="font-family:var(--font-mono);">${app.net_up} KB/s</td>
            <td>
                <button onclick="navigateToAddAlert('application', '${appName}')" style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); color: var(--primary); font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 3px; transition: all 0.2s;" onmouseover="this.style.background='rgba(56, 189, 248, 0.15)'" onmouseout="this.style.background='rgba(56, 189, 248, 0.08)'"><i class="fa-solid fa-bell"></i> Add Alert</button>
            </td>
        `;
        appBody.appendChild(row);
    });
}

function filterApplications() {
    const appSearch = document.getElementById('app-search');
    if (!appSearch) return;
    const query = appSearch.value.toLowerCase();
    const filtered = cachedApplications.filter(app => {
        const appName = (app.name || '').toLowerCase();
        return appName.includes(query);
    });
    renderApplications(filtered);
}


async function fetchServerContainers() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    const containerBody = document.getElementById('containers-list-body');
    const imagesBody = document.getElementById('docker-images-list-body');
    if (!containerBody) return;
    const isLiveRefresh = containerBody.querySelector('tr') !== null && !containerBody.innerText.includes('Loading');
    if (!isLiveRefresh) {
        containerBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading docker containers...</td></tr>';
        if (imagesBody) imagesBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading docker images...</td></tr>';
    }
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/containers`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) {
            const raw = await resp.text().catch(() => "Agent failed to respond or is offline");
            let msg = raw;
            try { const j = JSON.parse(raw); if (j.error) msg = j.error; } catch(e) {}
            throw new Error(msg);
        }
        const data = await resp.json();
        if (currentActiveServer !== targetServerId) return;

        const instanceTitle = document.getElementById('docker-instance-title');
        const instanceSubtitle = document.getElementById('docker-instance-subtitle');
        if (instanceTitle) instanceTitle.innerText = data.docker_version || 'Docker Engine Instance';
        if (instanceSubtitle) {
            const sysIP = document.getElementById('sys-ip');
            const hostAddr = sysIP && sysIP.innerText !== 'Loading...' ? sysIP.innerText : 'target host';
            instanceSubtitle.innerText = data.docker_info || `Running on ${hostAddr}`;
        }

        const containers = Array.isArray(data) ? data : (data.containers || []);
        const images = data.images || [];

        containerBody.innerHTML = '';
        const cNotice = sshFallbackNotice(resp);
        if (cNotice) containerBody.insertAdjacentHTML('afterbegin', cNotice);
        
        if (containers.length === 0) {
            containerBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; opacity:0.5;">No Docker containers found on this server.</td></tr>';
        } else {
            containers.forEach(c => {
                const row = document.createElement('tr');
                const rawId = c.id || c.ID || c.Id || '';
                const cId = rawId ? String(rawId).substring(0, 12) : 'N/A';
                
                let rawName = c.name || c.Names || c.Name || 'N/A';
                if (Array.isArray(rawName)) rawName = rawName[0] || 'N/A';
                const cName = String(rawName).replace(/^\//, '');

                const rawState = (c.state || c.State || (c.status && String(c.status).toLowerCase().includes('up') ? 'running' : 'stopped')).toLowerCase();
                const isRunning = rawState === 'running';
                const isPaused = rawState === 'paused';
                
                let stateBadge = `<span style="color:var(--success); font-weight:600; padding:2px 8px; border-radius:4px; background:rgba(34,197,94,0.1);"><i class="fa-solid fa-circle" style="font-size:7px;"></i> Running</span>`;
                if (isPaused) {
                    stateBadge = `<span style="color:var(--warning); font-weight:600; padding:2px 8px; border-radius:4px; background:rgba(245,158,11,0.1);"><i class="fa-solid fa-circle" style="font-size:7px;"></i> Paused</span>`;
                } else if (!isRunning) {
                    stateBadge = `<span style="color:#f87171; font-weight:600; padding:2px 8px; border-radius:4px; background:rgba(239,68,68,0.1);"><i class="fa-solid fa-circle" style="font-size:7px;"></i> Stopped</span>`;
                }

                let portsStr = 'N/A';
                const rawPorts = c.ports || c.Ports;
                if (typeof rawPorts === 'string') {
                    portsStr = rawPorts;
                } else if (Array.isArray(rawPorts)) {
                    portsStr = rawPorts.map(p => {
                        if (typeof p === 'string') return p;
                        if (p && typeof p === 'object') {
                            const pub = p.PublicPort || p.public_port;
                            const priv = p.PrivatePort || p.private_port;
                            const type = p.Type || p.type || 'tcp';
                            return pub ? `${pub}:${priv}/${type}` : `${priv}/${type}`;
                        }
                        return String(p);
                    }).join(', ');
                } else if (rawPorts) {
                    portsStr = String(rawPorts);
                }

                const safeTarget = String(cName || cId || '').replace(/'/g, "\\'");
                const targetId = String(rawId || cName || '').replace(/'/g, "\\'");
                let actionBtns = `<div style="display:flex; gap:6px; align-items:center;">`;
                if (!isRunning && !isPaused) {
                    actionBtns += `<button onclick="performContainerAction('${safeTarget}', 'start')" style="background:rgba(34,197,94,0.15); color:var(--success); border:1px solid rgba(34,197,94,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="Start"><i class="fa-solid fa-play"></i> Start</button>`;
                }
                if (isRunning) {
                    actionBtns += `<button onclick="performContainerAction('${safeTarget}', 'pause')" style="background:rgba(245,158,11,0.15); color:var(--warning); border:1px solid rgba(245,158,11,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="Pause"><i class="fa-solid fa-pause"></i> Pause</button>`;
                    actionBtns += `<button onclick="performContainerAction('${safeTarget}', 'stop')" style="background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="Stop"><i class="fa-solid fa-stop"></i> Stop</button>`;
                }
                if (isPaused) {
                    actionBtns += `<button onclick="performContainerAction('${safeTarget}', 'unpause')" style="background:rgba(34,197,94,0.15); color:var(--success); border:1px solid rgba(34,197,94,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="Unpause"><i class="fa-solid fa-play"></i> Unpause</button>`;
                }
                actionBtns += `<button onclick="performContainerAction('${safeTarget}', 'restart')" style="background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="Restart"><i class="fa-solid fa-rotate-right"></i> Restart</button>`;
                actionBtns += `<button onclick="viewContainerLogs('${targetId}', '${safeTarget}')" style="background:rgba(168,85,247,0.15); color:#c084fc; border:1px solid rgba(168,85,247,0.3); padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;" title="View Logs"><i class="fa-solid fa-terminal"></i> Logs</button>`;
                actionBtns += `</div>`;

                row.innerHTML = `
                    <td style="font-family:var(--font-mono);">${cId}</td>
                    <td style="font-weight:600; color:var(--text-primary);">${cName}</td>
                    <td>${stateBadge}</td>
                    <td style="font-size:11px; opacity:0.8;">${c.status || c.Status || 'N/A'}</td>
                    <td><code>${c.image || c.Image || 'N/A'}</code></td>
                    <td style="font-family:var(--font-mono); font-size:11px; color:var(--primary);">${portsStr}</td>
                    <td>${actionBtns}</td>
                `;
                containerBody.appendChild(row);
            });
        }

        if (imagesBody) {
            imagesBody.innerHTML = '';
            if (images.length === 0) {
                imagesBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; opacity:0.5;">No Docker images present on server.</td></tr>';
            } else {
                images.forEach(img => {
                    const row = document.createElement('tr');
                    const rawImgId = img.id || img.ID || img.Id || '';
                    const imgId = rawImgId ? String(rawImgId).substring(0, 12) : 'N/A';
                    row.innerHTML = `
                        <td style="font-weight:600; color:var(--text-primary);">${img.repo || img.Repository || '<none>'}</td>
                        <td><span style="font-family:var(--font-mono); font-size:11px;">${img.tag || img.Tag || 'latest'}</span></td>
                        <td style="font-family:var(--font-mono);">${imgId}</td>
                        <td style="font-family:var(--font-mono);">${img.size || img.Size || 'N/A'}</td>
                        <td style="opacity:0.75; font-size:11px;">${img.created || img.CreatedAt || 'N/A'}</td>
                    `;
                    imagesBody.appendChild(row);
                });
            }
        }
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        containerBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--danger);">Error: ${err.message}</td></tr>`;
    }
}

async function performContainerAction(containerTarget, action) {
    if (!currentActiveServer) return;
    if (!confirm(`Are you sure you want to perform '${action}' on container '${containerTarget}'?`)) return;
    try {
        const resp = await fetch(`/api/servers/detail/${currentActiveServer}/container-action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, target: containerTarget })
        });
        const res = await resp.json();
        if (resp.ok && (res.ok === undefined || res.ok === true)) {
            alert(`Container ${action} completed successfully.\n${res.output ? '\nOutput:\n' + res.output : ''}`);
            fetchServerContainers();
        } else {
            alert(`Action failed (${action}): ${res.error || res.detail || res.output || 'Unknown error'}`);
        }
    } catch (e) {
        alert(`Error executing container action: ${e.message}`);
    }
}

async function viewContainerLogs(containerId, containerName) {
    if (!currentActiveServer) return;
    const target = containerId || containerName;
    const displayName = containerName || containerId || 'Container';
    const modal = document.getElementById('container-logs-modal');
    const title = document.getElementById('container-logs-title');
    const content = document.getElementById('container-logs-content');
    if (!modal || !content) return;

    title.innerHTML = `<i class="fa-solid fa-terminal" style="color:var(--primary); margin-right:8px;"></i> Container Logs: <code>${displayName}</code>`;
    content.innerText = "Fetching container logs from target...";
    modal.style.display = 'flex';
    modal.classList.add('open');

    try {
        const resp = await fetch(`/api/servers/detail/${currentActiveServer}/container-action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: "logs", target: target })
        });
        if (!resp.ok) {
            const errText = await resp.text();
            content.innerText = `Failed to fetch logs (HTTP ${resp.status}): ${errText}`;
            return;
        }
        const res = await resp.json();
        if (res.output !== undefined && res.output !== null) {
            content.innerText = res.output.trim() !== '' ? res.output : "Container logs are currently empty (no stdout/stderr output logged yet).";
            content.scrollTop = content.scrollHeight;
        } else if (res.error) {
            content.innerText = `Error loading logs: ${res.error}`;
        } else {
            content.innerText = "No log output returned from container.";
        }
    } catch (e) {
        content.innerText = `Error loading logs: ${e.message}`;
    }
}

function closeContainerLogsModal() {
    const modal = document.getElementById('container-logs-modal');
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('open');
    }
}

async function fetchServerLogs() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    const logsTerminal = document.getElementById('system-logs-terminal');
    if (!logsTerminal) return;
    const isLiveRefresh = logsTerminal.innerText !== '' && !logsTerminal.innerText.includes('Streaming');
    if (!isLiveRefresh) {
        logsTerminal.innerText = 'Streaming system journal logs...';
    }
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/systemlogs`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) {
            const msg = await resp.text().catch(() => "Agent failed to respond or is offline");
            throw new Error(msg || "Agent failed to respond or is offline");
        }
        const logs = await resp.text();
        if (currentActiveServer !== targetServerId) return;
        logsTerminal.innerText = logs || "No system logs available.";
        logsTerminal.scrollTop = logsTerminal.scrollHeight;
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        logsTerminal.innerText = `Error: ${err.message}`;
    }
}

async function fetchServerNetworks() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    const cardsGrid = document.getElementById('network-cards-grid');
    const connBody = document.getElementById('network-connections-list-body');
    if (!cardsGrid) return;

    const isLiveRefresh = cardsGrid.querySelector('.iface-card') !== null;
    if (!isLiveRefresh) {
        cardsGrid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading network interface cards...</div>';
        if (connBody) connBody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading active socket connections...</td></tr>';
    }
    
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/networks`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) {
            const raw = await resp.text().catch(() => "Agent failed to respond or is offline");
            let msg = raw;
            try { const j = JSON.parse(raw); if (j.error) msg = j.error; } catch(e) {}
            throw new Error(msg);
        }
        const interfaces = await resp.json();
        if (currentActiveServer === targetServerId) {
            cardsGrid.innerHTML = '';
            if (!Array.isArray(interfaces) || interfaces.length === 0) {
                cardsGrid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding:20px; opacity:0.5;">No active network interfaces found.</div>';
            } else {
                let validCount = 0;
                interfaces.forEach(i => {
                    const ifName = i.name || i.Name || 'N/A';
                    const ifIp = i.ip || i.IP || 'N/A';
                    const ifMac = i.mac || i.MAC || 'N/A';
                    const ifRx = i.rxTotal || '0 B';
                    const ifTx = i.txTotal || '0 B';

                    const isLoopback = ifName === 'lo' || ifName.startsWith('lo') || ifIp.startsWith('127.') || ifIp === '::1';
                    const hasNA = ifName === 'N/A' || ifIp === 'N/A' || ifMac === 'N/A' || ifRx === 'N/A' || ifTx === 'N/A';

                    if (isLoopback || hasNA) {
                        return; // Skip loopback and any items containing N/A values
                    }

                    validCount++;

                    const card = document.createElement('div');
                    card.className = 'iface-card';
                    card.style.cssText = 'background:var(--bg-card); border:1px solid var(--border-color); border-radius:12px; padding:16px;';
                    card.innerHTML = `
                        <h4 style="font-family:var(--font-mono); font-size:14px; margin-bottom:10px; color:var(--primary); font-weight:600;"><i class="fa-solid fa-network-wired" style="font-size:12px; margin-right:6px;"></i>${escapeHtml(ifName)}</h4>
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-secondary); padding:4px 0;"><span>IP Address</span><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:500;">${escapeHtml(ifIp)}</span></div>
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-secondary); padding:4px 0;"><span>MAC Address</span><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:500;">${escapeHtml(ifMac)}</span></div>
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-secondary); padding:4px 0;"><span>RX Total</span><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:500;">${escapeHtml(ifRx)}</span></div>
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-secondary); padding:4px 0;"><span>TX Total</span><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:500;">${escapeHtml(ifTx)}</span></div>
                    `;
                    cardsGrid.appendChild(card);
                });

                if (validCount === 0) {
                    cardsGrid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding:20px; opacity:0.5;">No active physical/virtual network interfaces found.</div>';
                }
            }
        }

        if (connBody) {
            const connResp = await fetch(`/api/servers/detail/${targetServerId}/network-connections`);
            if (currentActiveServer === targetServerId && connResp.ok) {
                const connData = await connResp.json();
                connBody.innerHTML = '';
                const tcps = connData.tcp || [];
                const udps = connData.udp || [];

                if (tcps.length === 0 && udps.length === 0) {
                    connBody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; opacity:0.5;">No active socket connections found.</td></tr>';
                } else {
                    tcps.slice(0, 50).forEach(c => {
                        const row = document.createElement('tr');
                        let stateBadge = `<span class="badge badge-success">${c.state}</span>`;
                        if (c.state === 'ESTABLISHED') stateBadge = `<span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa;">ESTABLISHED</span>`;
                        else if (c.state === 'TIME_WAIT') stateBadge = `<span class="badge" style="background:rgba(245,158,11,0.15); color:var(--warning);">TIME_WAIT</span>`;
                        else if (c.state === 'LISTEN') stateBadge = `<span class="badge badge-success">LISTEN</span>`;

                        row.innerHTML = `
                            <td><strong style="color:var(--primary);">TCP</strong></td>
                            <td style="font-family:var(--font-mono);">${c.local || 'N/A'}</td>
                            <td style="font-family:var(--font-mono);">${c.remote || 'N/A'}</td>
                            <td>${stateBadge}</td>
                        `;
                        connBody.appendChild(row);
                    });
                    udps.slice(0, 20).forEach(c => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td><strong style="color:#c084fc;">UDP</strong></td>
                            <td style="font-family:var(--font-mono);">${c.local || 'N/A'}</td>
                            <td style="font-family:var(--font-mono);">${c.remote || 'N/A'}</td>
                            <td><span class="badge" style="background:rgba(168,85,247,0.15); color:#c084fc;">STATELESS</span></td>
                        `;
                        connBody.appendChild(row);
                    });
                }
            }
        }
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        console.error("Error fetching network interfaces:", err);
        netBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--danger);"><i class="fa-solid fa-circle-exclamation"></i> ${err.message}</td></tr>`;
    }
}

async function fetchServerHistory() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/history?limit=200`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) return;
        const { points } = await resp.json();
        if (currentActiveServer !== targetServerId) return;
        if (!points || points.length === 0) return;

        if (cpuHistoryChart) {
            cpuHistoryChart.data1 = [];
            points.forEach(p => cpuHistoryChart.data1.push(p.cpu));
            cpuHistoryChart.draw();
        }
        if (memoryHistoryChart) {
            memoryHistoryChart.data1 = [];
            memoryHistoryChart.data2 = [];
            points.forEach(p => { memoryHistoryChart.data1.push(p.ram_used_pct); memoryHistoryChart.data2.push(p.swap_used_pct); });
            memoryHistoryChart.draw();
        }
        if (networkHistoryChart) {
            networkHistoryChart.data1 = [];
            networkHistoryChart.data2 = [];
            points.forEach(p => { networkHistoryChart.data1.push(p.net_rx_kb); networkHistoryChart.data2.push(p.net_tx_kb); });
            networkHistoryChart.maxVal = Math.max(2000, ...networkHistoryChart.data1, ...networkHistoryChart.data2);
            networkHistoryChart.draw();
        }
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        console.error("Error fetching history:", err);
    }
}

async function renderGlobalAlerts() {
    const body = document.getElementById('global-rules-list-body');
    if (!body) return;
    body.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; opacity: 0.5;">Loading alert rules...</td></tr>';
    try {
        const rulesResp = await fetch('/api/alerts/rules');
        const allRules = await rulesResp.json();

        // Cache rules
        allRules.forEach(r => { rulesCache[r.id] = r; });

        const serversResp = await fetch('/api/servers');
        const servers = await serversResp.json();
        const sMap = {};
        const roleMap = {};
        servers.forEach(s => { 
            sMap[s.id] = s.hostname; 
            roleMap[s.id] = s.role;
        });

        const myEmail = (window.currentUserEmail || '').toLowerCase();

        // Only show rules that are relevant to the current user:
        // - recipient_type === 'self' (targeted at the creator, i.e. me)
        // - recipient_type === 'all' (broadcast — affects everyone)
        // - recipient_type === 'specific' and recipient_email contains my email
        const rules = allRules.filter(r => {
            if (r.recipient_type === 'all') return true;
            if (r.recipient_type === 'self') return true;
            if (r.recipient_type === 'specific' && myEmail) {
                const emails = (r.recipient_email || '').toLowerCase().split(',').map(e => e.trim());
                return emails.includes(myEmail);
            }
            return false;
        });

        body.innerHTML = '';
        if (rules.length === 0) {
            body.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; opacity: 0.5;">No alert rules relevant to your account are configured.</td></tr>';
            return;
        }

        rules.forEach(r => {
            const row = document.createElement('tr');
            const role = roleMap[r.server_id] || 'viewer';
            const canEdit = role === 'admin' || role === 'operator' || role === 'member';

            row.innerHTML = `
                <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(sMap[r.server_id] || 'Unknown Node')}</td>
                <td colspan="3">${getRuleDescription(r)}</td>
                <td style="font-family: var(--font-mono);">${r.duration_minutes} min</td>
                <td>${r.recipient_type === 'all' ? '\uD83D\uDC65 Everyone' : r.recipient_type === 'self' ? '\uD83D\uDC64 Me' : '\uD83D\uDCE7 ' + escapeHtml(r.recipient_email)}</td>
                <td><span class="badge ${r.is_active ? 'badge-success' : 'badge-danger'}">${r.is_active ? 'Active' : 'Muted'}</span></td>
                <td>
                    ${canEdit ? `
                    <button onclick="editAlertRule('${r.id}')" style="background-color: var(--primary); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; cursor: pointer; margin-right: 5px;"><i class="fa-solid fa-edit"></i> Edit</button>
                    <button onclick="deleteGlobalAlertRule('${r.id}')" style="background-color: var(--danger); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;"><i class="fa-solid fa-trash"></i> Delete</button>
                    ` : `
                    <button disabled style="background-color: var(--primary); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; opacity: 0.4; cursor: not-allowed; margin-right: 5px;" title="Only admins/operators can edit"><i class="fa-solid fa-edit"></i> Edit</button>
                    <button disabled style="background-color: var(--danger); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; opacity: 0.4; cursor: not-allowed;" title="Only admins/operators can delete"><i class="fa-solid fa-trash"></i> Delete</button>
                    `}
                </td>
            `;
            body.appendChild(row);
        });

    } catch (err) {
        body.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--danger);">Failed to load alert rules: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function deleteGlobalAlertRule(ruleId) {
    if (!confirm("Are you sure you want to delete this alert rule?")) return;
    try {
        const resp = await fetch(`/api/alerts/rules?id=${ruleId}`, { method: 'DELETE' });
        if (resp.ok) {
            alert("Alert rule deleted successfully.");
            renderGlobalAlerts();
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
        }
    } catch (err) {
        console.error("Failed to delete alert rule:", err);
    }
}

async function registerAlertRule(serverId, metric, operator, threshold, duration, email, targetType = 'server', targetValue = '', recipientType = 'self') {
    try {
        const payload = {
            server_id: serverId,
            metric_type: metric,
            operator: operator,
            threshold: isNaN(threshold) ? 0 : threshold,
            duration_minutes: duration,
            recipient_email: email,
            recipient_type: recipientType,
            is_active: true,
            target_type: targetType,
            target_value: targetValue
        };
        if (metric === 'process_down') {
            payload.operator = '==';
            payload.threshold = 0;
        }

        const resp = await fetchWithErrorHandling(
            '/api/alerts/rules', 
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            },
            'Alert Rule Registration Failed'
        );

        if (resp && resp.ok) {
            showToast('Alert Rule Registered', `Alert rule registered successfully.`, 'success', 4000);
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (currentActiveServer === serverId) updateRulesList(serverId);
        }
    } catch (err) {
        console.error("Failed to add alert rule:", err);
    }
}

async function deleteAlertRule(ruleId) {
    if (!confirm("Are you sure you want to delete this alert rule?")) return;
    try {
        const resp = await fetchWithErrorHandling(
            `/api/alerts/rules?id=${ruleId}`, 
            { method: 'DELETE' },
            'Alert Rule Deletion Failed'
        );
        if (resp && resp.ok) {
            showToast('Alert Rule Deleted', 'Alert rule removed successfully.', 'info', 3000);
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (currentActiveServer) updateRulesList(currentActiveServer);
        }
    } catch (err) {
        console.error("Failed to delete alert rule:", err);
    }
}

function onAlertRecipientTypeChange(select, prefix) {
    const val = select.value;
    const emailGroup = document.getElementById(prefix + 'alert-email-group');
    const displayGroup = document.getElementById(prefix + 'alert-email-display-group');
    const displayInput = document.getElementById(prefix + 'alert-email-display');

    // 'Specific user(s)' search group (replaces old email input)
    if (emailGroup) emailGroup.style.display = val === 'specific' ? 'block' : 'none';

    // 'Alert will be sent to:' readonly box — ONLY shown when recipient is 'Me'
    if (displayGroup) displayGroup.style.display = val === 'self' ? 'block' : 'none';
    if (val === 'self' && displayInput) displayInput.value = window.currentUserEmail || '';
    if (val === 'all' && displayInput) displayInput.value = 'All team members';
}

// Tracks selected alert users per form prefix
const alertSelectedUsers = { 'create-': {}, 'edit-': {} };

let _alertUserSearchTimer = null;
async function searchAlertUser(inputEl, prefix) {
    const query = inputEl.value.trim();
    const resultsEl = document.getElementById(prefix + 'alert-user-results');
    if (!resultsEl) return;

    clearTimeout(_alertUserSearchTimer);
    _alertUserSearchTimer = setTimeout(async () => {
        try {
            // First search server members who match
            let candidates = [];
            if (currentActiveServer) {
                const membResp = await fetch(`/api/servers/members?id=${currentActiveServer}`);
                if (membResp.ok) {
                    const membData = await membResp.json();
                    candidates = (membData.members || []).filter(m =>
                        !query || (m.username && m.username.toLowerCase().includes(query.toLowerCase()))
                    );
                }
            }

            resultsEl.innerHTML = '';
            if (candidates.length === 0) {
                resultsEl.innerHTML = '<div style="padding:8px 12px; font-size:12px; color:var(--text-secondary);">No users found</div>';
                resultsEl.style.display = 'block';
                return;
            }

            candidates.forEach(u => {
                const item = document.createElement('div');
                item.style.cssText = 'display:flex; align-items:center; gap:8px; padding:7px 12px; cursor:pointer; font-size:13px; border-bottom:1px solid var(--border-color); transition: background 0.15s;';
                item.onmouseover = () => item.style.background = 'rgba(255,255,255,0.05)';
                item.onmouseout = () => item.style.background = '';
                const avatarSrc = `https://github.com/${u.username}.png?size=24`;
                item.innerHTML = `<img src="${avatarSrc}" style="width:22px; height:22px; border-radius:50%;" onerror="this.src='https://github.com/identicons/${escapeHtml(u.username)}.png'"><span>${escapeHtml(u.username)}</span>${u.email ? `<span style="opacity:0.5; font-size:11px;">(${escapeHtml(u.email)})</span>` : ''}`;
                item.onclick = () => {
                    addAlertUserTag(prefix, u.username, u.email || '');
                    resultsEl.style.display = 'none';
                    inputEl.value = '';
                };
                resultsEl.appendChild(item);
            });
            resultsEl.style.display = 'block';
        } catch (e) {
            resultsEl.style.display = 'none';
        }
    }, 150);
}


function addAlertUserTag(prefix, username, email) {
    if (!alertSelectedUsers[prefix]) alertSelectedUsers[prefix] = {};
    if (alertSelectedUsers[prefix][username]) return; // already added
    alertSelectedUsers[prefix][username] = email;
    renderAlertUserTags(prefix);
    updateAlertEmailHidden(prefix);
}

function removeAlertUserTag(prefix, username) {
    if (alertSelectedUsers[prefix]) delete alertSelectedUsers[prefix][username];
    renderAlertUserTags(prefix);
    updateAlertEmailHidden(prefix);
}

function renderAlertUserTags(prefix) {
    const tagsEl = document.getElementById(prefix + 'alert-user-tags');
    if (!tagsEl) return;
    tagsEl.innerHTML = '';
    const users = alertSelectedUsers[prefix] || {};
    Object.entries(users).forEach(([uname, uemail]) => {
        const tag = document.createElement('div');
        tag.style.cssText = 'display:inline-flex; align-items:center; gap:5px; background:var(--primary); color:white; padding:3px 8px 3px 6px; border-radius:20px; font-size:12px; font-weight:600;';
        tag.innerHTML = `<img src="https://github.com/${escapeHtml(uname)}.png?size=18" style="width:16px; height:16px; border-radius:50%;" onerror="this.src='https://github.com/identicons/${escapeHtml(uname)}.png'"><span>${escapeHtml(uname)}</span><button onclick="removeAlertUserTag('${escapeHtml(prefix)}', '${escapeHtml(uname)}')" style="background:none; border:none; color:white; cursor:pointer; font-size:14px; line-height:1; padding:0; margin-left:2px; opacity:0.8;">×</button>`;
        tagsEl.appendChild(tag);
    });
}

function updateAlertEmailHidden(prefix) {
    const hiddenEl = document.getElementById((prefix === 'create-' ? '' : prefix) + 'alert-email');
    if (!hiddenEl) return;
    const users = alertSelectedUsers[prefix] || {};
    // Collect emails — if a user has no email in DB, store their username so backend can look it up
    const emailList = Object.entries(users).map(([uname, uemail]) => uemail || `@${uname}`).join(',');
    hiddenEl.value = emailList;
}

async function updateRulesList(serverId) {
    const configuredRulesContainer = document.getElementById('configured-rules-container');
    if (!configuredRulesContainer) return;
    try {
        const resp = await fetch('/api/alerts/rules');
        if (currentActiveServer !== serverId) return;
        const rules = await resp.json();
        if (currentActiveServer !== serverId) return;

        // Cache rules
        rules.forEach(r => { rulesCache[r.id] = r; });

        const serverRules = rules.filter(r => r.server_id === serverId);
        configuredRulesContainer.innerHTML = '';

        if (serverRules.length === 0) {
            configuredRulesContainer.innerHTML = '<p style="font-size:13px; color:var(--text-secondary);">No alerts defined for this machine.</p>';
            return;
        }

        serverRules.forEach(rule => {
            const item = document.createElement('div');
            item.className = 'rule-item';
            item.innerHTML = `
                <div style="display:flex; flex-direction:column; gap:2px;">
                    <span>${getRuleDescription(rule)} (${rule.duration_minutes}m)</span>
                    <span style="opacity: 0.6; font-size:11px;">
                        ${rule.recipient_type === 'all' ? '👥 Everyone' : rule.recipient_type === 'self' ? '👤 Me' : '📧 ' + rule.recipient_email}
                    </span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <button class="rule-edit-btn" onclick="editAlertRule(${rule.id})" style="background: var(--primary); border: none; color: white; border-radius: 4px; padding: 4px 6px; font-size: 11px; cursor: pointer; display: flex; align-items: center; justify-content: center; width: 24px; height: 24px;"><i class="fa-solid fa-edit"></i></button>
                    <button class="rule-delete-btn" onclick="deleteAlertRule(${rule.id})" style="width: 24px; height: 24px; display: flex; align-items: center; justify-content: center;"><i class="fa-solid fa-trash"></i></button>
                </div>
            `;
            configuredRulesContainer.appendChild(item);
        });
    } catch (err) {
        console.error("Error updating rules list:", err);
    }
}

function openRegisterModal() {
    const el = document.getElementById('register-modal-overlay');
    if (el) el.classList.add('open');
}

function closeRegisterModal() {
    const el = document.getElementById('register-modal-overlay');
    if (el) el.classList.remove('open');
    const form = document.getElementById('register-server-form');
    if (form) form.reset();
}

async function handleRegisterServer(e) {
    e.preventDefault();
    const hostname = document.getElementById('reg-hostname').value.trim();
    const ipAddress = document.getElementById('reg-ip').value.trim();
    const osFamily = document.getElementById('reg-os').value;
    const sshUser = document.getElementById('reg-ssh-user').value.trim();
    const sshPassword = document.getElementById('reg-ssh-password').value;
    const sshPortRaw = parseInt(document.getElementById('reg-ssh-port').value, 10);
    const sshPort = isNaN(sshPortRaw) ? 22 : sshPortRaw;
    const sshKey = document.getElementById('reg-ssh-key').value;

    if (!hostname || !ipAddress) {
        alert("Please fill in hostname and IP address.");
        return;
    }
    if (!sshUser || (!sshKey && !sshPassword)) {
        alert("SSH credentials are required: please provide the SSH user and either a private key or a password to register a server.");
        return;
    }

    try {
        const resp = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                hostname,
                ip_address: ipAddress,
                os_family: osFamily,
                ssh_user: sshUser,
                ssh_password: sshPassword,
                ssh_port: sshPort,
                ssh_key: sshKey
            })
        });

        const res = await resp.json();
        if (resp.ok) {
            alert("Server successfully registered and added to catalog!");
            closeRegisterModal();
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
        } else {
            alert(`Registration failed: ${res.message || 'Unknown error'}`);
        }
    } catch (e) {
        console.error("Error registering server:", e);
        alert("Error connecting to host backend. Please try again.");
    }
}

let pendingServerToDelete = null;

function unregisterCurrentServer() {
    if (!currentActiveServer) {
        alert("No server currently active or selected.");
        return;
    }
    confirmDeleteServerNode(currentActiveServer);
}

function deleteServer(serverId) {
    if (!serverId) return;
    confirmDeleteServerNode(serverId);
}

function confirmDeleteServerNode(serverId) {
    pendingServerToDelete = serverId;
    const serverObj = serversMap[serverId];
    const serverName = serverObj ? serverObj.hostname : 'this server';
    const serverIP = serverObj ? serverObj.ip_address : '';
    
    const textEl = document.getElementById('unregister-confirm-text');
    if (textEl) {
        textEl.innerText = `Are you sure you want to deregister '${serverName}'${serverIP ? ' (' + serverIP + ')' : ''}?`;
    }
    
    const modal = document.getElementById('unregister-confirm-modal');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('open');
    }
}

function closeUnregisterConfirmModal() {
    pendingServerToDelete = null;
    const modal = document.getElementById('unregister-confirm-modal');
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('open');
    }
}

async function executeServerUnregister() {
    const serverToDelete = pendingServerToDelete || currentActiveServer;
    if (!serverToDelete) {
        closeUnregisterConfirmModal();
        return;
    }

    const serverObj = serversMap[serverToDelete];
    const serverName = serverObj ? serverObj.hostname : 'this server';

    const btn = document.getElementById('confirm-unregister-btn-action');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deregistering...';
    }

    try {
        const resp = await fetchWithErrorHandling(
            `/api/servers/unregister?id=${encodeURIComponent(serverToDelete)}`, 
            { method: 'DELETE' },
            'Deregister Node Failed'
        );

        if (resp && (resp.ok || resp.status === 200 || resp.status === 204)) {
            closeUnregisterConfirmModal();
            closeDetailsModal();
            
            showToast('Node Deregistered', `Server node '${serverName}' removed from fleet catalog.`, 'info', 4000);

            // Delete from local cache and DOM immediately
            delete serversMap[serverToDelete];
            const card = document.getElementById(`server-card-${serverToDelete}`);
            if (card) card.remove();

            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (typeof renderSettingsView === 'function') renderSettingsView();
        }
    } catch (e) {
        console.error("Error unregistering server:", e);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-trash-can"></i> Yes, Deregister Node';
        }
        pendingServerToDelete = null;
    }
}

function manualRefreshSystem() {
    if (!currentActiveServer) return;
    const server = serversMap[currentActiveServer];
    if (server) {
        updateTelemetryMetrics(server);
    }
}

// Global window exposure for inline onclick handlers
window.unregisterCurrentServer = unregisterCurrentServer;
window.deleteServer = deleteServer;
window.confirmDeleteServerNode = confirmDeleteServerNode;
window.closeUnregisterConfirmModal = closeUnregisterConfirmModal;
window.executeServerUnregister = executeServerUnregister;
window.openServerDetails = openServerDetails;
window.closeDetailsModal = closeDetailsModal;
window.manualRefreshSystem = manualRefreshSystem;
window.switchMainView = switchMainView;
window.renderSettingsView = renderSettingsView;
window.deleteGlobalAlertRule = deleteGlobalAlertRule;
window.handleRegisterServerSettings = handleRegisterServerSettings;
window.searchAlertUser = searchAlertUser;
window.removeAlertUserTag = removeAlertUserTag;
window.onAlertRecipientTypeChange = onAlertRecipientTypeChange;

function switchMainView(viewName) {
    const menuIds = ['sidebar-menu-dashboard', 'sidebar-menu-alerts', 'sidebar-menu-settings'];
    menuIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (id === `sidebar-menu-${viewName}`) {
                el.classList.add('active');
            } else {
                el.classList.remove('active');
            }
        }
    });

    const viewIds = ['dashboard-view', 'alerts-view', 'settings-view'];
    viewIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (id === `${viewName}-view`) {
                el.style.display = 'block';
            } else {
                el.style.display = 'none';
            }
        }
    });

    if (viewName === 'alerts') {
        renderGlobalAlerts();
    } else if (viewName === 'settings') {
        renderSettingsView();
    }
}

async function renderSettingsView() {
    const body = document.getElementById('settings-servers-list-body');
    if (!body) return;
    body.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px; opacity: 0.5;">Loading registered nodes...</td></tr>';
    try {
        const resp = await fetch('/api/servers');
        if (!resp.ok) throw new Error(`HTTP error ${resp.status}`);
        const servers = await resp.json();
        
        body.innerHTML = '';
        if (servers.length === 0) {
            body.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px; opacity: 0.5;">No registered nodes in the fleet catalog.</td></tr>';
            return;
        }

        servers.forEach(s => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="padding: 12px; border-bottom: 1px solid var(--border-color); font-weight: 600; color: var(--text-primary);">${s.hostname}</td>
                <td style="padding: 12px; border-bottom: 1px solid var(--border-color); font-family: var(--font-mono);">${s.ip_address}</td>
                <td style="padding: 12px; border-bottom: 1px solid var(--border-color); text-transform: capitalize;">${s.os_family}</td>
                <td style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                    <button onclick="deleteServer('${s.id}')" style="background-color: var(--danger); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;"><i class="fa-solid fa-trash"></i> Delete</button>
                </td>
            `;
            body.appendChild(row);
        });
    } catch (err) {
        body.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 20px; color: var(--danger);">Failed to load registered nodes: ${err.message}</td></tr>`;
    }
}


async function handleRegisterServerSettings(event) {
    event.preventDefault();
    const hostname = document.getElementById('set-reg-hostname').value.trim();
    const ip = document.getElementById('set-reg-ip').value.trim();
    const os = document.getElementById('set-reg-os').value;
    const sshUser = document.getElementById('set-reg-ssh-user').value.trim();
    const sshPassword = document.getElementById('set-reg-ssh-password').value;
    const sshPortRaw = parseInt(document.getElementById('set-reg-ssh-port').value, 10);
    const sshPort = isNaN(sshPortRaw) ? 22 : sshPortRaw;
    const sshKey = document.getElementById('set-reg-ssh-key').value;

    if (!hostname || !ip || !sshUser || (!sshKey && !sshPassword)) {
        showToast('Form Validation Error', 'Hostname, IP address, SSH user and (private key or password) are required.', 'warning', 5000);
        return;
    }

    try {
        const resp = await fetchWithErrorHandling(
            '/api/register', 
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    hostname: hostname,
                    ip_address: ip,
                    os_family: os,
                    ssh_user: sshUser,
                    ssh_password: sshPassword,
                    ssh_port: sshPort,
                    ssh_key: sshKey
                })
            },
            'Server Registration Failed'
        );

        if (resp && resp.ok) {
            showToast('Server Registered', `Server '${hostname}' registered successfully to fleet catalog.`, 'success', 4000);
            document.getElementById('settings-register-form').reset();
            renderSettingsView();
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
        }
    } catch (err) {
        console.error("Error registering server:", err);
    }
}

window.editAlertRule = editAlertRule;
window.closeEditAlertModal = closeEditAlertModal;
window.handleEditAlertSubmit = handleEditAlertSubmit;
window.onAlertMetricChange = onAlertMetricChange;

function onAlertMetricChange(selectEl, prefix) {
    const customGroup = document.getElementById(`${prefix}alert-metric-custom-group`);
    if (customGroup) {
        if (selectEl && selectEl.value === 'custom') {
            customGroup.style.display = 'block';
        } else {
            customGroup.style.display = 'none';
        }
    }
    
    const operatorGroup = document.getElementById(`${prefix}alert-operator-group`);
    const thresholdGroup = document.getElementById(`${prefix}alert-threshold-group`);
    if (selectEl && selectEl.value === 'process_down') {
        if (operatorGroup) operatorGroup.style.display = 'none';
        if (thresholdGroup) thresholdGroup.style.display = 'none';
    } else {
        if (operatorGroup) operatorGroup.style.display = 'block';
        if (thresholdGroup) thresholdGroup.style.display = 'block';
    }
}

function editAlertRule(ruleId) {
    const rule = rulesCache[ruleId];
    if (!rule) return;

    const serverObj = serversMap[rule.server_id];
    const serverName = serverObj ? serverObj.hostname : 'Unknown Node';

    document.getElementById('edit-alert-id').value = rule.id;
    document.getElementById('edit-alert-server-id').value = rule.server_id;
    document.getElementById('edit-alert-server').value = serverName;

    const type = rule.target_type || 'server';
    const typeSelect = document.getElementById('edit-alert-target-type');
    if (typeSelect) {
        typeSelect.value = type;
        onAlertTargetTypeChange(typeSelect, 'edit-');
    }
    
    const valInput = document.getElementById('edit-alert-target-value');
    if (valInput) {
        valInput.value = rule.target_value || '';
    }

    const metricSelect = document.getElementById('edit-alert-metric');
    const customGroup = document.getElementById('edit-alert-metric-custom-group');
    const customInput = document.getElementById('edit-alert-metric-custom');

    if (type === 'server') {
        const isCustomMetric = !['cpu', 'ram', 'disk'].includes(rule.metric_type);
        if (isCustomMetric) {
            metricSelect.value = 'custom';
            customInput.value = rule.metric_type;
            if (customGroup) customGroup.style.display = 'block';
        } else {
            metricSelect.value = rule.metric_type;
            customInput.value = '';
            if (customGroup) customGroup.style.display = 'none';
        }
    } else {
        metricSelect.value = rule.metric_type;
        customInput.value = '';
        if (customGroup) customGroup.style.display = 'none';
    }
    onAlertMetricChange(metricSelect, 'edit-');

    document.getElementById('edit-alert-operator').value = rule.operator || '>';
    document.getElementById('edit-alert-threshold').value = rule.threshold || '';
    document.getElementById('edit-alert-duration').value = rule.duration_minutes;
    const rt = rule.recipient_type || 'self';
    const rtSelect = document.getElementById('edit-alert-recipient-type');
    if (rtSelect) {
        // Ensure 'all' option exists when editing a rule that was set to 'all'
        // (it may have been stripped for non-admins, but they need to see the current value)
        if (rt === 'all' && !rtSelect.querySelector('option[value="all"]')) {
            const allOpt = document.createElement('option');
            allOpt.value = 'all';
            allOpt.textContent = 'Everyone (all team members)';
            rtSelect.insertBefore(allOpt, rtSelect.options[1]);
        }
        rtSelect.value = rt;
        onAlertRecipientTypeChange(rtSelect, 'edit-');
    }
    document.getElementById('edit-alert-email').value = rule.recipient_type === 'specific' ? rule.recipient_email : '';
    const editDisplay = document.getElementById('edit-alert-email-display');
    if (editDisplay) {
        if (rt === 'self') editDisplay.value = window.currentUserEmail || rule.recipient_email;
        else if (rt === 'all') editDisplay.value = 'All team members';
        else editDisplay.value = rule.recipient_email;
    }
    document.getElementById('edit-alert-active').checked = rule.is_active;

    const modal = document.getElementById('edit-alert-modal');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('open');
    }
}

function closeEditAlertModal() {
    const modal = document.getElementById('edit-alert-modal');
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('open');
    }
}

async function handleEditAlertSubmit(event) {
    event.preventDefault();
    const id = document.getElementById('edit-alert-id').value;
    const serverId = document.getElementById('edit-alert-server-id').value;
    let metric = document.getElementById('edit-alert-metric').value;
    if (metric === 'custom') {
        metric = document.getElementById('edit-alert-metric-custom').value.trim();
        if (!metric) {
            showToast('Form Validation Error', 'Custom metric key is required.', 'warning', 4000);
            return;
        }
    }
    const operator = document.getElementById('edit-alert-operator').value;
    const threshold = parseFloat(document.getElementById('edit-alert-threshold').value);
    const duration = parseInt(document.getElementById('edit-alert-duration').value);
    const recipientType = document.getElementById('edit-alert-recipient-type').value;
    let email = document.getElementById('edit-alert-email').value.trim();
    if (recipientType === 'self') email = window.currentUserEmail || '';
    if (recipientType === 'all') email = '';
    const isActive = document.getElementById('edit-alert-active').checked;
    const targetType = document.getElementById('edit-alert-target-type').value;
    const targetValue = document.getElementById('edit-alert-target-value').value.trim();

    if (!id || !serverId || !metric || (recipientType === 'specific' && !email) || (metric !== 'process_down' && isNaN(threshold)) || isNaN(duration)) {
        showToast('Form Validation Error', 'All fields are required.', 'warning', 5000);
        return;
    }

    const rule = rulesCache[id] || {};
    const isFiring = rule.is_firing || false;

    const payload = {
        id: parseInt(id),
        server_id: serverId,
        metric_type: metric,
        operator: operator,
        threshold: isNaN(threshold) ? 0 : threshold,
        duration_minutes: duration,
        recipient_email: email,
        recipient_type: recipientType,
        is_active: isActive,
        is_firing: isFiring,
        target_type: targetType,
        target_value: targetValue
    };
    if (metric === 'process_down') {
        payload.operator = '==';
        payload.threshold = 0;
    }

    try {
        const resp = await fetchWithErrorHandling(
            `/api/alerts/rules?id=${id}`,
            {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            },
            'Failed to Update Alert Rule'
        );

        if (resp && resp.ok) {
            showToast('Alert Rule Updated', 'The alert rule has been successfully updated.', 'success', 4000);
            closeEditAlertModal();
            // Refresh views
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (currentActiveServer) updateRulesList(currentActiveServer);
            // Also refresh global alerts view in case it's open
            const alertsView = document.getElementById('alerts-view');
            if (alertsView && alertsView.style.display !== 'none') {
                renderGlobalAlerts();
            }
        }
    } catch (err) {
        console.error("Error updating alert rule:", err);
    }
}

// COMMANDS TAB
let cachedCommandSets = [];

async function fetchServerCommands() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    try {
        // Always fetch role fresh — ensures admin section is correct regardless of cache state
        let userRole = 'viewer';
        try {
            const membersResp = await fetch(`/api/servers/members?id=${targetServerId}`);
            if (currentActiveServer !== targetServerId) return;
            if (membersResp.ok) {
                const membersData = await membersResp.json();
                if (currentActiveServer !== targetServerId) return;
                userRole = membersData.current_user_role || 'viewer';
                window.currentUserRole = userRole;
            }
        } catch (e) {
            if (currentActiveServer !== targetServerId) return;
            userRole = window.currentUserRole || 'viewer';
        }

        const resp = await fetch(`/api/servers/detail/${targetServerId}/commands`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) {
            // Still show the admin section so admin can add commands even if fetch failed
            renderCommandSets(userRole);
            return;
        }
        cachedCommandSets = await resp.json();
        if (currentActiveServer !== targetServerId) return;
        renderCommandSets(userRole);
        renderCommandLogs();
    } catch (err) {
        console.error("Failed to fetch command sets:", err);
    }
}

function renderCommandSets(userRole) {
    // Accept userRole param; fall back to window.currentUserRole if not provided
    const role = userRole || window.currentUserRole || 'viewer';
    const container = document.getElementById('command-sets-container');
    const adminSection = document.getElementById('commands-admin-section');
    if (!container) return;

    if (cachedCommandSets.length === 0) {
        container.innerHTML = '<p style="font-size:13px; color:var(--text-secondary); padding:20px; text-align:center;">No command sets configured. ' +
            (role === 'admin' ? 'Use the form above to add one.' : 'Ask an admin to configure commands.') + '</p>';
    } else {
        container.innerHTML = '';
        cachedCommandSets.forEach(set => {
            const card = document.createElement('div');
            card.className = 'rule-item';
            card.dataset.serviceName = set.service_name.toLowerCase();
            card.style.flexDirection = 'column';
            card.style.alignItems = 'stretch';
            card.style.gap = '8px';

            let actionsHtml = '';
            Object.entries(set.commands).forEach(([type, cmd]) => {
                const canExecute = role === 'admin' || role === 'operator';
                actionsHtml += `<button class="btn-refresh" style="font-size:11px; padding:4px 10px; ${!canExecute ? 'opacity:0.5; cursor:not-allowed;' : ''}" 
                    ${canExecute ? `onclick="executeCommand('${set.service_name}', '${type}')"` : 'disabled'}
                    title="${cmd.replace(/"/g, '&quot;')}"><i class="fa-solid fa-play"></i> ${type}</button>`;
            });

            const isAdmin = role === 'admin';
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="color:var(--text-primary); font-size:14px;"><i class="fa-solid fa-cube"></i> ${set.service_name}</strong>
                    <div style="display:flex; gap:6px; align-items:center;">
                        ${isAdmin ? `<button class="btn-refresh" onclick="editCommandSet('${set.service_name}')" style="font-size:11px; padding:4px 8px;" title="Edit"><i class="fa-solid fa-edit"></i></button>
                        <button class="btn-refresh" onclick="deleteCommandSet('${set.service_name}')" style="font-size:11px; padding:4px 8px; color:var(--danger);" title="Delete"><i class="fa-solid fa-trash"></i></button>` : ''}
                    </div>
                </div>
                <div style="display:flex; flex-wrap:wrap; gap:6px;">
                    ${actionsHtml}
                </div>
            `;
            container.appendChild(card);
        });
    }

    // Show/hide admin JSON editor section based on role
    if (adminSection) {
        adminSection.style.display = role === 'admin' ? 'block' : 'none';
    }
}

function filterCommandSets() {
    const search = document.getElementById('cmd-search').value.toLowerCase();
    document.querySelectorAll('#command-sets-container .rule-item').forEach(card => {
        const name = card.dataset.serviceName || '';
        card.style.display = name.includes(search) ? '' : 'none';
    });
}

async function fetchCommandLogs() {
    if (!currentActiveServer) return;
    const targetServerId = currentActiveServer;
    try {
        const resp = await fetch(`/api/servers/detail/${targetServerId}/commands/logs`);
        if (currentActiveServer !== targetServerId) return;
        if (!resp.ok) return;
        const logs = await resp.json();
        if (currentActiveServer !== targetServerId) return;
        renderCommandLogsTable(logs);
    } catch (err) {
        console.error("Failed to fetch command logs:", err);
    }
}


function renderCommandLogs() {
    fetchCommandLogs();
}

let cachedLogs = [];

function renderCommandLogsTable(logs) {
    cachedLogs = logs;
    const body = document.getElementById('cmd-log-body');
    if (!body) return;
    if (logs.length === 0) {
        body.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:15px; opacity:0.5;">No commands have been executed yet.</td></tr>';
        return;
    }
    body.innerHTML = '';
    logs.forEach(l => {
        const row = document.createElement('tr');
        const time = new Date(l.executed_at).toLocaleString();
        const isSuccess = l.status === 'success';
        const cmdEscaped = (l.command || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const durationSec = ((l.duration_ms || 0) / 1000).toFixed(2) + 's';
        row.innerHTML = `
            <td>${l.service_name}</td>
            <td><code style="font-size:11px;">${l.command_type}</code></td>
            <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${cmdEscaped}"><code style="font-size:11px;">${cmdEscaped}</code></td>
            <td>${l.executed_by}</td>
            <td>${time}</td>
            <td>${durationSec}</td>
            <td><span class="badge ${isSuccess ? 'badge-success' : 'badge-danger'}">${l.status}</span></td>
            <td><button class="btn-refresh" style="font-size:10px; padding:2px 6px;" onclick="showCommandOutput(${l.id})"><i class="fa-solid fa-eye"></i></button></td>
        `;
        body.appendChild(row);
    });
}

function showCommandOutput(id) {
    const log = cachedLogs.find(l => l.id === id);
    if (!log) return;
    const durationSec = ((log.duration_ms || 0) / 1000).toFixed(2);
    const output = log.output || '(no output)';
    const maxLen = 500;
    const display = output.length > maxLen ? output.substring(0, maxLen) + '...' : output;
    const escaped = (display).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    showToast(`Command Output #${id} (ran for ${durationSec}s)`, `<pre style="max-height:300px; overflow:auto; font-size:11px; text-align:left; background:#000; padding:10px; border-radius:4px; white-space:pre-wrap; color:#0f0;">${escaped}</pre>`, 'info', 8000, true);
}

function editCommandSet(serviceName) {
    const set = cachedCommandSets.find(s => s.service_name === serviceName);
    if (!set) return;
    document.getElementById('cmd-service-name').value = set.service_name;
    document.getElementById('cmd-commands-json').value = JSON.stringify(set.commands, null, 4);
    document.getElementById('commands-admin-section').scrollIntoView({ behavior: 'smooth' });
}

function resetCommandForm() {
    document.getElementById('cmd-service-name').value = '';
    document.getElementById('cmd-commands-json').value = '';
}

async function deleteCommandSet(serviceName) {
    if (!confirm(`Delete command set "${serviceName}"?`)) return;
    try {
        const resp = await fetch(`/api/servers/detail/${currentActiveServer}/commands?name=${encodeURIComponent(serviceName)}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('Deleted', `Command set "${serviceName}" deleted.`, 'info', 3000);
            fetchServerCommands();
        }
    } catch (err) {
        console.error("Failed to delete command set:", err);
    }
}

async function executeCommand(serviceName, commandType) {
    if (!confirm(`Execute "${commandType}" on "${serviceName}"?`)) return;
    try {
        const resp = await fetch(`/api/servers/detail/${currentActiveServer}/commands/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ service_name: serviceName, command_type: commandType })
        });
        if (resp.ok) {
            const result = await resp.json().catch(() => ({ status: 'success', output: 'Success', duration_ms: 0 }));
            const durationSec = ((result.duration_ms || 0) / 1000).toFixed(2);
            const durationText = `ran for ${durationSec}s`;
            const displayOutput = (result.output || 'No output').substring(0, 500);
            const escapedOutput = escapeHtml(displayOutput);
            const msgHtml = `<strong>Status:</strong> ${result.status} (${durationText})<br><pre style="font-size:11px; text-align:left; background:#000; padding:8px; border-radius:4px; max-height:200px; overflow:auto; margin-top:5px; white-space:pre-wrap; color:#0f0;">${escapedOutput}</pre>`;
            showToast('Command Executed', msgHtml, result.status === 'success' ? 'success' : 'error', 8000, true);
        } else {
            let errMsg = 'Execution Failed';
            try {
                const result = await resp.json();
                errMsg = result.output || result.error || errMsg;
            } catch (_) {
                errMsg = await resp.text().catch(() => 'Execution Failed');
            }
            showToast('Execution Failed', errMsg, 'error', 5000);
        }
        fetchServerCommands();
    } catch (err) {
        showToast('Execution Error', err.message, 'error', 5000);
    }
}

// Initialize command set form handler
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('command-set-form');
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!currentActiveServer) return;
            const serviceName = document.getElementById('cmd-service-name').value.trim();
            let commands;
            try {
                commands = JSON.parse(document.getElementById('cmd-commands-json').value.trim());
            } catch (_) {
                showToast('Validation Error', 'Invalid JSON in commands field.', 'warning', 4000);
                return;
            }
            if (!serviceName || !commands || typeof commands !== 'object') {
                showToast('Validation Error', 'Service name and valid commands JSON are required.', 'warning', 4000);
                return;
            }
            try {
                const resp = await fetch(`/api/servers/detail/${currentActiveServer}/commands`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service_name: serviceName, commands })
                });
                if (resp.ok) {
                    showToast('Saved', `Command set "${serviceName}" saved.`, 'success', 3000);
                    resetCommandForm();
                    fetchServerCommands();
                } else {
                    let errMsg = 'Failed to save';
                    try {
                        const err = await resp.json();
                        errMsg = err.error || err.message || errMsg;
                    } catch (_) {
                        errMsg = await resp.text().catch(() => 'Failed to save');
                    }
                    showToast('Error', errMsg, 'error', 4000);
                }
            } catch (err) {
                showToast('Error', err.message, 'error', 4000);
            }
        });
    }
});

// SERVER TEAM ACCESS MANAGEMENT
let currentTeamServerId = null;

function openTeamModal(serverId, hostname) {
    currentTeamServerId = serverId;
    
    const serverIdEl = document.getElementById('team-server-id');
    const userEl = document.getElementById('team-invite-username');
    const roleEl = document.getElementById('team-invite-role');
    
    if (serverIdEl) serverIdEl.value = serverId;
    if (userEl) userEl.value = '';
    if (roleEl) roleEl.value = 'viewer';
    
    const modalTitle = document.querySelector('#team-modal .modal-header h3');
    if (modalTitle) {
        modalTitle.innerHTML = `<i class="fa-solid fa-users-gear"></i> Access &amp; Team Settings - ${hostname}`;
    }

    const modal = document.getElementById('team-modal');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('open');
    }
    
    loadServerMembers(serverId);
}

function closeTeamModal() {
    currentTeamServerId = null;
    const modal = document.getElementById('team-modal');
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('open');
    }
}

async function loadServerMembers(serverId) {
    try {
        const resp = await fetch(`/api/servers/members?id=${serverId}`);
        if (!resp.ok) {
            console.error("Failed to load server members");
            return;
        }
        const data = await resp.json();
        const members = data.members || [];
        const currentUserRole = data.current_user_role || 'viewer';

        const inviteSection = document.getElementById('team-invite-section');
        if (inviteSection) {
            inviteSection.style.display = currentUserRole === 'admin' ? 'block' : 'none';
        }

        const listContainer = document.getElementById('team-members-list');
        if (!listContainer) return;
        listContainer.innerHTML = '';

        if (members.length === 0) {
            listContainer.innerHTML = `<p style="text-align: center; color: var(--text-faint); margin: 20px 0; font-size: 13px;">No members added yet.</p>`;
            return;
        }

        // Deduplicate case-insensitively (guards against DB having both 'DevAyyan' and 'devayyan')
        // Keep the admin/highest-role entry when there are duplicates
        const seen = new Set();
        const uniqueMembers = members.filter(m => {
            const key = m.username.toLowerCase();
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        uniqueMembers.forEach(m => {
            const isSelf = m.username.toLowerCase() === (window.currentUserUsername || '').toLowerCase();

            const div = document.createElement('div');
            div.style.display = 'flex';
            div.style.alignItems = 'center';
            div.style.justifyContent = 'space-between';
            div.style.background = 'rgba(255, 255, 255, 0.02)';
            div.style.border = '1px solid var(--border-color)';
            div.style.padding = '8px 12px';
            div.style.borderRadius = '8px';
            div.style.gap = '10px';

            const avatarUrl = `https://github.com/${m.username}.png?size=40`;

            let roleControlHtml = '';
            if (currentUserRole === 'admin' && !isSelf) {
                // Admin can change other members' roles, but not their own (prevents self-demotion)
                roleControlHtml = `
                    <select onchange="updateMemberRole('${serverId}', '${m.username}', this.value)" style="background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-primary); font-size: 12px; padding: 4px 8px; border-radius: 4px; font-weight: 600;">
                        <option value="viewer" ${m.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                        <option value="operator" ${m.role === 'operator' || m.role === 'member' ? 'selected' : ''}>Operator</option>
                        <option value="admin" ${m.role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                `;
            } else {
                // Show role as a badge — can't change own role
                const roleLabel = m.role === 'member' ? 'operator' : m.role;
                roleControlHtml = `<span style="font-size: 11px; font-weight: 700; color: var(--text-secondary); background: rgba(255,255,255,0.06); padding: 3px 6px; border-radius: 4px; text-transform: uppercase; border: 1px solid var(--border-color);">${roleLabel}</span>`;
            }

            // Only admins can remove OTHER members. Never show a remove/leave button for yourself.
            let removeButtonHtml = '';
            if (currentUserRole === 'admin' && !isSelf) {
                removeButtonHtml = `
                    <button onclick="removeServerMember('${serverId}', '${m.username}', false)" style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); color: #f87171; cursor: pointer; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; transition: all 0.2s;" onmouseover="this.style.background='rgba(239, 68, 68, 0.15)'" onmouseout="this.style.background='rgba(239, 68, 68, 0.08)'">
                        Remove
                    </button>
                `;
            }

            div.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
                    <img src="${avatarUrl}" onerror="this.src='https://github.com/identicons/${m.username}.png'" style="width: 28px; height: 28px; border-radius: 50%; border: 1px solid var(--border-color); flex-shrink: 0;">
                    <div style="display: flex; flex-direction: column; min-width: 0;">
                        <span style="font-size: 13px; font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${m.username} ${isSelf ? '<span style="color: var(--primary); font-size: 11px;">(you)</span>' : ''}</span>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
                    ${roleControlHtml}
                    ${removeButtonHtml}
                </div>
            `;
            listContainer.appendChild(div);
        });

    } catch (e) {
        console.error("Error loading members:", e);
    }
}

async function handleTeamInvite(e) {
    e.preventDefault();
    const serverId = document.getElementById('team-server-id').value;
    const username = document.getElementById('team-invite-username').value.trim();
    const role = document.getElementById('team-invite-role').value;

    if (!serverId || !username) return;

    try {
        const resp = await fetch('/api/servers/members/invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_id: serverId, username, role })
        });
        const res = await resp.json();
        if (resp.ok) {
            document.getElementById('team-invite-username').value = '';
            loadServerMembers(serverId);
        } else {
            alert(res.message || "Failed to invite member.");
        }
    } catch (e) {
        console.error("Error inviting member:", e);
    }
}

async function updateMemberRole(serverId, username, newRole) {
    try {
        const resp = await fetch('/api/servers/members/role', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_id: serverId, username, role: newRole })
        });
        const res = await resp.json();
        if (!resp.ok) {
            alert(res.message || "Failed to update role.");
            loadServerMembers(serverId);
        } else {
            loadServerMembers(serverId);
        }
    } catch (e) {
        console.error("Error updating role:", e);
    }
}

async function removeServerMember(serverId, username, isSelf) {
    const actionText = isSelf ? "leave this server" : `remove ${username} from this server`;
    if (!confirm(`Are you sure you want to ${actionText}?`)) return;

    try {
        const resp = await fetch(`/api/servers/members/remove?server_id=${serverId}&username=${username}`, {
            method: 'DELETE'
        });
        const res = await resp.json();
        if (resp.ok) {
            if (isSelf) {
                closeTeamModal();
                if (typeof fetchDashboardData === 'function') fetchDashboardData();
            } else {
                loadServerMembers(serverId);
            }
        } else {
            alert(res.message || "Failed to remove member.");
        }
    } catch (e) {
        console.error("Error removing member:", e);
    }
}

// Scoped Alerts and Team helper functions
function openTeamModalFromDetail() {
    const sid = currentActiveServer;
    let hostname = serversMap[sid] ? serversMap[sid].hostname : '';
    if (!hostname) {
        const titleEl = document.getElementById('modal-server-title');
        if (titleEl) {
            const text = titleEl.textContent || '';
            hostname = text.split('(')[0].replace(/[<>\/]/g, '').trim();
        }
    }
    if (sid && hostname) {
        openTeamModal(sid, hostname);
    }
}

function onAlertTargetTypeChange(typeSelect, prefix = 'create-') {
    const type = typeSelect.value;
    const valueGroup = document.getElementById(prefix + 'alert-target-value-group');
    const metricSelect = document.getElementById(prefix + 'alert-metric');
    
    if (valueGroup) {
        valueGroup.style.display = type === 'server' ? 'none' : 'block';
    }
    
    if (metricSelect) {
        metricSelect.innerHTML = '';
        if (type === 'server') {
            metricSelect.innerHTML = `
                <option value="cpu">CPU Usage (%)</option>
                <option value="ram">RAM Usage (%)</option>
                <option value="disk">Disk Usage (%)</option>
                <option value="custom">Custom Metric Key...</option>
            `;
        } else {
            metricSelect.innerHTML = `
                <option value="process_down">Is Not Running (Offline)</option>
                <option value="cpu">CPU Usage (%)</option>
                <option value="ram">Memory Usage (MB)</option>
            `;
        }
    }
    
    onAlertMetricChange(metricSelect, prefix);
}

function getRuleDescription(rule) {
    const scope = rule.target_type || 'server';
    const target = rule.target_value || '';
    const metric = rule.metric_type;
    
    if (scope === 'process' || scope === 'application') {
        const typeLabel = scope === 'process' ? 'Process' : 'App';
        if (metric === 'process_down') {
            return `<strong>${typeLabel} Offline:</strong> ${target}`;
        }
        const unit = metric === 'ram' ? 'MB' : '%';
        const metricName = metric.toUpperCase();
        return `<strong>${typeLabel} ${target}:</strong> ${metricName} ${rule.operator} ${rule.threshold}${unit}`;
    }
    
    // Server scope
    const isCustom = !['cpu', 'ram', 'disk'].includes(metric);
    const metricLabel = isCustom ? metric : metric.toUpperCase();
    return `<strong>Server ${metricLabel}</strong> ${rule.operator} ${rule.threshold}%`;
}

function navigateToAddAlert(type, value) {
    switchTab('alerts-tab');
    
    const typeSelect = document.getElementById('alert-target-type');
    if (typeSelect) {
        typeSelect.value = type;
        onAlertTargetTypeChange(typeSelect, 'create-');
    }
    
    const valInput = document.getElementById('alert-target-value');
    if (valInput) {
        valInput.value = value;
    }
}

// Bind to window
window.openTeamModal = openTeamModal;
window.closeTeamModal = closeTeamModal;
window.handleTeamInvite = handleTeamInvite;
window.updateMemberRole = updateMemberRole;
window.removeServerMember = removeServerMember;
window.openTeamModalFromDetail = openTeamModalFromDetail;
window.onAlertTargetTypeChange = onAlertTargetTypeChange;
window.getRuleDescription = getRuleDescription;
window.navigateToAddAlert = navigateToAddAlert;
window.filterApplications = filterApplications;

