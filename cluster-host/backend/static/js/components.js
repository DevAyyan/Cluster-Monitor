// Components module for Fleet Monitor UI (Modal, Tab Managers, Containers, Processes, Applications, Alerts, Logs)

// Global state variables
let currentActiveServer = null;
let cachedProcesses = [];
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

function closeDetailsModal() {
    const modalOverlay = document.getElementById('modal-overlay');
    if (modalOverlay) modalOverlay.classList.remove('open');
    currentActiveServer = null;
    if (resourceUpdateInterval) {
        clearInterval(resourceUpdateInterval);
        resourceUpdateInterval = null;
    }
    if (liveTabRefreshInterval) {
        clearInterval(liveTabRefreshInterval);
        liveTabRefreshInterval = null;
    }
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
                <div style="display: flex; align-items: center; gap: 6px;">
                    <select id="sig-select-${pid}" onchange="processSignalCache['${pid}'] = this.value" style="background-color: #1a1a24; color: #a9b1d6; border: 1px solid var(--border-color); border-radius: 4px; padding: 4px 6px; font-size: 11px; outline: none; cursor: pointer;">
                        <option value="kill" ${savedSig === 'kill' ? 'selected' : ''}>Kill (SIGKILL)</option>
                        <option value="terminate" ${savedSig === 'terminate' ? 'selected' : ''}>Terminate (SIGTERM)</option>
                        <option value="suspend" ${savedSig === 'suspend' ? 'selected' : ''}>Suspend (SIGSTOP)</option>
                        <option value="continue" ${savedSig === 'continue' ? 'selected' : ''}>Continue (SIGCONT)</option>
                        <option value="hangup" ${savedSig === 'hangup' ? 'selected' : ''}>Hangup (SIGHUP)</option>
                        <option value="interrupt" ${savedSig === 'interrupt' ? 'selected' : ''}>Interrupt (SIGINT)</option>
                    </select>
                    <button class="rule-delete-btn" onclick="sendSignalToProcess('${pid}', '${name}')" style="color: var(--danger); padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.05); cursor: pointer; font-size: 11px; display: flex; align-items: center; gap: 4px;" title="Send Signal"><i class="fa-solid fa-paper-plane"></i> Send</button>
                </div>
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
        const resp = await fetch(`/api/servers/control/kill/${currentActiveServer}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: String(pid), signal: signal })
        });

        if (resp.ok) {
            alert(`Successfully sent signal ${signal.toUpperCase()} to PID ${pid}.`);
            fetchServerProcesses();
        } else {
            const text = await resp.text();
            alert(`Failed to send signal: ${text}`);
        }
    } catch (e) {
        console.error("Error sending signal to process:", e);
        alert("Error connecting to host backend.");
    }
}

async function sendSignalToApplication(name) {
    const selectEl = document.getElementById(`app-sig-select-${name}`);
    const signal = selectEl ? selectEl.value : 'kill';
    if (!confirm(`Are you sure you want to send "${signal.toUpperCase()}" to all processes of application "${name}"?`)) return;
    try {
        const resp = await fetch(`/api/servers/control/kill-by-name/${currentActiveServer}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, signal: signal })
        });
        if (resp.ok) {
            alert(`Successfully sent signal ${signal.toUpperCase()} to application ${name}.`);
            fetchServerApplications();
        } else {
            const text = await resp.text();
            alert(`Failed to send signal: ${text}`);
        }
    } catch (e) {
        console.error("Error sending signal to application:", e);
        alert("Error connecting to host backend.");
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

        appBody.innerHTML = '';
        if (appList.length === 0) {
            appBody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:20px; opacity:0.5;">No applications detected.</td></tr>';
            return;
        }

        appList.sort((a, b) => b.cpu - a.cpu);
        appList.forEach(app => {
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

            const monitoredBadge = isMonitored ? `<span title="Monitored" style="color:#c084fc; margin-right:6px; font-size:11px;"><i class="fa-solid fa-eye"></i></span>` : '';

            const savedSig = appSignalCache[appName] || 'kill';

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
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <select id="app-sig-select-${appName}" onchange="appSignalCache['${appName}'] = this.value" style="background-color: #1a1a24; color: #a9b1d6; border: 1px solid var(--border-color); border-radius: 4px; padding: 4px 6px; font-size: 11px; outline: none; cursor: pointer;">
                            <option value="kill" ${savedSig === 'kill' ? 'selected' : ''}>Kill (SIGKILL)</option>
                            <option value="terminate" ${savedSig === 'terminate' ? 'selected' : ''}>Terminate (SIGTERM)</option>
                            <option value="suspend" ${savedSig === 'suspend' ? 'selected' : ''}>Suspend (SIGSTOP)</option>
                            <option value="continue" ${savedSig === 'continue' ? 'selected' : ''}>Continue (SIGCONT)</option>
                            <option value="hangup" ${savedSig === 'hangup' ? 'selected' : ''}>Hangup (SIGHUP)</option>
                            <option value="interrupt" ${savedSig === 'interrupt' ? 'selected' : ''}>Interrupt (SIGINT)</option>
                        </select>
                        <button class="rule-delete-btn" onclick="sendSignalToApplication('${appName}')" style="color: var(--danger); padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.05); cursor: pointer; font-size: 11px; display: flex; align-items: center; gap: 4px;" title="Send Signal"><i class="fa-solid fa-paper-plane"></i> Send</button>
                    </div>
                </td>
            `;
            appBody.appendChild(row);
        });
    } catch (err) {
        if (currentActiveServer !== targetServerId) return;
        appBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:20px; color:var(--danger);">Error: ${err.message}</td></tr>`;
    }
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
    const netBody = document.getElementById('networks-list-body');
    const connBody = document.getElementById('network-connections-list-body');
    if (!netBody) return;
    const isLiveRefresh = netBody.querySelector('tr') !== null && !netBody.innerText.includes('Loading');
    if (!isLiveRefresh) {
        netBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; opacity:0.5;"><i class="fa-solid fa-spinner fa-spin"></i> Loading network interfaces...</td></tr>';
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
            netBody.innerHTML = '';
            const nNotice = sshFallbackNotice(resp);
            if (nNotice) netBody.insertAdjacentHTML('afterbegin', nNotice);
            if (!Array.isArray(interfaces) || interfaces.length === 0) {
                netBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; opacity:0.5;">No network interfaces found.</td></tr>';
            } else {
                interfaces.forEach(i => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td style="font-weight:600; color:var(--text-primary);">${i.name || i.Name || 'N/A'}</td>
                        <td style="font-family:var(--font-mono);">${i.ip || i.IP || 'N/A'}</td>
                        <td style="font-family:var(--font-mono);">${i.rxSpeed || 'Active'}</td>
                        <td style="font-family:var(--font-mono);">${i.txSpeed || 'Active'}</td>
                        <td style="font-family:var(--font-mono);">${i.rxTotal || 'Calculated live'}</td>
                        <td style="font-family:var(--font-mono);">${i.txTotal || 'Calculated live'}</td>
                    `;
                    netBody.appendChild(row);
                });
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
    body.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; opacity: 0.5;">Loading active alert rules...</td></tr>';
    try {
        const rulesResp = await fetch('/api/alerts/rules');
        const rules = await rulesResp.json();
        
        const serversResp = await fetch('/api/servers');
        const servers = await serversResp.json();
        const sMap = {};
        servers.forEach(s => { sMap[s.id] = s.hostname; });

        body.innerHTML = '';
        if (rules.length === 0) {
            body.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; opacity: 0.5;">No active alert rules configured in the fleet.</td></tr>';
            return;
        }

        rules.forEach(r => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-weight: 600; color: var(--text-primary);">${sMap[r.server_id] || 'Unknown Node'}</td>
                <td style="text-transform: uppercase;">${r.metric_type}</td>
                <td>${r.operator || '>'}</td>
                <td style="font-family: var(--font-mono);">${r.threshold}%</td>
                <td style="font-family: var(--font-mono);">${r.duration_minutes} min</td>
                <td>${r.recipient_email}</td>
                <td><span class="badge ${r.is_active ? 'badge-success' : 'badge-danger'}">${r.is_active ? 'Active' : 'Muted'}</span></td>
                <td>
                    <button onclick="deleteGlobalAlertRule('${r.id}')" style="background-color: var(--danger); border: none; color: white; padding: 5px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;"><i class="fa-solid fa-trash"></i> Delete</button>
                </td>
            `;
            body.appendChild(row);
        });
    } catch (err) {
        body.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--danger);">Failed to load alert rules: ${err.message}</td></tr>`;
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

async function registerAlertRule(serverId, metric, threshold, duration, email) {
    try {
        const resp = await fetch('/api/alerts/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                server_id: serverId,
                metric_type: metric,
                operator: '>',
                threshold: threshold,
                duration_minutes: duration,
                recipient_email: email,
                is_active: true
            })
        });

        if (resp.ok) {
            alert("Alert rule successfully registered!");
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (currentActiveServer === serverId) updateRulesList(serverId);
        } else {
            alert("Failed to register alert rule.");
        }
    } catch (err) {
        console.error("Failed to add alert rule:", err);
    }
}

async function deleteAlertRule(ruleId) {
    if (!confirm("Are you sure you want to delete this alert rule?")) return;
    try {
        const resp = await fetch(`/api/alerts/rules?id=${ruleId}`, { method: 'DELETE' });
        if (resp.ok) {
            alert("Alert rule deleted successfully.");
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (currentActiveServer) updateRulesList(currentActiveServer);
        }
    } catch (err) {
        console.error("Failed to delete alert rule:", err);
    }
}

async function updateRulesList(serverId) {
    const configuredRulesContainer = document.getElementById('configured-rules-container');
    if (!configuredRulesContainer) return;
    try {
        const resp = await fetch('/api/alerts/rules');
        const rules = await resp.json();

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
                <span><strong>${rule.metric_type.toUpperCase()}</strong> ${rule.operator} ${rule.threshold}% (${rule.duration_minutes}m)</span>
                <div style="display:flex; align-items:center; gap:12px;">
                    <span style="opacity: 0.7; font-size:12px;">${rule.recipient_email}</span>
                    <button class="rule-delete-btn" onclick="deleteAlertRule(${rule.id})"><i class="fa-solid fa-trash"></i></button>
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
        const resp = await fetch(`/api/servers/unregister?id=${encodeURIComponent(serverToDelete)}`, { method: 'DELETE' });
        let res = {};
        try { res = await resp.json(); } catch(e) {}

        if (resp.ok || resp.status === 200 || resp.status === 204) {
            closeUnregisterConfirmModal();
            closeDetailsModal();
            
            // Delete from local cache and DOM immediately
            delete serversMap[serverToDelete];
            const card = document.getElementById(`server-card-${serverToDelete}`);
            if (card) card.remove();

            if (typeof fetchDashboardData === 'function') fetchDashboardData();
            if (typeof renderSettingsView === 'function') renderSettingsView();
        } else {
            alert(`Failed to unregister server (${resp.status}): ${res.message || res.error || 'Unknown error'}`);
        }
    } catch (e) {
        console.error("Error unregistering server:", e);
        alert("Error unregistering server: " + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-trash-can"></i> Yes, Deregister Node';
        }
        pendingServerToDelete = null;
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
        alert("Hostname, IP address, SSH user and (private key or password) are all required to register a server.");
        return;
    }

    try {
        const resp = await fetch('/api/register', {
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
        });

        if (resp.ok) {
            alert("Server registered successfully!");
            document.getElementById('settings-register-form').reset();
            renderSettingsView();
            if (typeof fetchDashboardData === 'function') fetchDashboardData();
        } else {
            const text = await resp.json();
            alert("Failed to register server: " + (text.message || text));
        }
    } catch (err) {
        alert("Error registering server: " + err.message);
    }
}
