// Main Application Controller for Fleet Monitor
let isFetchingDashboard = false;

document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    const sidebar = document.getElementById('sidebar');
    const toggleSidebarBtn = document.getElementById('toggle-sidebar-btn');
    const toggleIcon = document.getElementById('toggle-icon');
    const modalOverlay = document.getElementById('modal-overlay');
    const modalCloseBtn = document.getElementById('modal-close-btn');

    if (toggleSidebarBtn && sidebar && toggleIcon) {
        toggleSidebarBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            if (sidebar.classList.contains('collapsed')) {
                toggleIcon.classList.replace('fa-chevron-left', 'fa-chevron-right');
            } else {
                toggleIcon.classList.replace('fa-chevron-right', 'fa-chevron-left');
            }
        });
    }

    if (modalCloseBtn) {
        modalCloseBtn.addEventListener('click', () => {
            closeDetailsModal();
        });
    }

    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) {
                closeDetailsModal();
            }
        });
    }

    const procSearch = document.getElementById('proc-search');
    if (procSearch) {
        procSearch.addEventListener('input', filterProcesses);
    }

    const appSearch = document.getElementById('app-search');
    if (appSearch) {
        appSearch.addEventListener('input', filterApplications);
    }

    const createAlertForm = document.getElementById('create-alert-form');
    if (createAlertForm) {
        createAlertForm.addEventListener('submit', (e) => {
            e.preventDefault();
            if (!currentActiveServer) return;

            const targetType = document.getElementById('alert-target-type').value;
            const targetValue = document.getElementById('alert-target-value').value.trim();

            let metric = document.getElementById('alert-metric').value;
            if (metric === 'custom') {
                metric = document.getElementById('alert-metric-custom').value.trim();
                if (!metric) {
                    showToast('Validation Error', 'Custom metric key is required.', 'warning', 4000);
                    return;
                }
            }
            const operator = document.getElementById('alert-operator').value;
            const threshold = parseFloat(document.getElementById('alert-threshold').value);
            const duration = parseInt(document.getElementById('alert-duration').value);
            const recipientType = document.getElementById('alert-recipient-type').value;
            let email = document.getElementById('alert-email').value || '';
            if (recipientType === 'self') email = window.currentUserEmail || '';
            if (recipientType === 'all') email = '';
            if (recipientType === 'specific' && !email.trim()) {
                showToast('Validation Error', 'Please select at least one user to notify.', 'warning', 4000);
                return;
            }

            registerAlertRule(currentActiveServer, metric, operator, threshold, duration, email, targetType, targetValue, recipientType);
        });
    }

    const unregisterServerBtn = document.getElementById('unregister-server-btn');
    if (unregisterServerBtn) {
        unregisterServerBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (typeof unregisterCurrentServer === 'function') {
                unregisterCurrentServer();
            }
        });
    }

    // Initial Dashboard Load & Sub-Second SSE Stream
    fetchUserProfile();
    fetchDashboardData();
    initLiveStream();
    setInterval(fetchDashboardData, 5000);
}

function initLiveStream() {
    if (typeof EventSource !== 'undefined') {
        const sse = new EventSource('/api/stream/metrics');
        sse.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (typeof fetchDashboardData === 'function') {
                    fetchDashboardData();
                }
            } catch (e) {
                console.error("Stream error:", e);
            }
        };
    }
}

async function fetchUserProfile() {
    try {
        const resp = await fetch('/api/auth/user');
        if (!resp.ok) {
            if (resp.status === 401) {
                window.location.href = '/static/login.html';
            }
            return;
        }
        const user = await resp.json();
        window.currentUserUsername = user.username;
        window.currentUserEmail = user.email;
        
        try {
            localStorage.setItem('rememberedUser', JSON.stringify({
                username: user.username,
                email: user.email
            }));
        } catch(e) {
            console.error("Failed to write rememberedUser", e);
        }
        
        // Populate sidebar footer
        const profileName = document.getElementById('user-profile-name');
        const profileEmail = document.getElementById('user-profile-email');
        if (profileName) profileName.textContent = user.username;
        if (profileEmail) profileEmail.textContent = user.email;

        // Populate alert email display
        const alertDisplay = document.getElementById('alert-email-display');
        const editAlertDisplay = document.getElementById('edit-alert-email-display');
        if (alertDisplay) alertDisplay.value = user.email;
        if (editAlertDisplay) editAlertDisplay.value = user.email;
        // Set initial recipient type to 'self'
        const rtSelect = document.getElementById('alert-recipient-type');
        if (rtSelect) onAlertRecipientTypeChange(rtSelect, 'create-');
    } catch (err) {
        console.error("Failed to fetch user profile:", err);
    }
}

// Fetch and render servers dashboard cards in parallel
async function fetchDashboardData() {
    if (isFetchingDashboard) return;
    isFetchingDashboard = true;

    try {
        const serversResp = await fetch('/api/servers');
        if (!serversResp.ok) return;
        const servers = await serversResp.json();
        
        serversMap = {};
        servers.forEach(s => { serversMap[s.id] = s; });
        
        const rulesResp = await fetch('/api/alerts/rules').catch(() => null);
        const rules = rulesResp && rulesResp.ok ? await rulesResp.json() : [];

        const statTotalServers = document.getElementById('stat-total-servers');
        const statOnlineServers = document.getElementById('stat-online-servers');
        const statActiveAlerts = document.getElementById('stat-active-alerts');

        if (statTotalServers) statTotalServers.innerText = servers.length;
        if (statOnlineServers) statOnlineServers.innerText = servers.filter(s => s.status === 'online').length;
        if (statActiveAlerts) statActiveAlerts.innerText = rules.filter(r => r.is_active).length;

        // SIDEBAR: SHOW ALL REGISTERED SERVERS (BOTH ONLINE AND OFFLINE)
        const sidebarServersList = document.getElementById('sidebar-servers-list');
        if (sidebarServersList) {
            sidebarServersList.innerHTML = '';
            servers.forEach(server => {
                const el = document.createElement('a');
                el.className = 'server-list-item';
                el.href = '#';
                el.title = server.hostname;
                el.onclick = (e) => { e.preventDefault(); openServerDetails(server.id); };
                
                const dotClass = server.status === 'online' ? 'online' : 'offline';
                el.innerHTML = `
                    <div class="server-status-dot ${dotClass}"></div>
                    <span>${server.hostname}</span>
                `;
                sidebarServersList.appendChild(el);
            });
        }

        const activeServersGrid = document.getElementById('active-servers-grid');
        if (!activeServersGrid) return;

        // Clean up cards for servers no longer in database
        const existingCards = activeServersGrid.querySelectorAll('.active-card');
        existingCards.forEach(c => {
            const id = c.id.replace('server-card-', '');
            if (!servers.some(s => s.id === id)) {
                c.remove();
            }
        });

function renderDashboardCardMetrics(serverId, metrics) {
    const card = document.getElementById(`server-card-${serverId}`);
    if (!card || !metrics) return;

    const rawCpu = metrics.cpu || 0;
    const rawRamPct = metrics.ram_used_pct || 0;
    const rawStoragePct = metrics.disk_used_pct || 0;

    const cpuVal = rawCpu.toFixed(1);
    const ramPct = rawRamPct.toFixed(1);
    const currentRam = (metrics.ram_used_gb || 0).toFixed(1);
    const totalRam = (metrics.ram_total_gb || 0).toFixed(1);
    const storagePct = rawStoragePct.toFixed(1);
    const currentStorage = (metrics.disk_used_gb || 0).toFixed(1);
    const totalStorage = (metrics.disk_total_gb || 0).toFixed(1);

    if (typeof serverHistoryMap !== 'undefined') {
        if (!serverHistoryMap[serverId]) {
            serverHistoryMap[serverId] = Array.from({length: 15}, () => 0);
        }
        serverHistoryMap[serverId].push(rawCpu);
        if (serverHistoryMap[serverId].length > 20) {
            serverHistoryMap[serverId].shift();
        }

        const points = serverHistoryMap[serverId];
        const maxVal = 100, height = 50, width = 360;
        const pathData = points.map((val, index) => {
            const x = (index / (points.length - 1)) * width;
            const y = height - (val / maxVal) * height + 5;
            return `${x},${y}`;
        }).join(' ');
        const fillPathData = `0,60 ${pathData} ${width},60`;

        const strokeColor = rawCpu > 80 ? 'var(--danger)' : (rawCpu > 60 ? 'var(--warning)' : 'var(--primary)');
        const strokeGlow = rawCpu > 80 ? 'rgba(239, 68, 68, 0.2)' : (rawCpu > 60 ? 'rgba(245, 158, 11, 0.2)' : 'var(--primary-glow)');

        const cpuOffset = 188.4 - (rawCpu / 100) * 188.4;
        const ramOffset = 188.4 - (rawRamPct / 100) * 188.4;
        const storageOffset = 188.4 - (rawStoragePct / 100) * 188.4;

        const sparkHeader = `<span style="color: ${strokeColor}; font-weight:700;"><i class="fa-solid fa-wave-square"></i> Live</span>`;

        const titleBadge = card.querySelector('.active-os-badge');
        if (titleBadge) {
            titleBadge.className = 'active-os-badge online';
            titleBadge.style.backgroundColor = 'var(--primary-glow)';
            titleBadge.style.color = 'var(--primary)';
            titleBadge.innerHTML = '<i class="fa-solid fa-circle" style="font-size:7px; margin-right:4px;"></i> Online';
        }

        const cpuFill = card.querySelector('.card-cpu-fill');
        const cpuValEl = card.querySelector('.card-cpu-val');
        const cpuDetEl = card.querySelector('.card-cpu-det');
        if (cpuFill) { cpuFill.style.strokeDashoffset = cpuOffset; cpuFill.style.stroke = strokeColor; }
        if (cpuValEl) { cpuValEl.innerText = cpuVal + '%'; cpuValEl.style.color = strokeColor; }
        if (cpuDetEl) { cpuDetEl.innerText = 'Active load'; }

        const ramFill = card.querySelector('.card-ram-fill');
        const ramValEl = card.querySelector('.card-ram-val');
        const ramDetEl = card.querySelector('.card-ram-det');
        if (ramFill) { ramFill.style.strokeDashoffset = ramOffset; }
        if (ramValEl) { ramValEl.innerText = ramPct + '%'; }
        if (ramDetEl) { ramDetEl.innerHTML = `${currentRam} GB<br>of ${totalRam} GB`; }

        const diskFill = card.querySelector('.card-disk-fill');
        const diskValEl = card.querySelector('.card-disk-val');
        const diskDetEl = card.querySelector('.card-disk-det');
        if (diskFill) { diskFill.style.strokeDashoffset = storageOffset; }
        if (diskValEl) { diskValEl.innerText = storagePct + '%'; }
        if (diskDetEl) { diskDetEl.innerHTML = `${currentStorage} GB<br>of ${totalStorage} GB`; }

        const polyline = card.querySelector('.sparkline-path');
        const fillPath = card.querySelector('.sparkline-fill');
        const sparkHeaderEl = card.querySelector('.card-spark-header');
        if (sparkHeaderEl) sparkHeaderEl.innerHTML = sparkHeader;
        if (polyline) {
            polyline.setAttribute('points', pathData);
            polyline.style.stroke = strokeColor;
            polyline.style.filter = `drop-shadow(0 2px 4px ${strokeGlow})`;
        }
        if (fillPath) {
            fillPath.setAttribute('d', `M ${fillPathData} Z`);
        }
    }
}

        // Synchronously create placeholder cards for ONLINE servers only (prevents flickering offline cards!)
        servers.forEach(server => {
            if (server.status !== 'online') {
                const card = document.getElementById(`server-card-${server.id}`);
                if (card) card.remove();
                return;
            }

            let card = document.getElementById(`server-card-${server.id}`);
            if (!card) {
                card = document.createElement('div');
                card.id = `server-card-${server.id}`;
                card.className = 'active-card';
                card.onclick = () => openServerDetails(server.id);
                card.innerHTML = `
                    <div class="active-card-header" style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
                        <div class="active-card-title" style="flex: 1; min-width: 0;">
                            <h3 style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"><div class="server-status-dot online"></div> ${server.hostname}</h3>
                            <p>${server.ip_address} &bull; ${server.os_family.toUpperCase()}</p>
                        </div>
                        <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0;">
                            <span class="active-os-badge online" style="background-color: var(--primary-glow); color: var(--primary); font-weight:600; font-size: 11px; padding: 4px 8px; border-radius: 4px;"><i class="fa-solid fa-circle" style="font-size:7px; margin-right:4px;"></i> Online</span>
                            <div style="display: flex; gap: 5px; align-items: center; margin-top: 2px;">
                                <span style="font-size: 10px; font-weight: 700; color: var(--text-secondary); background: rgba(255,255,255,0.06); padding: 3px 6px; border-radius: 4px; text-transform: uppercase; border: 1px solid var(--border-color);">${server.role || 'viewer'}</span>
                                <button onclick="event.stopPropagation(); openTeamModal('${server.id}', '${server.hostname}')" style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); color: var(--primary); font-size: 10px; font-weight: 700; padding: 3px 6px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 3px; transition: all 0.2s;" onmouseover="this.style.background='rgba(56, 189, 248, 0.15)'" onmouseout="this.style.background='rgba(56, 189, 248, 0.08)'"><i class="fa-solid fa-users"></i> Team</button>
                            </div>
                        </div>
                    </div>

                    <div class="sparkline-container">
                        <div class="sparkline-header">
                            <span>CPU Utilization History</span>
                            <span class="card-spark-header"><span style="color: var(--primary); font-weight:700;"><i class="fa-solid fa-wave-square"></i> Live</span></span>
                        </div>
                        <svg class="sparkline-svg" viewBox="0 0 360 60" preserveAspectRatio="none">
                            <path class="sparkline-fill" d="M 0,60 0,60 360,60 360,60 Z"></path>
                            <polyline class="sparkline-path" points="0,60 360,60" style="stroke: var(--primary); filter: drop-shadow(0 2px 4px var(--primary-glow));"></polyline>
                        </svg>
                    </div>

                    <div class="radial-gauges-row">
                        <div class="radial-gauge-container">
                            <div class="radial-gauge-title">CPU</div>
                            <div class="radial-gauge">
                                <svg class="radial-svg" width="70" height="70">
                                    <circle class="radial-bg" cx="35" cy="35" r="30"></circle>
                                    <circle class="radial-fill card-cpu-fill" cx="35" cy="35" r="30" style="stroke-dashoffset: 188.4; stroke: var(--primary);"></circle>
                                </svg>
                                <div class="radial-value card-cpu-val" style="color: var(--primary);">0.0%</div>
                            </div>
                            <div class="radial-details card-cpu-det">Active load</div>
                        </div>

                        <div class="radial-gauge-container">
                            <div class="radial-gauge-title">Memory</div>
                            <div class="radial-gauge">
                                <svg class="radial-svg" width="70" height="70">
                                    <circle class="radial-bg" cx="35" cy="35" r="30"></circle>
                                    <circle class="radial-fill card-ram-fill" cx="35" cy="35" r="30" style="stroke-dashoffset: 188.4;"></circle>
                                </svg>
                                <div class="radial-value card-ram-val">0.0%</div>
                            </div>
                            <div class="radial-details card-ram-det">Loading...</div>
                        </div>

                        <div class="radial-gauge-container">
                            <div class="radial-gauge-title">Storage</div>
                            <div class="radial-gauge">
                                <svg class="radial-svg" width="70" height="70">
                                    <circle class="radial-bg" cx="35" cy="35" r="30"></circle>
                                    <circle class="radial-fill card-disk-fill" cx="35" cy="35" r="30" style="stroke-dashoffset: 188.4;"></circle>
                                </svg>
                                <div class="radial-value card-disk-val">0.0%</div>
                            </div>
                            <div class="radial-details card-disk-det">Loading...</div>
                        </div>
                    </div>

                    <div class="services-pills" id="monitored-pills-${server.id}">
                        <span style="opacity:0.45; font-size:12px;">Loading monitored items...</span>
                    </div>
                `;
                activeServersGrid.appendChild(card);
            }

            if (typeof latestMetricsMap !== 'undefined' && latestMetricsMap[server.id]) {
                renderDashboardCardMetrics(server.id, latestMetricsMap[server.id]);
            }
        });

        // Parallel processing of card metrics for online servers with 4-second timeout per server
        await Promise.all(servers.filter(s => s.status === 'online').map(async (server) => {
            const card = document.getElementById(`server-card-${server.id}`);
            if (!card) return;

            let metricsAvailable = false;
            let metrics = null;

            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 4000);
                const mResp = await fetch(`/api/servers/detail/${server.id}/metrics`, { signal: controller.signal });
                clearTimeout(timeoutId);

                if (mResp.ok) {
                    metrics = await mResp.json();
                    if (typeof latestMetricsMap !== 'undefined') {
                        latestMetricsMap[server.id] = metrics;
                    }
                    metricsAvailable = true;

                    renderDashboardCardMetrics(server.id, metrics);

                    if (typeof currentActiveServer !== 'undefined' && currentActiveServer === server.id && typeof renderOverviewMetrics === 'function') {
                        renderOverviewMetrics(server, metrics);
                    }
                }
            } catch (e) {
                // Network timeout for offline nodes
            }

            if (!metricsAvailable && typeof latestMetricsMap !== 'undefined' && latestMetricsMap[server.id]) {
                renderDashboardCardMetrics(server.id, latestMetricsMap[server.id]);
            }

            loadCardMonitored(server.id);
        }));
    } catch (err) {
        console.error("Error updating dashboard data:", err);
    } finally {
        isFetchingDashboard = false;
    }
}
