/**
 * PBL4 Network IDS — Minimal Enterprise SOC Frontend Engine
 * Handles telemetry streaming, forensic analysis, chart visualization, and view routing.
 */

document.addEventListener("DOMContentLoaded", () => {
    // State variables
    let isRunning = false;
    let pollInterval = null;
    let activeView = "view-overview";
    let alertCache = [];

    // DOM Elements - Status & Controls
    const statusDot = document.getElementById("statusDot");
    const statusText = document.getElementById("statusText");
    const interfaceSelect = document.getElementById("interfaceSelect");
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");
    const btnReset = document.getElementById("btnReset");
    const currentViewTitle = document.getElementById("currentViewTitle");

    // DOM Elements - Metrics
    const valTotalPackets = document.getElementById("valTotalPackets");
    const valThroughput = document.getElementById("valThroughput");
    const valThroughputSub = document.getElementById("valThroughputSub");
    const valTotalAlerts = document.getElementById("valTotalAlerts");
    const valSuppressedAlerts = document.getElementById("valSuppressedAlerts");
    const valUptime = document.getElementById("valUptime");
    const valActiveIface = document.getElementById("valActiveIface");
    const valQueuePercent = document.getElementById("valQueuePercent");
    const valQueuePercentSub = document.getElementById("valQueuePercentSub");
    const valDroppedPackets = document.getElementById("valDroppedPackets");
    const valQueueRaw = document.getElementById("valQueueRaw");
    const queueProgressBar = document.getElementById("queueProgressBar");
    const alertTabCount = document.getElementById("alertTabCount");

    // DOM Elements - Protocol Counters
    const protoCountTcp = document.getElementById("protoCountTcp");
    const protoCountUdp = document.getElementById("protoCountUdp");
    const protoCountIcmp = document.getElementById("protoCountIcmp");
    const protoCountOther = document.getElementById("protoCountOther");

    // DOM Elements - Tables
    const alertsTableBody = document.getElementById("alertsTableBody");
    const overviewRecentAlertsBody = document.getElementById("overviewRecentAlertsBody");
    const systemLogConsole = document.getElementById("systemLogConsole");
    const storageFilesBody = document.getElementById("storageFilesBody");
    const storageTotalMb = document.getElementById("storageTotalMb");
    const storageMaxMb = document.getElementById("storageMaxMb");
    const storageRetentionDays = document.getElementById("storageRetentionDays");
    const btnTriggerCleanup = document.getElementById("btnTriggerCleanup");

    // DOM Elements - Filters
    const filterSeverity = document.getElementById("filterSeverity");
    const filterSearch = document.getElementById("filterSearch");
    const filterLogLevel = document.getElementById("filterLogLevel");
    const btnRefreshAlerts = document.getElementById("btnRefreshAlerts");
    const btnRefreshLogs = document.getElementById("btnRefreshLogs");
    const btnClearAlerts = document.getElementById("btnClearAlerts");

    // DOM Elements - Simulation Buttons
    const btnSimScan = document.getElementById("btnSimScan");
    const btnSimSyn = document.getElementById("btnSimSyn");
    const btnSimIcmp = document.getElementById("btnSimIcmp");
    const btnSimUdp = document.getElementById("btnSimUdp");
    const btnSimNormal = document.getElementById("btnSimNormal");

    // DOM Elements - Slide-over Drawer
    const alertModal = document.getElementById("alertModal");
    const alertModalBackdrop = document.getElementById("alertModalBackdrop");
    const btnModalClose = document.getElementById("btnModalClose");
    const btnModalDismiss = document.getElementById("btnModalDismiss");
    const modalAlertId = document.getElementById("modalAlertId");
    const modalAlertTime = document.getElementById("modalAlertTime");
    const modalAlertIp = document.getElementById("modalAlertIp");
    const modalAlertDesc = document.getElementById("modalAlertDesc");
    const modalAlertEvidence = document.getElementById("modalAlertEvidence");

    // Traffic view details
    const trafficDetailTcp = document.getElementById("trafficDetailTcp");
    const trafficDetailUdp = document.getElementById("trafficDetailUdp");
    const trafficDetailIcmp = document.getElementById("trafficDetailIcmp");
    const trafficDetailOther = document.getElementById("trafficDetailOther");
    const trafficDetailIface = document.getElementById("trafficDetailIface");
    const trafficDetailQueue = document.getElementById("trafficDetailQueue");
    const trafficDetailDropped = document.getElementById("trafficDetailDropped");

    // =========================================================================
    // 1. Chart.js Initialization (Clean Minimalist Theme)
    // =========================================================================
    const ctxThroughput = document.getElementById("throughputChart").getContext("2d");
    const gradThroughput = ctxThroughput.createLinearGradient(0, 0, 0, 200);
    gradThroughput.addColorStop(0, "rgba(56, 139, 253, 0.20)");
    gradThroughput.addColorStop(1, "rgba(56, 139, 253, 0.0)");

    const throughputChart = new Chart(ctxThroughput, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Packets / sec",
                data: [],
                borderColor: "#388bfd",
                borderWidth: 1.8,
                backgroundColor: gradThroughput,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: "#388bfd",
                pointHoverBorderColor: "#ffffff"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#131922",
                    titleColor: "#919bb0",
                    bodyColor: "#e6edf3",
                    borderColor: "#334155",
                    borderWidth: 1,
                    padding: 8,
                    displayColors: false,
                    titleFont: { family: "Inter", size: 11 },
                    bodyFont: { family: "JetBrains Mono", size: 12, weight: 600 }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.04)" },
                    ticks: { color: "#5c6779", font: { family: "JetBrains Mono", size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(255, 255, 255, 0.04)" },
                    ticks: { color: "#5c6779", font: { family: "JetBrains Mono", size: 10 } }
                }
            }
        }
    });

    const ctxProtocol = document.getElementById("protocolChart").getContext("2d");
    const protocolChart = new Chart(ctxProtocol, {
        type: "doughnut",
        data: {
            labels: ["TCP", "UDP", "ICMP", "Khác"],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ["#388bfd", "#d29922", "#8957e5", "#5c6779"],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "78%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#131922",
                    titleColor: "#919bb0",
                    bodyColor: "#e6edf3",
                    borderColor: "#334155",
                    borderWidth: 1,
                    padding: 8
                }
            }
        }
    });

    // Expanded Chart on Traffic View
    let trafficExpandedChart = null;
    const canvasTraffic = document.getElementById("trafficExpandedChart");
    if (canvasTraffic) {
        const ctxTraffic = canvasTraffic.getContext("2d");
        trafficExpandedChart = new Chart(ctxTraffic, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Throughput (pps)",
                    data: [],
                    borderColor: "#2ea085",
                    borderWidth: 2,
                    backgroundColor: "rgba(46, 160, 133, 0.12)",
                    fill: true,
                    tension: 0.3,
                    pointRadius: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#5c6779", font: { family: "JetBrains Mono", size: 10 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#5c6779", font: { family: "JetBrains Mono", size: 10 } }
                    }
                }
            }
        });
    }

    // =========================================================================
    // 2. Telemetry & Real-Time Polling
    // =========================================================================
    async function fetchStatus() {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) return;
            const data = await res.json();

            // Status Indicator
            const status = data.status || "STOPPED";
            isRunning = (status === "RUNNING");
            statusText.textContent = status;
            statusText.className = `status-indicator-text ${status.toLowerCase()}`;
            statusDot.className = `status-indicator-dot ${status.toLowerCase()}`;

            btnStart.disabled = isRunning || (status === "STARTING");
            btnStop.disabled = !isRunning;
            interfaceSelect.disabled = isRunning;

            // Core Numbers
            valTotalPackets.textContent = Number(data.stats.total).toLocaleString();
            valTotalAlerts.textContent = Number(data.alerts.total_emitted).toLocaleString();
            valSuppressedAlerts.textContent = `${data.alerts.total_suppressed} suppressed`;
            alertTabCount.textContent = data.alerts.total_emitted;

            // Uptime
            const sec = Math.floor(data.uptime_seconds || 0);
            const hrs = String(Math.floor(sec / 3600)).padStart(2, "0");
            const mins = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
            const secs = String(sec % 60).padStart(2, "0");
            valUptime.textContent = `${hrs}:${mins}:${secs}`;

            // Interface
            const ifaceLabel = data.interface.includes("Loopback") ? "Loopback" : "Physical NIC";
            valActiveIface.textContent = ifaceLabel;
            valActiveIface.title = data.interface;

            // Queue Health
            const qPercent = Math.min(100, Math.round((data.queue_size / data.queue_max) * 100));
            valQueuePercent.textContent = `${qPercent}%`;
            if (valQueuePercentSub) valQueuePercentSub.textContent = `${qPercent}%`;
            valQueueRaw.textContent = `${data.queue_size} / ${data.queue_max}`;
            valDroppedPackets.textContent = `${data.dropped_packets} drop`;
            if (queueProgressBar) {
                queueProgressBar.style.width = `${Math.max(qPercent, data.queue_size > 0 ? 3 : 0)}%`;
            }

            // Throughput PPS
            const history = data.throughput_history || [];
            if (history.length > 0) {
                const latestPps = history[history.length - 1].pps;
                valThroughput.textContent = `${latestPps.toFixed(1)} pps`;
                if (valThroughputSub) valThroughputSub.textContent = `${latestPps.toFixed(1)} pps`;

                // Update Overview Throughput Chart
                throughputChart.data.labels = history.map(h => h.time);
                throughputChart.data.datasets[0].data = history.map(h => h.pps);
                throughputChart.update("none");

                // Update Expanded Traffic Chart if present
                if (trafficExpandedChart) {
                    trafficExpandedChart.data.labels = history.map(h => h.time);
                    trafficExpandedChart.data.datasets[0].data = history.map(h => h.pps);
                    trafficExpandedChart.update("none");
                }
            }

            // Update Doughnut Protocol Chart
            protocolChart.data.datasets[0].data = [
                data.stats.tcp,
                data.stats.udp,
                data.stats.icmp,
                data.stats.other
            ];
            protocolChart.update("none");

            // Update Protocol Percentages
            const totalPkts = (data.stats.tcp + data.stats.udp + data.stats.icmp + data.stats.other) || 0;
            const pTcp = totalPkts > 0 ? Math.round((data.stats.tcp / totalPkts) * 100) : 0;
            const pUdp = totalPkts > 0 ? Math.round((data.stats.udp / totalPkts) * 100) : 0;
            const pIcmp = totalPkts > 0 ? Math.round((data.stats.icmp / totalPkts) * 100) : 0;
            const pOther = totalPkts > 0 ? Math.max(0, 100 - (pTcp + pUdp + pIcmp)) : 0;

            if (protoCountTcp) protoCountTcp.textContent = `${Number(data.stats.tcp).toLocaleString()} (${pTcp}%)`;
            if (protoCountUdp) protoCountUdp.textContent = `${Number(data.stats.udp).toLocaleString()} (${pUdp}%)`;
            if (protoCountIcmp) protoCountIcmp.textContent = `${Number(data.stats.icmp).toLocaleString()} (${pIcmp}%)`;
            if (protoCountOther) protoCountOther.textContent = `${Number(data.stats.other).toLocaleString()} (${pOther}%)`;

            // Traffic View Detailed Info
            if (trafficDetailTcp) trafficDetailTcp.textContent = `${Number(data.stats.tcp).toLocaleString()} pkts`;
            if (trafficDetailUdp) trafficDetailUdp.textContent = `${Number(data.stats.udp).toLocaleString()} pkts`;
            if (trafficDetailIcmp) trafficDetailIcmp.textContent = `${Number(data.stats.icmp).toLocaleString()} pkts`;
            if (trafficDetailOther) trafficDetailOther.textContent = `${Number(data.stats.other).toLocaleString()} pkts`;
            if (trafficDetailIface) trafficDetailIface.textContent = data.interface;
            if (trafficDetailQueue) trafficDetailQueue.textContent = `${data.queue_size} / ${data.queue_max} pkts (${qPercent}%)`;
            if (trafficDetailDropped) trafficDetailDropped.textContent = `${data.dropped_packets} drop`;

        } catch (err) {
            console.error("Lỗi khi tải telemetry:", err);
        }
    }

    // =========================================================================
    // 3. Interface Enumeration
    // =========================================================================
    async function loadInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            if (!res.ok) return;
            const data = await res.json();
            interfaceSelect.innerHTML = "";

            data.interfaces.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.id;
                opt.textContent = iface.name;
                if (iface.id === data.current) {
                    opt.selected = true;
                }
                interfaceSelect.appendChild(opt);
            });
        } catch (err) {
            interfaceSelect.innerHTML = `<option value="">Lỗi nạp card mạng</option>`;
        }
    }

    // =========================================================================
    // 4. Alerts Loading & Rendering
    // =========================================================================
    async function fetchAlerts() {
        try {
            const severity = filterSeverity ? filterSeverity.value : "ALL";
            const search = filterSearch ? encodeURIComponent(filterSearch.value.trim()) : "";
            const res = await fetch(`/api/alerts?severity=${severity}&search=${search}&limit=80`);
            if (!res.ok) return;
            const data = await res.json();
            alertCache = data.alerts || [];

            // 1. Render Full Alerts Table (View: view-alerts)
            if (alertsTableBody) {
                if (alertCache.length === 0) {
                    alertsTableBody.innerHTML = `<tr class="empty-state-row"><td colspan="8">Không tìm thấy cảnh báo xâm nhập phù hợp.</td></tr>`;
                } else {
                    alertsTableBody.innerHTML = alertCache.map((a, idx) => {
                        const timeStr = formatLocalTime(a.timestamp);
                        const threatBadge = formatThreatBadge(a.attack_type, a.severity);

                        return `
                            <tr onclick="inspectAlert(${idx})">
                                <td><code>${timeStr}</code></td>
                                <td><code style="color: var(--text-primary); font-weight: 600;">${a.alert_id}</code></td>
                                <td>${threatBadge}</td>
                                <td>${formatSeverityTag(a.severity)}</td>
                                <td><code>${a.src_ip}</code></td>
                                <td><code>${a.dst_ip}</code></td>
                                <td style="color: var(--text-primary);">${escapeHtml(a.description)}</td>
                                <td style="text-align: center;">
                                    <button class="btn-soc btn-outline" style="padding: 2px 8px; font-size: 0.72rem;" onclick="event.stopPropagation(); inspectAlert(${idx})">
                                        Xem
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join("");
                }
            }

            // 2. Render Recent Alerts on Overview Page (Top 5 only)
            if (overviewRecentAlertsBody) {
                if (alertCache.length === 0) {
                    overviewRecentAlertsBody.innerHTML = `<tr class="empty-state-row"><td colspan="6">Hệ thống an toàn. Chưa phát hiện hành vi xâm nhập nào.</td></tr>`;
                } else {
                    const top5 = alertCache.slice(0, 5);
                    overviewRecentAlertsBody.innerHTML = top5.map((a, idx) => {
                        const timeStr = formatLocalTime(a.timestamp);
                        const threatBadge = formatThreatBadge(a.attack_type, a.severity);

                        return `
                            <tr onclick="inspectAlert(${idx})">
                                <td><code>${timeStr}</code></td>
                                <td><code style="color: var(--text-primary);">${a.alert_id}</code></td>
                                <td>${threatBadge}</td>
                                <td>${formatSeverityTag(a.severity)}</td>
                                <td><code>${a.src_ip} &rarr; ${a.dst_ip}</code></td>
                                <td style="color: var(--text-secondary);">${escapeHtml(a.description)}</td>
                            </tr>
                        `;
                    }).join("");
                }
            }

        } catch (err) {
            console.error("Lỗi khi nạp cảnh báo:", err);
        }
    }

    function formatThreatBadge(attackType, severity) {
        let tagClass = "badge-threat";
        if (severity === "HIGH") tagClass += " badge-threat-high";
        else if (severity === "MEDIUM") tagClass += " badge-threat-medium";
        else tagClass += " badge-threat-low";

        return `<span class="${tagClass}">${attackType}</span>`;
    }

    function formatSeverityTag(sev) {
        if (sev === "HIGH") return `<span class="kpi-tag tag-critical">HIGH</span>`;
        if (sev === "MEDIUM") return `<span class="kpi-tag" style="color: #e3b341; border-color: rgba(210, 153, 34, 0.4);">MEDIUM</span>`;
        return `<span class="kpi-tag" style="color: #58a6ff; border-color: rgba(56, 139, 253, 0.4);">LOW</span>`;
    }

    function formatLocalTime(isoStr) {
        if (!isoStr) return "-";
        try {
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return isoStr.split("T")[1]?.slice(0, 8) || isoStr;
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        } catch {
            return isoStr.split("T")[1]?.slice(0, 8) || isoStr;
        }
    }

    function formatLocalDateTime(isoStr) {
        if (!isoStr) return "-";
        try {
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return isoStr;
            return d.toLocaleString([], { hour12: false });
        } catch {
            return isoStr;
        }
    }

    // Inspect Alert Drawer
    window.inspectAlert = function(idx) {
        const item = alertCache[idx];
        if (!item) return;

        modalAlertId.textContent = item.alert_id || "-";
        modalAlertTime.textContent = formatLocalDateTime(item.timestamp);
        modalAlertIp.textContent = `${item.src_ip} -> ${item.dst_ip}`;
        modalAlertDesc.textContent = item.description || "-";
        modalAlertEvidence.textContent = JSON.stringify(item.evidence || {}, null, 2);

        alertModal.classList.add("show");
        alertModalBackdrop.classList.add("show");
    };

    function closeInspectorDrawer() {
        alertModal.classList.remove("show");
        alertModalBackdrop.classList.remove("show");
    }

    if (btnModalClose) btnModalClose.onclick = closeInspectorDrawer;
    if (btnModalDismiss) btnModalDismiss.onclick = closeInspectorDrawer;
    if (alertModalBackdrop) alertModalBackdrop.onclick = closeInspectorDrawer;

    // =========================================================================
    // 5. System Logs Loading
    // =========================================================================
    async function fetchLogs() {
        try {
            const level = filterLogLevel ? filterLogLevel.value : "ALL";
            const res = await fetch(`/api/logs?level=${level}&limit=100`);
            if (!res.ok) return;
            const data = await res.json();
            const logs = data.logs || [];

            if (logs.length === 0) {
                systemLogConsole.innerHTML = `<div class="log-line text-muted">Chưa có bản ghi log nào.</div>`;
                return;
            }

            systemLogConsole.innerHTML = logs.map(l => {
                let colorClass = "log-info";
                if (l.includes("[ERROR]")) colorClass = "log-error";
                else if (l.includes("[WARNING]")) colorClass = "log-warning";
                return `<div class="log-line ${colorClass}">${escapeHtml(l)}</div>`;
            }).join("");

            systemLogConsole.scrollTop = systemLogConsole.scrollHeight;
        } catch (err) {
            console.error("Lỗi khi nạp log:", err);
        }
    }

    // =========================================================================
    // 6. Storage Stats & Cleanup
    // =========================================================================
    async function fetchStorage() {
        try {
            const res = await fetch("/api/storage");
            if (!res.ok) return;
            const data = await res.json();

            storageTotalMb.textContent = `${data.total_size_mb} MB`;
            storageMaxMb.textContent = `${data.max_total_mb} MB`;
            storageRetentionDays.textContent = `${data.retention_days} ngày`;

            const files = data.files || [];
            if (files.length === 0) {
                storageFilesBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">Thư mục log trống.</td></tr>`;
                return;
            }

            storageFilesBody.innerHTML = files.map(f => `
                <tr>
                    <td><code>${f.name}</code></td>
                    <td><strong>${f.size_kb} KB</strong></td>
                    <td>${f.modified.replace("T", " ").slice(0, 19)}</td>
                </tr>
            `).join("");

        } catch (err) {
            console.error("Lỗi khi nạp storage:", err);
        }
    }

    if (btnTriggerCleanup) {
        btnTriggerCleanup.onclick = async () => {
            try {
                const res = await fetch("/api/storage/cleanup", { method: "POST" });
                const data = await res.json();
                showToast(`Đã dọn dẹp ${data.cleanup_result.deleted_count} file log cũ.`, "info");
                fetchStorage();
            } catch (err) {
                showToast("Lỗi khi dọn dẹp log.", "error");
            }
        };
    }

    // =========================================================================
    // 7. Start / Stop / Reset Controls
    // =========================================================================
    if (btnStart) {
        btnStart.onclick = async () => {
            const iface = interfaceSelect.value;
            btnStart.disabled = true;
            try {
                const res = await fetch("/api/control/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ interface: iface })
                });
                const data = await res.json();
                showToast(data.message, data.success ? "success" : "error");
                fetchStatus();
            } catch (err) {
                showToast("Lỗi kết nối tới máy chủ Flask.", "error");
            }
        };
    }

    if (btnStop) {
        btnStop.onclick = async () => {
            btnStop.disabled = true;
            try {
                const res = await fetch("/api/control/stop", { method: "POST" });
                const data = await res.json();
                showToast(data.message, "info");
                fetchStatus();
            } catch (err) {
                showToast("Lỗi kết nối tới máy chủ Flask.", "error");
            }
        };
    }

    async function triggerReset(clearAlertsFile = true) {
        try {
            const res = await fetch("/api/control/reset", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ clear_alerts_file: clearAlertsFile })
            });
            const data = await res.json();
            if (data.success) {
                showToast("Đã reset toàn bộ bộ đếm và làm sạch bảng cảnh báo!", "success");
                alertCache = [];
                if (alertsTableBody) {
                    alertsTableBody.innerHTML = `<tr class="empty-state-row"><td colspan="8">Chưa phát hiện hành vi xâm nhập nào.</td></tr>`;
                }
                if (overviewRecentAlertsBody) {
                    overviewRecentAlertsBody.innerHTML = `<tr class="empty-state-row"><td colspan="6">Hệ thống an toàn. Chưa phát hiện hành vi xâm nhập nào.</td></tr>`;
                }
                throughputChart.data.labels = [];
                throughputChart.data.datasets[0].data = [];
                throughputChart.update("none");
                fetchStatus();
                fetchAlerts();
            } else {
                showToast(data.message || "Lỗi khi reset.", "error");
            }
        } catch (err) {
            showToast("Lỗi kết nối tới máy chủ Flask.", "error");
        }
    }

    if (btnReset) btnReset.onclick = () => triggerReset(true);
    if (btnClearAlerts) btnClearAlerts.onclick = () => triggerReset(true);

    // =========================================================================
    // 8. Simulation Triggers
    // =========================================================================
    if (btnSimScan) {
        btnSimScan.onclick = async () => {
            showToast("Đang phát 25 kết nối Port Scan thử nghiệm...", "info");
            try {
                const res = await fetch("/api/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mode: "scan" })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Port Scan test hoàn tất tới ${data.result.distinct_ports_count} cổng!`, "success");
                    setTimeout(fetchAlerts, 1000);
                }
            } catch (err) {
                showToast("Lỗi chạy kiểm thử mô phỏng.", "error");
            }
        };
    }

    if (btnSimSyn) {
        btnSimSyn.onclick = async () => {
            showToast("Đang phát 120 gói TCP SYN Flood...", "info");
            try {
                const res = await fetch("/api/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mode: "syn" })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Phát ${data.result.packets_sent} gói SYN Flood (${data.result.rate_per_sec} SYN/s)!`, "success");
                    setTimeout(fetchAlerts, 1000);
                }
            } catch (err) {
                showToast("Lỗi chạy kiểm thử SYN Flood.", "error");
            }
        };
    }

    if (btnSimIcmp) {
        btnSimIcmp.onclick = async () => {
            showToast("Đang phát 60 gói ICMP Ping Flood...", "info");
            try {
                const res = await fetch("/api/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mode: "icmp" })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Phát ${data.result.packets_sent} gói ICMP Ping Flood!`, "success");
                    setTimeout(fetchAlerts, 1000);
                }
            } catch (err) {
                showToast("Lỗi chạy kiểm thử ICMP Flood.", "error");
            }
        };
    }

    if (btnSimUdp) {
        btnSimUdp.onclick = async () => {
            showToast("Đang phát 100 gói UDP Flood...", "info");
            try {
                const res = await fetch("/api/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mode: "udp" })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Phát ${data.result.packets_sent} gói UDP Flood!`, "success");
                    setTimeout(fetchAlerts, 1000);
                }
            } catch (err) {
                showToast("Lỗi chạy kiểm thử UDP Flood.", "error");
            }
        };
    }

    if (btnSimNormal) {
        btnSimNormal.onclick = async () => {
            showToast("Đang gửi 15 gói tới cùng cổng 8080 (Negative Test)...", "info");
            try {
                const res = await fetch("/api/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mode: "normal" })
                });
                const data = await res.json();
                if (data.success) {
                    showToast("Đã gửi xong 15 gói tin bình thường (0 cảnh báo sinh ra).", "success");
                }
            } catch (err) {
                showToast("Lỗi chạy kiểm thử mô phỏng.", "error");
            }
        };
    }

    // =========================================================================
    // 9. Single Page App Navigation (Sidebar Routing)
    // =========================================================================
    const viewTitleMap = {
        "view-overview": "Tổng quan (Overview)",
        "view-traffic": "Lưu lượng mạng (Traffic Analytics)",
        "view-alerts": "Cảnh báo xâm nhập (Alerts)",
        "view-logs": "Nhật ký hệ thống (System Logs)",
        "view-storage": "Quản lý tệp Log (Storage)",
        "view-simulation": "Phòng kiểm thử (Simulation Lab)",
        "view-settings": "Cấu hình & Ngưỡng luật (Settings)"
    };

    window.switchView = function(viewId) {
        document.querySelectorAll(".nav-item").forEach(item => {
            if (item.getAttribute("data-view") === viewId) item.classList.add("active");
            else item.classList.remove("active");
        });

        document.querySelectorAll(".soc-view").forEach(v => {
            if (v.id === viewId) v.classList.add("active");
            else v.classList.remove("active");
        });

        activeView = viewId;
        if (currentViewTitle && viewTitleMap[viewId]) {
            currentViewTitle.textContent = viewTitleMap[viewId];
        }

        // Trigger immediate data fetch for the active view
        if (viewId === "view-overview" || viewId === "view-alerts") fetchAlerts();
        if (viewId === "view-logs") fetchLogs();
        if (viewId === "view-storage") fetchStorage();
    };

    document.querySelectorAll(".nav-item").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetView = btn.getAttribute("data-view");
            if (targetView) switchView(targetView);
        });
    });

    // Filter Change Listeners
    if (filterSeverity) filterSeverity.onchange = fetchAlerts;
    if (filterSearch) filterSearch.oninput = debounce(fetchAlerts, 300);
    if (btnRefreshAlerts) btnRefreshAlerts.onclick = fetchAlerts;
    if (filterLogLevel) filterLogLevel.onchange = fetchLogs;
    if (btnRefreshLogs) btnRefreshLogs.onclick = fetchLogs;

    // Toast Utility
    function showToast(msg, type = "info") {
        const container = document.getElementById("toastContainer");
        if (!container) return;
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    function escapeHtml(text) {
        if (!text) return "";
        return String(text).replace(/[&<>"']/g, m => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
        }[m]));
    }

    function debounce(func, wait) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // =========================================================================
    // 10. Start Dashboard Lifecycle
    // =========================================================================
    loadInterfaces();
    fetchStatus();
    fetchAlerts();

    // Constant background polling without reload
    pollInterval = setInterval(() => {
        fetchStatus();
        if (activeView === "view-overview" || activeView === "view-alerts") {
            fetchAlerts();
        } else if (activeView === "view-logs") {
            fetchLogs();
        }
    }, 1500);
});
