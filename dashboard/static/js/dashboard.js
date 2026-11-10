/**
 * PBL4 Network IDS - Frontend Logic & Real-time Visualizer
 */

document.addEventListener("DOMContentLoaded", () => {
    // State variables
    let isRunning = false;
    let pollInterval = null;
    let activeTab = "tabAlerts";
    let alertCache = [];

    // DOM Elements
    const statusDot = document.getElementById("statusDot");
    const statusText = document.getElementById("statusText");
    const interfaceSelect = document.getElementById("interfaceSelect");
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");
    const btnReset = document.getElementById("btnReset");
    const btnClearAlerts = document.getElementById("btnClearAlerts");
    const btnSimScan = document.getElementById("btnSimScan");
    const btnSimSyn = document.getElementById("btnSimSyn");
    const btnSimIcmp = document.getElementById("btnSimIcmp");
    const btnSimUdp = document.getElementById("btnSimUdp");
    const btnSimNormal = document.getElementById("btnSimNormal");

    // Metrics DOM
    const valTotalPackets = document.getElementById("valTotalPackets");
    const valThroughput = document.getElementById("valThroughput");
    const valTotalAlerts = document.getElementById("valTotalAlerts");
    const valSuppressedAlerts = document.getElementById("valSuppressedAlerts");
    const valUptime = document.getElementById("valUptime");
    const valActiveIface = document.getElementById("valActiveIface");
    const valQueuePercent = document.getElementById("valQueuePercent");
    const valDroppedPackets = document.getElementById("valDroppedPackets");
    const valQueueRaw = document.getElementById("valQueueRaw");
    const alertTabCount = document.getElementById("alertTabCount");

    // Tables and Views
    const alertsTableBody = document.getElementById("alertsTableBody");
    const systemLogConsole = document.getElementById("systemLogConsole");
    const storageFilesBody = document.getElementById("storageFilesBody");
    const storageTotalMb = document.getElementById("storageTotalMb");
    const storageMaxMb = document.getElementById("storageMaxMb");
    const storageRetentionDays = document.getElementById("storageRetentionDays");
    const btnTriggerCleanup = document.getElementById("btnTriggerCleanup");

    // Filters
    const filterSeverity = document.getElementById("filterSeverity");
    const filterSearch = document.getElementById("filterSearch");
    const filterLogLevel = document.getElementById("filterLogLevel");
    const btnRefreshAlerts = document.getElementById("btnRefreshAlerts");
    const btnRefreshLogs = document.getElementById("btnRefreshLogs");

    // Modal
    const alertModal = document.getElementById("alertModal");
    const btnModalClose = document.getElementById("btnModalClose");
    const btnModalDismiss = document.getElementById("btnModalDismiss");
    const modalAlertId = document.getElementById("modalAlertId");
    const modalAlertTime = document.getElementById("modalAlertTime");
    const modalAlertIp = document.getElementById("modalAlertIp");
    const modalAlertDesc = document.getElementById("modalAlertDesc");
    const modalAlertEvidence = document.getElementById("modalAlertEvidence");

    // =========================================================================
    // 1. Chart.js Initialization
    // =========================================================================
    const ctxThroughput = document.getElementById("throughputChart").getContext("2d");
    const gradThroughput = ctxThroughput.createLinearGradient(0, 0, 0, 240);
    gradThroughput.addColorStop(0, "rgba(6, 182, 212, 0.35)");
    gradThroughput.addColorStop(1, "rgba(6, 182, 212, 0.0)");

    const throughputChart = new Chart(ctxThroughput, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Packets / sec",
                data: [],
                borderColor: "#06b6d4",
                borderWidth: 2,
                backgroundColor: gradThroughput,
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: "#06b6d4",
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
                    backgroundColor: "rgba(15, 23, 42, 0.95)",
                    titleColor: "#94a3b8",
                    bodyColor: "#06b6d4",
                    borderColor: "rgba(255, 255, 255, 0.1)",
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.03)" },
                    ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(255, 255, 255, 0.03)" },
                    ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
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
                backgroundColor: ["#06b6d4", "#f59e0b", "#8b5cf6", "#64748b"],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "75%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(15, 23, 42, 0.95)",
                    titleColor: "#94a3b8",
                    bodyColor: "#ffffff",
                    borderColor: "rgba(255, 255, 255, 0.1)",
                    borderWidth: 1,
                    padding: 10
                }
            }
        }
    });

    // =========================================================================
    // 2. Telemetry & Real-Time Polling
    // =========================================================================
    async function fetchStatus() {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) return;
            const data = await res.json();

            // Status Badge
            const status = data.status || "STOPPED";
            isRunning = (status === "RUNNING");
            statusText.textContent = status;
            statusText.className = `status-text ${status.toLowerCase()}`;
            statusDot.className = `status-dot ${status.toLowerCase()}`;

            btnStart.disabled = isRunning || (status === "STARTING");
            btnStop.disabled = !isRunning;
            interfaceSelect.disabled = isRunning;

            // Metrics Update
            valTotalPackets.textContent = Number(data.stats.total).toLocaleString();
            valTotalAlerts.textContent = Number(data.alerts.total_emitted).toLocaleString();
            valSuppressedAlerts.textContent = `${data.alerts.total_suppressed} suppressed`;
            alertTabCount.textContent = data.alerts.total_emitted;

            // Uptime format
            const sec = Math.floor(data.uptime_seconds || 0);
            const hrs = String(Math.floor(sec / 3600)).padStart(2, "0");
            const mins = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
            const secs = String(sec % 60).padStart(2, "0");
            valUptime.textContent = `${hrs}:${mins}:${secs}`;

            // Interface
            valActiveIface.textContent = data.interface.includes("Loopback") ? "Loopback" : "Physical NIC";
            valActiveIface.title = data.interface;

            // Queue Health
            const qPercent = Math.min(100, Math.round((data.queue_size / data.queue_max) * 100));
            valQueuePercent.textContent = `${qPercent}%`;
            valQueueRaw.textContent = `${data.queue_size} / ${data.queue_max}`;
            valDroppedPackets.textContent = `${data.dropped_packets} drop`;
            const queueBar = document.getElementById("queueProgressBar");
            if (queueBar) {
                queueBar.style.width = `${Math.max(qPercent, data.queue_size > 0 ? 3 : 0)}%`;
            }

            // Throughput PPS
            const history = data.throughput_history || [];
            if (history.length > 0) {
                const latestPps = history[history.length - 1].pps;
                valThroughput.textContent = `${latestPps.toFixed(1)} pps`;

                // Update Line Chart
                throughputChart.data.labels = history.map(h => h.time);
                throughputChart.data.datasets[0].data = history.map(h => h.pps);
                throughputChart.update("none");
            }

            // Update Doughnut Chart
            protocolChart.data.datasets[0].data = [
                data.stats.tcp,
                data.stats.udp,
                data.stats.icmp,
                data.stats.other
            ];
            protocolChart.update("none");

            // Update Custom Protocol Legend Pills
            const totalPkts = (data.stats.tcp + data.stats.udp + data.stats.icmp + data.stats.other) || 0;
            const pTcp = totalPkts > 0 ? Math.round((data.stats.tcp / totalPkts) * 100) : 0;
            const pUdp = totalPkts > 0 ? Math.round((data.stats.udp / totalPkts) * 100) : 0;
            const pIcmp = totalPkts > 0 ? Math.round((data.stats.icmp / totalPkts) * 100) : 0;
            const pOther = totalPkts > 0 ? Math.max(0, 100 - (pTcp + pUdp + pIcmp)) : 0;

            const elTcp = document.getElementById("protoCountTcp");
            if (elTcp) elTcp.textContent = `${Number(data.stats.tcp).toLocaleString()} (${pTcp}%)`;
            const elUdp = document.getElementById("protoCountUdp");
            if (elUdp) elUdp.textContent = `${Number(data.stats.udp).toLocaleString()} (${pUdp}%)`;
            const elIcmp = document.getElementById("protoCountIcmp");
            if (elIcmp) elIcmp.textContent = `${Number(data.stats.icmp).toLocaleString()} (${pIcmp}%)`;
            const elOther = document.getElementById("protoCountOther");
            if (elOther) elOther.textContent = `${Number(data.stats.other).toLocaleString()} (${pOther}%)`;

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
            const severity = filterSeverity.value;
            const search = encodeURIComponent(filterSearch.value.trim());
            const res = await fetch(`/api/alerts?severity=${severity}&search=${search}&limit=50`);
            if (!res.ok) return;
            const data = await res.json();
            alertCache = data.alerts || [];

            if (alertCache.length === 0) {
                alertsTableBody.innerHTML = `<tr><td colspan="8" class="text-center empty-state">Không có cảnh báo nào thỏa mãn bộ lọc.</td></tr>`;
                return;
            }

            alertsTableBody.innerHTML = alertCache.map((a, idx) => {
                const timeStr = formatLocalTime(a.timestamp);

                let attackBadge = `<span class="alert-type-badge badge-port-scan">${a.attack_type}</span>`;
                if (a.attack_type === "SYN_FLOOD") attackBadge = `<span class="alert-type-badge badge-syn-flood">SYN FLOOD</span>`;
                else if (a.attack_type === "UDP_FLOOD") attackBadge = `<span class="alert-type-badge badge-udp-flood">UDP FLOOD</span>`;
                else if (a.attack_type === "ICMP_FLOOD") attackBadge = `<span class="alert-type-badge badge-icmp-flood">ICMP FLOOD</span>`;
                else if (a.attack_type === "PORT_SCAN") attackBadge = `<span class="alert-type-badge badge-port-scan">PORT SCAN</span>`;

                let sevPill = `<span class="sev-pill sev-pill-low">● LOW</span>`;
                if (a.severity === "HIGH") sevPill = `<span class="sev-pill sev-pill-high">● HIGH</span>`;
                else if (a.severity === "MEDIUM") sevPill = `<span class="sev-pill sev-pill-medium">● MEDIUM</span>`;

                return `
                    <tr>
                        <td><code>${timeStr}</code></td>
                        <td><strong style="color: #f8fafc;">${a.alert_id}</strong></td>
                        <td>${attackBadge}</td>
                        <td>${sevPill}</td>
                        <td><code>${a.src_ip}</code></td>
                        <td><code>${a.dst_ip}</code></td>
                        <td style="color: #cbd5e1;">${escapeHtml(a.description)}</td>
                        <td style="text-align: center;">
                            <button class="btn btn-ghost btn-sm btn-evidence" data-index="${idx}" title="Xem hồ sơ bằng chứng">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                    <circle cx="12" cy="12" r="3"></circle>
                                </svg>
                                <span>Chi tiết</span>
                            </button>
                        </td>
                    </tr>
                `;
            }).join("");

            // Gán event cho các nút xem bằng chứng
            document.querySelectorAll(".btn-evidence").forEach(btn => {
                btn.addEventListener("click", () => {
                    const idx = Number(btn.getAttribute("data-index"));
                    showEvidenceModal(alertCache[idx]);
                });
            });

        } catch (err) {
            console.error("Lỗi khi tải danh sách cảnh báo:", err);
        }
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

    function showEvidenceModal(alertItem) {
        if (!alertItem) return;
        modalAlertId.textContent = alertItem.alert_id || "-";
        modalAlertTime.textContent = formatLocalDateTime(alertItem.timestamp);
        modalAlertIp.textContent = `${alertItem.src_ip} -> ${alertItem.dst_ip}`;
        modalAlertDesc.textContent = alertItem.description || "-";
        modalAlertEvidence.textContent = JSON.stringify(alertItem.evidence || {}, null, 2);
        alertModal.classList.add("show");
    }

    // Modal Close
    btnModalClose.onclick = () => alertModal.classList.remove("show");
    btnModalDismiss.onclick = () => alertModal.classList.remove("show");
    alertModal.onclick = (e) => {
        if (e.target === alertModal) alertModal.classList.remove("show");
    };

    // =========================================================================
    // 5. System Logs Loading
    // =========================================================================
    async function fetchLogs() {
        try {
            const level = filterLogLevel.value;
            const res = await fetch(`/api/logs?level=${level}&limit=80`);
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

            // Tự cuộn xuống dưới
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
                storageFilesBody.innerHTML = `<tr><td colspan="3" class="text-center">Thư mục log trống.</td></tr>`;
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

    btnTriggerCleanup.onclick = async () => {
        try {
            const res = await fetch("/api/storage/cleanup", { method: "POST" });
            const data = await res.json();
            showToast(`Đã dọn dẹp ${data.cleanup_result.deleted_count} file log cũ.`, "success");
            fetchStorage();
        } catch (err) {
            showToast("Lỗi khi dọn dẹp log.", "error");
        }
    };

    // =========================================================================
    // 7. Start / Stop Controls
    // =========================================================================
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
            if (data.success) {
                showToast(data.message, "success");
            } else {
                showToast(data.message, "error");
            }
            fetchStatus();
        } catch (err) {
            showToast("Lỗi kết nối tới máy chủ Flask.", "error");
        }
    };

    btnStop.onclick = async () => {
        btnStop.disabled = true;
        try {
            const res = await fetch("/api/control/stop", { method: "POST" });
            const data = await res.json();
            showToast(data.message, "success");
            fetchStatus();
        } catch (err) {
            showToast("Lỗi kết nối tới máy chủ Flask.", "error");
        }
    };

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
                alertsTableBody.innerHTML = `<tr><td colspan="8" class="text-center empty-state">Chưa phát hiện hành vi xâm nhập nào.</td></tr>`;
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

    if (btnReset) {
        btnReset.onclick = () => triggerReset(true);
    }

    if (btnClearAlerts) {
        btnClearAlerts.onclick = () => triggerReset(true);
    }

    // =========================================================================
    // 8. Simulation Triggers
    // =========================================================================
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
                showToast(`Đã hoàn thành Port Scan test tới ${data.result.distinct_ports_count} cổng!`, "success");
                setTimeout(fetchAlerts, 1000);
            }
        } catch (err) {
            showToast("Lỗi chạy kiểm thử mô phỏng.", "error");
        }
    };

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
                showToast(`Phát ${data.result.packets_sent} gói UDP Flood (${data.result.rate_per_sec} UDP/s)!`, "success");
                setTimeout(fetchAlerts, 1000);
            }
        } catch (err) {
            showToast("Lỗi chạy kiểm thử UDP Flood.", "error");
        }
    };

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
                showToast("Đã gửi xong 15 gói tin bình thường (không phát cảnh báo).", "success");
            }
        } catch (err) {
            showToast("Lỗi chạy kiểm thử mô phỏng.", "error");
        }
    };

    // =========================================================================
    // 9. Tab Switching
    // =========================================================================
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            activeTab = btn.getAttribute("data-tab");
            document.getElementById(activeTab).classList.add("active");

            // Điều chỉnh bộ lọc header
            document.getElementById("alertActions").style.display = (activeTab === "tabAlerts") ? "flex" : "none";
            document.getElementById("logActions").style.display = (activeTab === "tabLogs") ? "flex" : "none";

            if (activeTab === "tabAlerts") fetchAlerts();
            else if (activeTab === "tabLogs") fetchLogs();
            else if (activeTab === "tabStorage") fetchStorage();
        });
    });

    // Filter Change Listeners
    filterSeverity.onchange = fetchAlerts;
    filterSearch.oninput = debounce(fetchAlerts, 300);
    if (btnRefreshAlerts) {
        btnRefreshAlerts.onclick = async () => {
            await fetchAlerts();
            showToast(`Đã làm mới danh sách (${alertCache.length} cảnh báo).`, "info");
        };
    }

    filterLogLevel.onchange = fetchLogs;
    btnRefreshLogs.onclick = fetchLogs;

    // Toast Notification Utility
    function showToast(msg, type = "info") {
        const container = document.getElementById("toastContainer");
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    function escapeHtml(text) {
        return text.replace(/[&<>"']/g, m => ({
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

    // Định kỳ lấy dữ liệu mỗi 1.5 giây
    pollInterval = setInterval(() => {
        fetchStatus();
        if (activeTab === "tabAlerts") fetchAlerts();
        else if (activeTab === "tabLogs") fetchLogs();
    }, 1500);
});
