"""
Flask Web Dashboard Backend for PBL4 Network IDS.
------------------------------------------------
Nguyen tac bao mat:
1. Chi bind vao 127.0.0.1 (Localhost), khong mo ra LAN hoac Internet.
2. Khong thuc thi bat ky lenh he dieu hanh nao qua giao dien (No OS execution).
3. Validate chat che moi tham so dau vao.
4. Flask Debug Mode = False trong moi moi truong van hanh.
5. Cung cap cac REST API phuc vu giao dien giam sat va bieu do thoi gian thuc.
"""

import os
from flask import Flask, render_template, jsonify, request
from core.ids_service import IDSService


# Thu muc templates va static
TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
ids_service = IDSService.get_instance()


@app.route("/")
def index():
    """Giao dien Dashboard giam sat chinh."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """API lay trang thai he thong, thong ke goi tin va lich su throughput."""
    telemetry = ids_service.get_telemetry()
    return jsonify(telemetry)


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """API lay danh sach cac giao dien mang kha dung tren Windows."""
    ifaces = ids_service.get_available_interfaces()
    return jsonify({"interfaces": ifaces, "current": ids_service.current_interface})


@app.route("/api/control/start", methods=["POST"])
def start_ids():
    """API khoi dong qua trinh giam sat."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    result = ids_service.start(interface=interface)
    return jsonify(result), (200 if result.get("success") else 400)


@app.route("/api/control/stop", methods=["POST"])
def stop_ids():
    """API dung giam sat an toan."""
    result = ids_service.stop()
    return jsonify(result)


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    API lay danh sach canh bao gan nhat tu alerts.jsonl voi bo loc:
    - severity: ALL, HIGH, MEDIUM, LOW
    - search: tu khoa IP
    - limit: so luong ban ghi (mac dinh 50, toi da 200)
    """
    severity = request.args.get("severity", "ALL")
    search = request.args.get("search", "")
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        limit = 50

    alerts = ids_service.logger.read_recent_alerts(
        limit=limit,
        severity_filter=severity,
        search_ip=search if search else None
    )
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    API lay nhat ky van hanh tu system.log voi bo loc level.
    """
    level = request.args.get("level", "ALL")
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        limit = 50

    logs = ids_service.logger.read_system_logs(limit=limit, level_filter=level)
    return jsonify({"logs": logs, "count": len(logs)})


@app.route("/api/storage", methods=["GET"])
def get_storage():
    """API xem thong ke dung luong luu tru log."""
    stats = ids_service.logger.get_storage_stats()
    return jsonify(stats)


@app.route("/api/storage/cleanup", methods=["POST"])
def trigger_cleanup():
    """API kich hoat don dep log theo chinh sach retention & size limit."""
    result = ids_service.logger.cleanup_logs()
    return jsonify({"success": True, "cleanup_result": result})


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """API kich hoat mo phong luu luong kiem thu an toan tren localhost."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "scan")
    valid_modes = ["scan", "normal", "syn", "syn_flood", "icmp", "icmp_flood", "udp", "udp_flood"]
    if mode not in valid_modes:
        return jsonify({"success": False, "message": f"Che do mo phong khong hop le (chi chap nhan: {', '.join(valid_modes)})."}), 400

    result = ids_service.run_simulation(mode=mode)
    return jsonify(result)


@app.route("/api/control/reset", methods=["POST"])
def reset_session():
    """API dat lai toan bo bo dem thong ke va lam sach lich su canh bao."""
    data = request.get_json(silent=True) or {}
    clear_file = data.get("clear_alerts_file", True)
    res = ids_service.reset(clear_alerts_file=clear_file)
    return jsonify(res)


def run_dashboard(host: str = "127.0.0.1", port: int = 5000):
    """Ham khoi dong web server Flask va tu dong mo trinh duyet."""
    url = f"http://{host}:{port}"
    print("=" * 70)
    print(f"   PBL4 NETWORK IDS - WEB DASHBOARD DANG CHAY TAI:")
    print(f"   {url}")
    print("=" * 70)

    # Tu dong bat trinh duyet sau 1 giay khi server san sang
    def _open_browser():
        import time
        import webbrowser
        time.sleep(1.0)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import threading
    threading.Thread(target=_open_browser, daemon=True).start()

    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
