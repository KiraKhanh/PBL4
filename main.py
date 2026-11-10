"""
PBL4 Network Intrusion Detection System (IDS) - Unified Entry Point
-------------------------------------------------------------------
Ho tro 2 che do van hanh:
1. Web Dashboard (Mac dinh):
   Khoidong giao dien Web giam sat truc quan tai http://127.0.0.1:5000.
   Lenh: python main.py

2. Terminal CLI Mode:
   Chay giam sat va in luong truc tiep tren terminal.
   Lenh: python main.py --mode cli --duration 10
"""

import sys
import argparse
from config.config_loader import load_config
from dashboard.app import run_dashboard


def run_cli_mode(duration=None):
    """Che do chay CLI truyen thong."""
    import time
    import threading
    from common.models import ParsedPacket, CaptureStats
    from capture.sniffer import PacketSniffer, SnifferStatus
    from parser.packet_parser import PacketParser
    from features.flow_engine import FlowEngine
    from detection.engine import DetectionEngine
    from detection.port_scan import PortScanRule
    from alert.manager import AlertManager
    from storage.file_logger import FileLogger

    print("=" * 75)
    print("   PBL4 NETWORK IDS - TERMINAL CLI MODE")
    print("=" * 75)

    cfg = load_config("config/config.json")
    iface = cfg["capture"]["interface"]
    max_queue = cfg["capture"]["max_queue_size"]
    bpf = cfg["capture"].get("bpf_filter", "")

    time_window = cfg["detection"].get("time_window_seconds", 5.0)
    ps_cfg = cfg["detection"].get("port_scan", {})
    ps_threshold = ps_cfg.get("distinct_ports_threshold", 20)
    cooldown = cfg["alert"].get("cooldown_seconds", 10.0)

    logger = FileLogger(
        log_dir=cfg["logging"]["log_dir"],
        max_bytes=cfg["logging"]["max_bytes_per_file"],
        backup_count=cfg["logging"]["backup_count"]
    )
    logger.log_info(f"Khoi dong IDS CLI tren {iface}")

    flow_engine = FlowEngine(time_window_seconds=time_window)
    detection_engine = DetectionEngine(flow_engine=flow_engine)
    detection_engine.add_rule(PortScanRule(
        enabled=ps_cfg.get("enabled", True),
        distinct_ports_threshold=ps_threshold,
        time_window_seconds=time_window,
        severity=ps_cfg.get("severity", "HIGH")
    ))

    alert_manager = AlertManager(file_logger=logger, cooldown_seconds=cooldown)
    sniffer = PacketSniffer(iface=iface, max_queue_size=max_queue, bpf_filter=bpf or None)
    stats = CaptureStats(start_time=time.time())
    stop_event = threading.Event()

    def consumer_loop():
        while not stop_event.is_set():
            try:
                raw_pkt = sniffer.packet_queue.get(timeout=0.3)
                parsed = PacketParser.parse(raw_pkt)
                if parsed:
                    stats.total_packets += 1
                    if parsed.protocol == "TCP": stats.tcp_packets += 1
                    elif parsed.protocol == "UDP": stats.udp_packets += 1
                    elif parsed.protocol == "ICMP": stats.icmp_packets += 1
                    else: stats.other_packets += 1

                    alerts = detection_engine.process_packet(parsed)
                    for a in alerts:
                        emitted = alert_manager.process_alert(a)
                        if emitted:
                            print(f"\n[!!! CANH BAO !!!] {emitted.alert_id} | {emitted.attack_type} | {emitted.src_ip} -> {emitted.dst_ip} ({emitted.description})")

                sniffer.packet_queue.task_done()
            except Exception:
                continue

    worker_thread = threading.Thread(target=consumer_loop, daemon=True)
    worker_thread.start()

    print(f"[+] Dang lang nghe tren: {iface}")
    print("[+] Nhan Ctrl+C de dung...")

    if not sniffer.start():
        print(f"[ERROR] Khong the khoi dong Sniffer: {sniffer.error_message}")
        return

    try:
        start_t = time.time()
        while True:
            time.sleep(0.5)
            if duration and (time.time() - start_t) >= duration:
                break
    except KeyboardInterrupt:
        pass

    sniffer.stop()
    stop_event.set()
    worker_thread.join(timeout=2.0)
    logger.close()
    print("\n[OK] Da dung giam sat.")


def main():
    parser = argparse.ArgumentParser(description="PBL4 Network Intrusion Detection System")
    parser.add_argument("--mode", choices=["dashboard", "cli"], default="dashboard",
                        help="Che do chay: 'dashboard' (Web UI, mac dinh) hoac 'cli' (Terminal)")
    parser.add_argument("--host", default="127.0.0.1", help="Host bind cho Dashboard (mac dinh: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port cho Dashboard (mac dinh: 5000)")
    parser.add_argument("--duration", type=float, default=None, help="Thoi luong chay CLI (tinh bang giay)")

    # Ho tro truyen so truc tiep (vi du: python main.py 5 -> chay CLI 5 giay)
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        run_cli_mode(duration=float(sys.argv[1]))
        return

    args = parser.parse_args()

    if args.mode == "cli":
        run_cli_mode(duration=args.duration)
    else:
        run_dashboard(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
