"""
Core IDS Service Module for PBL4 Network IDS.
--------------------------------------------
Trach nhiem:
1. Quan ly toan bo vong doi cua he thong IDS (Start / Stop / Status).
2. Tich hop tat ca cac module: Sniffer -> Parser -> FlowEngine -> DetectionEngine -> AlertManager -> FileLogger.
3. Cung cap State va Telemetry thread-safe cho Flask Web Dashboard.
4. Tinh toan thong so thoi gian thuc: Throughput (packets per second), lich su luu luong cho bieu do.
5. Liet ke danh sach cac giao dien mang tren Windows mot cach than thien.
"""

import time
import threading
from datetime import datetime, timezone
from collections import deque
from typing import Dict, Any, List, Optional

from scapy.all import conf
from scapy.arch.windows import get_windows_if_list

from config.config_loader import load_config
from common.models import ParsedPacket, CaptureStats, Alert
from capture.sniffer import PacketSniffer, SnifferStatus
from parser.packet_parser import PacketParser
from features.flow_engine import FlowEngine
from detection.engine import DetectionEngine
from detection.port_scan import PortScanRule
from detection.syn_flood import SYNFloodRule
from detection.icmp_flood import ICMPFloodRule
from detection.udp_flood import UDPFloodRule
from alert.manager import AlertManager
from storage.file_logger import FileLogger
from simulator.traffic_generator import TrafficGenerator


class IDSService:
    """
    Service trung tam quan ly hoat dong cua IDS de Dashboard giao tiep an toan.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        """Singleton pattern de Flask app luon truy cap cung mot service duy nhat."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.config = load_config("config/config.json")
        self.logger = FileLogger(
            log_dir=self.config["logging"]["log_dir"],
            max_bytes=self.config["logging"]["max_bytes_per_file"],
            backup_count=self.config["logging"]["backup_count"]
        )

        time_window = self.config["detection"].get("time_window_seconds", 5.0)
        self.flow_engine = FlowEngine(time_window_seconds=time_window)
        self.detection_engine = DetectionEngine(flow_engine=self.flow_engine)
        
        # 1. Dang ky luat Port Scan
        ps_cfg = self.config["detection"].get("port_scan", {})
        self.detection_engine.add_rule(PortScanRule(
            enabled=ps_cfg.get("enabled", True),
            distinct_ports_threshold=ps_cfg.get("distinct_ports_threshold", 20),
            time_window_seconds=time_window,
            severity=ps_cfg.get("severity", "HIGH")
        ))

        # 2. Dang ky luat SYN Flood
        syn_cfg = self.config["detection"].get("syn_flood", {})
        self.detection_engine.add_rule(SYNFloodRule(
            enabled=syn_cfg.get("enabled", True),
            syn_rate_threshold=syn_cfg.get("syn_rate_threshold", 100),
            time_window_seconds=time_window,
            severity=syn_cfg.get("severity", "HIGH")
        ))

        # 3. Dang ky luat ICMP Flood
        icmp_cfg = self.config["detection"].get("icmp_flood", {})
        self.detection_engine.add_rule(ICMPFloodRule(
            enabled=icmp_cfg.get("enabled", True),
            icmp_rate_threshold=icmp_cfg.get("icmp_rate_threshold", 50),
            time_window_seconds=time_window,
            severity=icmp_cfg.get("severity", "MEDIUM")
        ))

        # 4. Dang ky luat UDP Flood
        udp_cfg = self.config["detection"].get("udp_flood", {})
        self.detection_engine.add_rule(UDPFloodRule(
            enabled=udp_cfg.get("enabled", True),
            udp_rate_threshold=udp_cfg.get("udp_rate_threshold", 80),
            time_window_seconds=time_window,
            severity=udp_cfg.get("severity", "MEDIUM")
        ))

        self.alert_manager = AlertManager(
            file_logger=self.logger,
            cooldown_seconds=self.config["alert"].get("cooldown_seconds", 10.0)
        )

        self.sniffer: Optional[PacketSniffer] = None
        self.stats = CaptureStats()
        self.current_interface = self.config["capture"].get("interface", getattr(conf, "loopback_name", "\\Device\\NPF_Loopback"))

        # Luong consumer va kiem soat dung
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._service_lock = threading.Lock()

        # Lich su Throughput phuc vu bieu do (giu 30 diem gan nhat)
        self.throughput_history: deque = deque(maxlen=30)
        self._last_packet_count = 0
        self._last_calc_time = time.time()

    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """Liet ke cac giao dien mang kha dung tren Windows cho Dashboard."""
        ifaces = []
        loopback_guid = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")

        # Uu tien giao dien Loopback o dau danh sach
        ifaces.append({
            "id": loopback_guid,
            "name": "Software Loopback (Localhost 127.0.0.1)",
            "description": "Npcap Loopback Adapter - Danh cho kiem thu tren cung mot may",
            "ips": ["127.0.0.1", "::1"],
            "is_loopback": True
        })

        try:
            win_if_list = get_windows_if_list()
            for item in win_if_list:
                ips = item.get("ips", [])
                name = item.get("name", "")
                desc = item.get("description", "")
                guid = item.get("guid", "")

                # Bo qua loopback vi da them thu cong o tren
                if "Loopback" in desc or "Loopback" in name:
                    continue

                # Chi hien thi card co IP hoac Wi-Fi / Ethernet
                if ips or "Wi-Fi" in name or "Ethernet" in name:
                    # Npcap device path tren Windows thuong co dang \Device\NPF_{GUID}
                    device_id = f"\\Device\\NPF_{guid}" if guid else name
                    ifaces.append({
                        "id": device_id,
                        "name": f"{name} ({', '.join(ips) if ips else 'No IP'})",
                        "description": desc,
                        "ips": ips,
                        "is_loopback": False
                    })
        except Exception as e:
            self.logger.log_error(f"Khong the liet ke interface: {e}")

        return ifaces

    def start(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """Khoi dong pipeline giam sat an toan."""
        with self._service_lock:
            if self.sniffer and self.sniffer.status == SnifferStatus.RUNNING:
                return {"success": False, "message": "IDS hien dang hoat dong, khong the khoi dong lai."}

            if interface:
                self.current_interface = interface

            self.stats = CaptureStats(start_time=time.time())
            self._stop_event.clear()
            self._last_packet_count = 0
            self._last_calc_time = time.time()
            self.throughput_history.clear()

            # Khoi tao Sniffer
            self.sniffer = PacketSniffer(
                iface=self.current_interface,
                max_queue_size=self.config["capture"].get("max_queue_size", 10000),
                bpf_filter=self.config["capture"].get("bpf_filter", "") or None
            )

            # Khoi dong luong Consumer
            def consumer_loop():
                while not self._stop_event.is_set():
                    try:
                        raw_pkt = self.sniffer.packet_queue.get(timeout=0.3)
                        parsed = PacketParser.parse(raw_pkt)
                        if parsed:
                            self.stats.total_packets += 1
                            if parsed.protocol == "TCP":
                                self.stats.tcp_packets += 1
                            elif parsed.protocol == "UDP":
                                self.stats.udp_packets += 1
                            elif parsed.protocol == "ICMP":
                                self.stats.icmp_packets += 1
                            else:
                                self.stats.other_packets += 1

                            # Danh gia canh bao
                            alerts = self.detection_engine.process_packet(parsed)
                            for alert in alerts:
                                self.alert_manager.process_alert(alert)

                        self.sniffer.packet_queue.task_done()
                    except Exception:
                        continue

            self._worker_thread = threading.Thread(target=consumer_loop, daemon=True)
            self._worker_thread.start()

            if not self.sniffer.start():
                error_msg = self.sniffer.error_message or "Khong the khoi dong Npcap sniffer."
                self.logger.log_error(f"Loi khoi dong IDS: {error_msg}")
                return {"success": False, "message": error_msg}

            self.logger.log_info(f"IDS bat dau giam sat tren giao dien: {self.current_interface}")
            return {"success": True, "message": f"IDS da khoi dong thanh cong tren {self.current_interface}."}

    def stop(self) -> Dict[str, Any]:
        """Dung giam sat mot cach co kiem soat."""
        with self._service_lock:
            if not self.sniffer or self.sniffer.status == SnifferStatus.STOPPED:
                return {"success": True, "message": "IDS da o trang thai dung."}

            self.sniffer.stop()
            self._stop_event.set()
            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

            self.logger.log_info(f"IDS da dung giam sat. Tong goi da quan sat: {self.stats.total_packets}")
            return {"success": True, "message": "IDS da dung thanh cong."}

    def get_telemetry(self) -> Dict[str, Any]:
        """Tra ve toan bo thong so he thong va thong ke thoi gian thuc cho Dashboard."""
        with self._service_lock:
            status = self.sniffer.status if self.sniffer else SnifferStatus.STOPPED
            queue_size = self.sniffer.packet_queue.qsize() if self.sniffer else 0
            dropped = self.sniffer.stats.dropped_packets if self.sniffer else 0

            # Tinh toan Throughput (pps)
            now = time.time()
            elapsed = now - self._last_calc_time
            if elapsed >= 1.0:
                current_total = self.stats.total_packets
                pps = round((current_total - self._last_packet_count) / elapsed, 1)
                self._last_packet_count = current_total
                self._last_calc_time = now
                time_label = datetime.now().strftime("%H:%M:%S")
                self.throughput_history.append({"time": time_label, "pps": max(0.0, pps)})

            uptime = 0.0
            if self.stats.start_time and status == SnifferStatus.RUNNING:
                uptime = round(now - self.stats.start_time, 1)

            alert_summary = self.alert_manager.get_summary()

            return {
                "status": status,
                "interface": self.current_interface,
                "uptime_seconds": uptime,
                "queue_size": queue_size,
                "queue_max": self.config["capture"].get("max_queue_size", 10000),
                "dropped_packets": dropped,
                "stats": {
                    "total": self.stats.total_packets,
                    "tcp": self.stats.tcp_packets,
                    "udp": self.stats.udp_packets,
                    "icmp": self.stats.icmp_packets,
                    "other": self.stats.other_packets
                },
                "alerts": {
                    "total_received": alert_summary["total_received"],
                    "total_emitted": alert_summary["total_emitted"],
                    "total_suppressed": alert_summary["total_suppressed"]
                },
                "throughput_history": list(self.throughput_history)
            }

    def run_simulation(self, mode: str = "scan") -> Dict[str, Any]:
        """Chay trinh mo phong luu luong an toan tu Dashboard."""
        generator = TrafficGenerator(target_ip="127.0.0.1")
        if mode == "scan":
            result = generator.simulate_port_scan(start_port=25000, port_count=25, delay_seconds=0.01)
        elif mode in ["syn", "syn_flood"]:
            result = generator.simulate_syn_flood(target_port=80, packet_count=120, delay_seconds=0.002)
        elif mode in ["icmp", "icmp_flood"]:
            result = generator.simulate_icmp_flood(packet_count=60, delay_seconds=0.005)
        elif mode in ["udp", "udp_flood"]:
            result = generator.simulate_udp_flood(target_port=9999, packet_count=100, delay_seconds=0.002)
        else:
            result = generator.simulate_normal_traffic(target_port=8080, packet_count=15, delay_seconds=0.01)
        return {"success": True, "result": result}

    def reset(self, clear_alerts_file: bool = True) -> Dict[str, Any]:
        """Dat lai toan bo bo dem thong ke va lich su canh bao cho phien moi."""
        with self._service_lock:
            start_t = time.time() if (self.sniffer and self.sniffer.status == SnifferStatus.RUNNING) else None
            self.stats = CaptureStats(start_time=start_t)
            if self.sniffer:
                self.sniffer.stats = CaptureStats(start_time=start_t)
            self._last_packet_count = 0
            self._last_calc_time = time.time()
            self.throughput_history.clear()
            self.flow_engine.reset()
            self.alert_manager.reset()
            if clear_alerts_file:
                self.logger.clear_alerts()
            self.logger.log_info("IDS da duoc reset toan bo bo dem thong ke va lich su canh bao.")
            return {"success": True, "message": "Da dat lai toan bo bo dem thong ke va lam sach lich su thanh cong."}
