"""
Full Integration Test for Phase 3: Port Scan Detection Pipeline on Loopback.
Pipeline:
TrafficGenerator (socket) -> Npcap Loopback -> PacketSniffer -> Queue ->
Consumer Worker -> PacketParser -> FlowEngine -> PortScanRule -> AlertManager -> FileLogger (alerts.jsonl).
"""

import time
import os
import json
import threading
import pytest
from scapy.all import conf

from capture.sniffer import PacketSniffer, SnifferStatus
from parser.packet_parser import PacketParser
from features.flow_engine import FlowEngine
from detection.port_scan import PortScanRule
from detection.engine import DetectionEngine
from alert.manager import AlertManager
from storage.file_logger import FileLogger
from simulator.traffic_generator import TrafficGenerator


class TestPortScanIntegration:

    def test_full_port_scan_detection_and_negative_test(self, tmp_path):
        loopback_iface = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")
        
        # 1. Khoi tao cac thanh phan pipeline
        logger = FileLogger(log_dir=str(tmp_path))
        flow_engine = FlowEngine(time_window_seconds=5.0)
        
        detection_engine = DetectionEngine(flow_engine=flow_engine)
        port_scan_rule = PortScanRule(distinct_ports_threshold=20, time_window_seconds=5.0, severity="HIGH")
        detection_engine.add_rule(port_scan_rule)
        
        alert_manager = AlertManager(file_logger=logger, cooldown_seconds=5.0)
        
        # BPF filter de chi bat cac goi TCP toi loopback trong dai port test
        sniffer = PacketSniffer(iface=loopback_iface, bpf_filter="tcp and dst host 127.0.0.1")
        
        stop_worker = threading.Event()
        
        def consumer_worker():
            while not stop_worker.is_set():
                try:
                    raw_pkt = sniffer.packet_queue.get(timeout=0.2)
                    parsed = PacketParser.parse(raw_pkt)
                    if parsed:
                        alerts = detection_engine.process_packet(parsed)
                        for alert in alerts:
                            alert_manager.process_alert(alert)
                    sniffer.packet_queue.task_done()
                except Exception:
                    continue

        worker_thread = threading.Thread(target=consumer_worker, daemon=True)
        worker_thread.start()
        
        # 2. Start Sniffer
        assert sniffer.start() is True
        time.sleep(0.5)  # Cho Npcap khoi dong capture
        
        # 3. Chay Bai Kiem Thu Duong Tinh (Positive Test): Quet 25 cong khac nhau tren localhost
        generator = TrafficGenerator(target_ip="127.0.0.1")
        scan_result = generator.simulate_port_scan(start_port=31000, port_count=25, delay_seconds=0.01)
        assert scan_result["distinct_ports_count"] == 25
        
        # Cho worker tieu thu goi tin va danh gia luat
        time.sleep(1.0)
        
        # Kiem tra da phat canh bao Port Scan
        assert alert_manager.total_alerts_emitted >= 1
        alerts_emitted_after_scan = alert_manager.total_alerts_emitted
        
        # 4. Chay Bai Kiem Thu Am Tinh (Negative Test): Gui 15 goi tin toi CUNG MOT CONG 8080
        norm_result = generator.simulate_normal_traffic(target_port=8080, packet_count=15, delay_seconds=0.01)
        assert norm_result["packets_sent"] == 15
        
        time.sleep(0.8)
        
        # So luong canh bao KHONG duoc phep tang len sau luu luong binh thuong
        assert alert_manager.total_alerts_emitted == alerts_emitted_after_scan
        
        # 5. Stop pipeline
        sniffer.stop()
        stop_worker.set()
        worker_thread.join(timeout=2.0)
        logger.close()
        
        # 6. Kiem tra file log alerts.jsonl da duoc ghi dung format
        alerts_file = os.path.join(str(tmp_path), "alerts.jsonl")
        assert os.path.exists(alerts_file)
        
        with open(alerts_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]
            
        assert len(lines) >= 1
        recorded_alert = lines[0]
        assert recorded_alert["attack_type"] == "PORT_SCAN"
        assert recorded_alert["severity"] == "HIGH"
        assert recorded_alert["src_ip"] == "127.0.0.1"
        assert recorded_alert["evidence"]["distinct_ports_count"] >= 20
        assert "ports_sample" in recorded_alert["evidence"]
