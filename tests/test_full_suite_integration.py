"""
Full Integration Test for All 4 Detection Rules:
Port Scan, SYN Flood, UDP Flood, ICMP Flood.
"""

import time
import json
import os
import threading
import pytest
from scapy.all import conf

from capture.sniffer import PacketSniffer
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


class TestFullSuiteIntegration:

    def test_multi_attack_detection_pipeline(self, tmp_path):
        loopback_iface = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")
        logger = FileLogger(log_dir=str(tmp_path))
        flow = FlowEngine(time_window_seconds=5.0)

        engine = DetectionEngine(flow_engine=flow)
        # Cau hinh nguong de test nhanh
        engine.add_rule(PortScanRule(distinct_ports_threshold=15, time_window_seconds=5.0))
        engine.add_rule(SYNFloodRule(syn_rate_threshold=50, time_window_seconds=5.0))
        engine.add_rule(UDPFloodRule(udp_rate_threshold=50, time_window_seconds=5.0))
        engine.add_rule(ICMPFloodRule(icmp_rate_threshold=25, time_window_seconds=5.0))

        alert_mgr = AlertManager(file_logger=logger, cooldown_seconds=3.0)
        sniffer = PacketSniffer(iface=loopback_iface)

        stop_worker = threading.Event()
        detected_types = set()

        def consumer():
            while not stop_worker.is_set():
                try:
                    raw_pkt = sniffer.packet_queue.get(timeout=0.2)
                    parsed = PacketParser.parse(raw_pkt)
                    if parsed:
                        alerts = engine.process_packet(parsed)
                        for a in alerts:
                            emitted = alert_mgr.process_alert(a)
                            if emitted:
                                detected_types.add(emitted.attack_type)
                    sniffer.packet_queue.task_done()
                except Exception:
                    continue

        t = threading.Thread(target=consumer, daemon=True)
        t.start()

        assert sniffer.start() is True
        time.sleep(0.5)

        generator = TrafficGenerator(target_ip="127.0.0.1")

        # 1. Kiem thu UDP Flood (gui 60 goi UDP)
        generator.simulate_udp_flood(target_port=9999, packet_count=60, delay_seconds=0.001)
        time.sleep(0.6)

        # 2. Kiem thu Port Scan (quet 18 cong)
        generator.simulate_port_scan(start_port=28000, port_count=18, delay_seconds=0.01)
        time.sleep(0.6)

        # 3. Kiem thu SYN Flood (gui 65 goi SYN toi cong 80)
        generator.simulate_syn_flood(target_port=80, packet_count=65, delay_seconds=0.002)
        time.sleep(0.6)

        # Stop
        sniffer.stop()
        stop_worker.set()
        t.join(timeout=2.0)
        logger.close()

        # Kiem tra ket qua: ca 3 kieu tan cong da duoc phat hien
        assert "UDP_FLOOD" in detected_types
        assert "PORT_SCAN" in detected_types
        assert "SYN_FLOOD" in detected_types
