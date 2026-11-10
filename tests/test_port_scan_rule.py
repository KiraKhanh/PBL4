"""
Unit tests for PortScanRule: Positive, Negative, and Edge Cases.
"""

import pytest
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.port_scan import PortScanRule


class TestPortScanRule:

    def test_positive_port_scan_exceeds_threshold(self):
        """Kiem thu duong tinh: Tiep can 20 cong dich khac nhau -> phat sinh Alert."""
        flow_engine = FlowEngine(time_window_seconds=5.0)
        rule = PortScanRule(distinct_ports_threshold=20, time_window_seconds=5.0)

        now = 1000.0
        alert = None

        # Gui den 20 cong khac nhau: 1000 -> 1019
        for port in range(1000, 1020):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                protocol="TCP",
                packet_length=60,
                src_port=45000,
                dst_port=port,
                tcp_flags=["SYN"]
            )
            flow_engine.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow_engine, now=now)

        assert alert is not None
        assert alert.attack_type == "PORT_SCAN"
        assert alert.severity == "HIGH"
        assert alert.src_ip == "192.168.1.100"
        assert alert.dst_ip == "192.168.1.1"
        assert alert.evidence["distinct_ports_count"] == 20
        assert alert.evidence["threshold"] == 20

    def test_negative_below_threshold_no_alert(self):
        """Kiem thu am tinh: Chi tiep can 5 cong dich khac nhau (< 20) -> KHONG phat alert."""
        flow_engine = FlowEngine(time_window_seconds=5.0)
        rule = PortScanRule(distinct_ports_threshold=20, time_window_seconds=5.0)

        now = 1000.0
        for port in range(80, 85):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="192.168.1.50",
                dst_ip="192.168.1.1",
                protocol="TCP",
                packet_length=60,
                dst_port=port,
                tcp_flags=["SYN"]
            )
            flow_engine.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow_engine, now=now)
            assert alert is None

    def test_negative_many_packets_to_same_port_no_alert(self):
        """Kiem thu am tinh: Gui 100 goi tin den CUNG MOT CONG 80 -> KHONG phai quet cong!"""
        flow_engine = FlowEngine(time_window_seconds=5.0)
        rule = PortScanRule(distinct_ports_threshold=20, time_window_seconds=5.0)

        now = 1000.0
        for _ in range(100):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.5",
                dst_ip="10.0.0.1",
                protocol="TCP",
                packet_length=60,
                dst_port=80,
                tcp_flags=["SYN"]
            )
            flow_engine.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow_engine, now=now)
            assert alert is None

    def test_non_tcp_packets_ignored_by_port_scan_rule(self):
        """Goi UDP hoac ICMP khong lam kich hoat luat TCP Port Scan."""
        flow_engine = FlowEngine(time_window_seconds=5.0)
        rule = PortScanRule(distinct_ports_threshold=5, time_window_seconds=5.0)

        now = 1000.0
        for p in range(10):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.5",
                dst_ip="10.0.0.1",
                protocol="UDP",
                packet_length=60,
                dst_port=5000 + p
            )
            flow_engine.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow_engine, now=now)
            assert alert is None
