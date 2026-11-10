"""
Unit tests for SYN Flood, ICMP Flood, and UDP Flood detection rules.
"""

import pytest
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.syn_flood import SYNFloodRule
from detection.icmp_flood import ICMPFloodRule
from detection.udp_flood import UDPFloodRule


class TestSYNFloodRule:

    def test_positive_syn_flood_triggers_alert(self):
        """Kiem thu duong tinh: Gui 100 goi TCP SYN -> kich hoat Alert SYN_FLOOD."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = SYNFloodRule(syn_rate_threshold=100, time_window_seconds=5.0, severity="HIGH")

        now = 1000.0
        alert = None

        for _ in range(100):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.99",
                dst_ip="10.0.0.1",
                protocol="TCP",
                packet_length=60,
                dst_port=80,
                tcp_flags=["SYN"]
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)

        assert alert is not None
        assert alert.attack_type == "SYN_FLOOD"
        assert alert.severity == "HIGH"
        assert alert.evidence["syn_packet_count"] == 100
        assert alert.evidence["threshold"] == 100

    def test_negative_syn_below_threshold_no_alert(self):
        """Kiem thu am tinh: Chi gui 30 goi SYN (< 100) -> KHONG phat alert."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = SYNFloodRule(syn_rate_threshold=100, time_window_seconds=5.0)

        now = 1000.0
        for _ in range(30):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.99",
                dst_ip="10.0.0.1",
                protocol="TCP",
                packet_length=60,
                dst_port=80,
                tcp_flags=["SYN"]
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)
            assert alert is None

    def test_tcp_ack_packets_do_not_trigger_syn_flood(self):
        """Goi TCP ACK du lieu khong duoc tinh vao SYN Flood."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = SYNFloodRule(syn_rate_threshold=100, time_window_seconds=5.0)

        now = 1000.0
        for _ in range(150):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.99",
                dst_ip="10.0.0.1",
                protocol="TCP",
                packet_length=60,
                dst_port=80,
                tcp_flags=["ACK"]
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)
            assert alert is None


class TestICMPFloodRule:

    def test_positive_icmp_flood_triggers_alert(self):
        """Kiem thu duong tinh: Gui 50 goi ICMP -> kich hoat Alert ICMP_FLOOD."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = ICMPFloodRule(icmp_rate_threshold=50, time_window_seconds=5.0)

        now = 1000.0
        alert = None

        for _ in range(50):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="192.168.1.200",
                dst_ip="192.168.1.1",
                protocol="ICMP",
                packet_length=84
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)

        assert alert is not None
        assert alert.attack_type == "ICMP_FLOOD"
        assert alert.severity == "MEDIUM"
        assert alert.evidence["icmp_packet_count"] == 50

    def test_negative_normal_ping_no_alert(self):
        """Kiem thu am tinh: Ping thong thuong (4 goi) khong phat alert."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = ICMPFloodRule(icmp_rate_threshold=50, time_window_seconds=5.0)

        now = 1000.0
        for _ in range(4):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="192.168.1.200",
                dst_ip="192.168.1.1",
                protocol="ICMP",
                packet_length=84
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)
            assert alert is None


class TestUDPFloodRule:

    def test_positive_udp_flood_triggers_alert(self):
        """Kiem thu duong tinh: Gui 80 goi UDP -> kich hoat Alert UDP_FLOOD."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = UDPFloodRule(udp_rate_threshold=80, time_window_seconds=5.0)

        now = 1000.0
        alert = None

        for _ in range(80):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="172.16.0.50",
                dst_ip="172.16.0.1",
                protocol="UDP",
                packet_length=512,
                dst_port=53
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)

        assert alert is not None
        assert alert.attack_type == "UDP_FLOOD"
        assert alert.severity == "MEDIUM"
        assert alert.evidence["udp_packet_count"] == 80

    def test_negative_normal_udp_no_alert(self):
        """Kiem thu am tinh: Gui 20 goi UDP (< 80) khong phat alert."""
        flow = FlowEngine(time_window_seconds=5.0)
        rule = UDPFloodRule(udp_rate_threshold=80, time_window_seconds=5.0)

        now = 1000.0
        for _ in range(20):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="172.16.0.50",
                dst_ip="172.16.0.1",
                protocol="UDP",
                packet_length=128,
                dst_port=53
            )
            flow.add_packet(pkt, now=now)
            alert = rule.evaluate(pkt, flow, now=now)
            assert alert is None
