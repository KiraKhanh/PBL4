"""
Unit tests for FlowEngine module.
"""

import time
import pytest
from common.models import ParsedPacket
from features.flow_engine import FlowEngine


class TestFlowEngine:

    def test_add_packet_and_distinct_ports(self):
        engine = FlowEngine(time_window_seconds=5.0)
        now = 1000.0

        # IP 10.0.0.1 gui den 3 cong khac nhau: 80, 443, 8080
        for port in [80, 443, 8080]:
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="TCP",
                packet_length=60,
                src_port=50000,
                dst_port=port,
                tcp_flags=["SYN"]
            )
            engine.add_packet(pkt, now=now)

        distinct_ports = engine.get_distinct_ports("10.0.0.1", now=now)
        assert len(distinct_ports) == 3
        assert distinct_ports == {80, 443, 8080}
        assert engine.get_packet_count("10.0.0.1", now=now) == 3
        assert engine.get_syn_count("10.0.0.1", now=now) == 3

    def test_multiple_packets_to_same_port_results_in_one_distinct_port(self):
        engine = FlowEngine(time_window_seconds=5.0)
        now = 1000.0

        # Gui 20 goi tin den CUNG MOT CONG 80
        for _ in range(20):
            pkt = ParsedPacket(
                timestamp="2026-10-23T00:00:00Z",
                src_ip="192.168.1.5",
                dst_ip="192.168.1.1",
                protocol="TCP",
                packet_length=60,
                src_port=50000,
                dst_port=80,
                tcp_flags=["SYN"]
            )
            engine.add_packet(pkt, now=now)

        distinct_ports = engine.get_distinct_ports("192.168.1.5", now=now)
        assert len(distinct_ports) == 1
        assert distinct_ports == {80}
        assert engine.get_packet_count("192.168.1.5", now=now) == 20

    def test_sliding_window_expiration(self):
        engine = FlowEngine(time_window_seconds=5.0)
        start_t = 1000.0

        # Goi 1 gui vao thoi diem 1000.0 den port 21
        pkt1 = ParsedPacket(
            timestamp="2026-10-23T00:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
            packet_length=60,
            dst_port=21,
            tcp_flags=["SYN"]
        )
        engine.add_packet(pkt1, now=start_t)

        # Goi 2 gui vao thoi diem 1006.0 (sau 6s, goi 1 da het han)
        pkt2 = ParsedPacket(
            timestamp="2026-10-23T00:00:06Z",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
            packet_length=60,
            dst_port=22,
            tcp_flags=["SYN"]
        )
        engine.add_packet(pkt2, now=start_t + 6.0)

        # Tai thoi diem 1006.0, chi con port 22 con hieu luc trong cua so 5s
        distinct_ports = engine.get_distinct_ports("10.0.0.1", now=start_t + 6.0)
        assert distinct_ports == {22}
        assert len(distinct_ports) == 1

    def test_cleanup_expired_ips_frees_memory(self):
        engine = FlowEngine(time_window_seconds=5.0)
        now = 1000.0

        pkt = ParsedPacket(
            timestamp="2026-10-23T00:00:00Z",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            protocol="TCP",
            packet_length=60,
            dst_port=80
        )
        engine.add_packet(pkt, now=now)
        assert "1.2.3.4" in engine.flows

        # Don dep tai thoi diem 1010.0 (qua 10 giay sau)
        engine.cleanup_expired(now=now + 10.0)
        assert "1.2.3.4" not in engine.flows
