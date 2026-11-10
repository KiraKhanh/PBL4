"""
Unit tests for PacketParser module.
"""

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6

from parser.packet_parser import PacketParser
from common.models import ParsedPacket


class TestPacketParser:

    def test_parse_tcp_syn_packet(self):
        """Kiem thu parser trich xuat dung goi tin TCP co co SYN."""
        pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S")
        parsed = PacketParser.parse(pkt)

        assert parsed is not None
        assert parsed.src_ip == "192.168.1.100"
        assert parsed.dst_ip == "192.168.1.1"
        assert parsed.protocol == "TCP"
        assert parsed.src_port == 54321
        assert parsed.dst_port == 80
        assert "SYN" in parsed.tcp_flags
        assert "ACK" not in parsed.tcp_flags
        assert parsed.packet_length > 0

    def test_parse_tcp_syn_ack_packet(self):
        """Kiem thu parser trich xuat ca 2 co SYN va ACK."""
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=443, dport=60000, flags="SA")
        parsed = PacketParser.parse(pkt)

        assert parsed is not None
        assert "SYN" in parsed.tcp_flags
        assert "ACK" in parsed.tcp_flags
        assert len(parsed.tcp_flags) == 2

    def test_parse_udp_packet(self):
        """Kiem thu parser voi goi UDP mang payload."""
        payload = b"TEST_UDP_PAYLOAD_DATA"
        pkt = IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / payload
        parsed = PacketParser.parse(pkt)

        assert parsed is not None
        assert parsed.src_ip == "1.1.1.1"
        assert parsed.dst_ip == "8.8.8.8"
        assert parsed.protocol == "UDP"
        assert parsed.src_port == 5353
        assert parsed.dst_port == 53
        assert parsed.tcp_flags == []
        assert parsed.payload_length == len(payload)

    def test_parse_icmp_packet(self):
        """Kiem thu parser voi goi ICMP (khong co TCP/UDP port)."""
        pkt = IP(src="192.168.1.50", dst="192.168.1.1") / ICMP(type=8)
        parsed = PacketParser.parse(pkt)

        assert parsed is not None
        assert parsed.protocol == "ICMP"
        assert parsed.src_port is None
        assert parsed.dst_port is None
        assert "ICMP 192.168.1.50 -> 192.168.1.1" in parsed.summary

    def test_parse_ipv6_packet(self):
        """Kiem thu kha nang xu ly goi tin IPv6."""
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1234, dport=5678)
        parsed = PacketParser.parse(pkt)

        assert parsed is not None
        assert parsed.src_ip == "2001:db8::1"
        assert parsed.dst_ip == "2001:db8::2"
        assert parsed.protocol == "UDP"
        assert parsed.dst_port == 5678

    def test_parse_non_ip_packet_returns_none(self):
        """Goi ARP hoac Ethernet thuan khong phai IP phai tra ve None an toan."""
        pkt = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.2")
        parsed = PacketParser.parse(pkt)
        assert parsed is None

    def test_parse_malformed_object_does_not_crash(self):
        """Truyen doi tuong bat thuong khong duoc quang ngoai le."""
        assert PacketParser.parse(None) is None
        assert PacketParser.parse("INVALID_STRING_PACKET") is None
        assert PacketParser.parse(12345) is None

    def test_parsed_packet_to_dict(self):
        """Kiem thu chuyen doi ParsedPacket sang Dictionary."""
        pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=1000, dport=2000, flags="R")
        parsed = PacketParser.parse(pkt)
        d = parsed.to_dict()

        assert isinstance(d, dict)
        assert d["src_ip"] == "127.0.0.1"
        assert d["protocol"] == "TCP"
        assert d["tcp_flags"] == ["RST"]
        assert "timestamp" in d
