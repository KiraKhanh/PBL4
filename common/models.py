"""
Common data models and definitions for PBL4 Network IDS.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


@dataclass
class ParsedPacket:
    """
    Chuan hoa du lieu goi tin mang sau khi tach tu Scapy Packet.
    Tach roi hoan toan khoi cac lop doi tuong Scapy de giam thieu bo nho RAM
    va cho phep xu ly bat dong bo / da luong an toan.
    """
    timestamp: str  # ISO 8601 string, vi du: "2026-10-23T03:30:00.123456+00:00"
    src_ip: str
    dst_ip: str
    protocol: str  # "TCP", "UDP", "ICMP", "OTHER"
    packet_length: int  # Do dai goi tin tinh bang bytes
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: List[str] = field(default_factory=list)  # ["SYN"], ["SYN", "ACK"], ["RST"], ...
    summary: str = ""
    payload_length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Chuyen doi sang dictionary de ghi log JSONL hoac tra ve cho Web Dashboard."""
        return asdict(self)


@dataclass
class Alert:
    """
    Chuan hoa cau truc mot canh bao an ninh sinh boi Detection Engine.
    """
    alert_id: str
    timestamp: str  # ISO 8601 string
    attack_type: str  # Vi du: "PORT_SCAN", "SYN_FLOOD", "ICMP_FLOOD", "UDP_FLOOD"
    severity: str     # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    src_ip: str
    dst_ip: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Chuyen doi sang dictionary de ghi file alerts.jsonl hoac tra ve cho Dashboard."""
        return asdict(self)


@dataclass
class CaptureStats:
    """
    Thong ke so luong goi tin va hieu nang xu ly cua luong bat goi tin.
    """
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    dropped_packets: int = 0  # So goi bi bo roi khi hang doi xu ly (queue) bi day
    start_time: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
