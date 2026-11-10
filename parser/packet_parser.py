"""
Packet Parser Module for PBL4 Network IDS.
-----------------------------------------
Trach nhiem:
1. Nhan Scapy Packet tu Packet Capture.
2. Trich xuat va chuan hoa thong tin thanh ParsedPacket dataclass.
3. Xu ly an toan cac truong hop goi tin khong co port (ICMP, ARP), goi tin IPv6,
   hoac goi tin di dang / thieu truong.
4. Tuyet doi khong luu payload nhay cam vao bo nho RAM hoac log.
"""

from datetime import datetime, timezone
from typing import Optional, List
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from common.models import ParsedPacket


class PacketParser:
    """
    Bo phan tich va chuan hoa goi tin mang.
    """

    # Danh sach co TCP chuan can theo doi
    TCP_FLAG_MAP = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    @classmethod
    def extract_tcp_flags(cls, flags_val) -> List[str]:
        """
        Giai ma cac co TCP tu doi tuong flags cua Scapy.
        flags_val co the la FlagValue hoac string (vi du: 'SA', 'PA', 'R').
        """
        if not flags_val:
            return []

        flags_str = str(flags_val)
        result: List[str] = []
        for char, name in cls.TCP_FLAG_MAP.items():
            if char in flags_str:
                result.append(name)
        return result

    @classmethod
    def parse(cls, pkt: Packet) -> Optional[ParsedPacket]:
        """
        Phan tich mot goi tin Scapy thanh ParsedPacket.
        Neu goi tin khong hop le hoac khong phai goi IP/IPv6, tra ve None hoac ParsedPacket voi protocol 'OTHER'.
        Khong bao gio quang ngoai le (exception) ra ngoai lam sap he thong.
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            pkt_len = len(pkt) if hasattr(pkt, "__len__") else 0

            src_ip: Optional[str] = None
            dst_ip: Optional[str] = None
            protocol: str = "OTHER"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags: List[str] = []
            payload_len: int = 0

            # 1. Trich xuat IP Layer (IPv4 hoac IPv6)
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
            else:
                # Goi tin khong thuoc lop mang IP (vi du: ARP, LLDP, STP)
                return None

            # 2. Trich xuat Transport Layer
            if TCP in pkt:
                tcp_layer = pkt[TCP]
                protocol = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = cls.extract_tcp_flags(tcp_layer.flags)
                if hasattr(tcp_layer, "payload") and tcp_layer.payload:
                    payload_len = len(tcp_layer.payload)

            elif UDP in pkt:
                udp_layer = pkt[UDP]
                protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                if hasattr(udp_layer, "payload") and udp_layer.payload:
                    payload_len = len(udp_layer.payload)

            elif ICMP in pkt:
                protocol = "ICMP"
                # ICMP khong co port truyen thong
                src_port = None
                dst_port = None
                if hasattr(pkt[ICMP], "payload") and pkt[ICMP].payload:
                    payload_len = len(pkt[ICMP].payload)

            else:
                protocol = "OTHER"

            # 3. Tao mo ta tom tat ngan gon de hien thi / debug
            if src_port is not None and dst_port is not None:
                summary = f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            else:
                summary = f"{protocol} {src_ip} -> {dst_ip}"

            return ParsedPacket(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                packet_length=pkt_len,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                summary=summary,
                payload_length=payload_len,
            )

        except Exception:
            # An toan tuyet doi: khong de loi parser lam crash pipeline
            return None
