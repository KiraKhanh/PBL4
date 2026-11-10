"""
Flow Engine / Feature Extraction Module for PBL4 Network IDS.
-------------------------------------------------------------
Trach nhiem:
1. Theo doi va trich xuat dac trung luu luong mang theo tung dia chi IP nguon.
2. Duy tri cua so thoi gian truot (Sliding Time Window, vi du: 5 giay).
3. Tu dong loai bo cac ban ghi goi tin da het han khoi bo nho RAM.
4. Gioi han so luong IP duoc theo doi toi da (max_tracked_ips) de tranh tran bo nho.
5. Cung cap cac dac trung: so cong dich khac nhau (distinct ports), so goi SYN, ICMP, UDP.
"""

import time
from collections import deque
from typing import Dict, Set, Optional, Deque, Tuple, List
from common.models import ParsedPacket


class FlowRecord:
    """
    Luu tru danh sach cac goi tin gan nhat cua mot IP nguon trong cua so thoi gian.
    Moi phan tu trong deque: (timestamp_epoch, dst_ip, dst_port, protocol, tcp_flags)
    """
    def __init__(self):
        self.events: Deque[Tuple[float, str, Optional[int], str, List[str]]] = deque()

    def add_event(self, timestamp: float, dst_ip: str, dst_port: Optional[int], protocol: str, tcp_flags: List[str]):
        self.events.append((timestamp, dst_ip, dst_port, protocol, tcp_flags))

    def purge_expired(self, cutoff_time: float):
        """Xoa cac su kien cu hon thoi diem cutoff_time (dau deque)."""
        while self.events and self.events[0][0] < cutoff_time:
            self.events.popleft()

    def is_empty(self) -> bool:
        return len(self.events) == 0

    def get_distinct_ports(self, dst_ip: Optional[str] = None, syn_only: bool = True) -> Set[int]:
        """
        Lay tap hop cac cong dich khac nhau trong cua so thoi gian.
        Mac dinh syn_only=True: chi dem cac goi TCP SYN khoi tao ket noi (SYN=1, ACK=0),
        tranh tinh nham cac goi phan hoi (RST, ACK, SYN-ACK) mang port ephemeral tren Loopback.
        """
        ports = set()
        for _, dip, dport, proto, flags in self.events:
            if dport is not None and proto == "TCP":
                if syn_only and ("SYN" not in flags or "ACK" in flags):
                    continue
                if dst_ip is None or dip == dst_ip:
                    ports.add(dport)
        return ports

    def get_syn_count(self) -> int:
        """Dem so goi TCP mang co SYN trong cua so."""
        return sum(1 for _, _, _, proto, flags in self.events if proto == "TCP" and "SYN" in flags)

    def get_udp_count(self) -> int:
        """Dem so goi UDP trong cua so."""
        return sum(1 for _, _, _, proto, _ in self.events if proto == "UDP")

    def get_icmp_count(self) -> int:
        """Dem so goi ICMP trong cua so."""
        return sum(1 for _, _, _, proto, _ in self.events if proto == "ICMP")

    def get_total_count(self) -> int:
        return len(self.events)


class FlowEngine:
    """
    Quan ly toan bo trang thai luu luong (Flow Tracking) cua he thong IDS.
    """

    def __init__(self, time_window_seconds: float = 5.0, max_tracked_ips: int = 1000):
        self.time_window = time_window_seconds
        self.max_tracked_ips = max_tracked_ips
        # Map: src_ip -> FlowRecord
        self.flows: Dict[str, FlowRecord] = {}
        self.last_cleanup_time = time.time()

    def add_packet(self, packet: ParsedPacket, now: Optional[float] = None) -> None:
        """
        Ghi nhan mot goi tin moi vao bo dem theo doi luu luong.
        Tu dong loai bo cac ban ghi cu theo cua so thoi gian.
        """
        current_time = now if now is not None else time.time()
        src_ip = packet.src_ip

        if src_ip not in self.flows:
            # Kiem tra gioi han dung luong RAM
            if len(self.flows) >= self.max_tracked_ips:
                self.cleanup_expired(current_time)
                # Neu van day, xoa 1 IP cu nhat
                if len(self.flows) >= self.max_tracked_ips:
                    oldest_ip = next(iter(self.flows))
                    del self.flows[oldest_ip]

            self.flows[src_ip] = FlowRecord()

        flow = self.flows[src_ip]
        flow.add_event(
            timestamp=current_time,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            tcp_flags=packet.tcp_flags
        )
        # Xoa cac goi da het han cua IP nay
        cutoff = current_time - self.time_window
        flow.purge_expired(cutoff)

        # Don dep tong the dinh ky moi 5 giay
        if current_time - self.last_cleanup_time > 5.0:
            self.cleanup_expired(current_time)
            self.last_cleanup_time = current_time

    def get_distinct_ports(
        self,
        src_ip: str,
        dst_ip: Optional[str] = None,
        now: Optional[float] = None,
        syn_only: bool = True
    ) -> Set[int]:
        """
        Tra ve tap hop cac cong dich khac nhau ma src_ip da tiep can trong cua so thoi gian.
        """
        current_time = now if now is not None else time.time()
        if src_ip not in self.flows:
            return set()

        flow = self.flows[src_ip]
        flow.purge_expired(current_time - self.time_window)
        return flow.get_distinct_ports(dst_ip=dst_ip, syn_only=syn_only)

    def get_packet_count(self, src_ip: str, now: Optional[float] = None) -> int:
        """Dem tong so goi tin cua src_ip trong cua so thoi gian."""
        current_time = now if now is not None else time.time()
        if src_ip not in self.flows:
            return 0
        flow = self.flows[src_ip]
        flow.purge_expired(current_time - self.time_window)
        return flow.get_total_count()

    def get_syn_count(self, src_ip: str, now: Optional[float] = None) -> int:
        current_time = now if now is not None else time.time()
        if src_ip not in self.flows:
            return 0
        flow = self.flows[src_ip]
        flow.purge_expired(current_time - self.time_window)
        return flow.get_syn_count()

    def get_udp_count(self, src_ip: str, now: Optional[float] = None) -> int:
        """Dem so goi UDP cua src_ip trong cua so thoi gian."""
        current_time = now if now is not None else time.time()
        if src_ip not in self.flows:
            return 0
        flow = self.flows[src_ip]
        flow.purge_expired(current_time - self.time_window)
        return flow.get_udp_count()

    def get_icmp_count(self, src_ip: str, now: Optional[float] = None) -> int:
        """Dem so goi ICMP cua src_ip trong cua so thoi gian."""
        current_time = now if now is not None else time.time()
        if src_ip not in self.flows:
            return 0
        flow = self.flows[src_ip]
        flow.purge_expired(current_time - self.time_window)
        return flow.get_icmp_count()

    def cleanup_expired(self, now: Optional[float] = None):
        """Don dep cac IP khong con goi tin nao trong cua so thoi gian."""
        current_time = now if now is not None else time.time()
        cutoff = current_time - self.time_window
        expired_ips = []

        for ip, flow in self.flows.items():
            flow.purge_expired(cutoff)
            if flow.is_empty():
                expired_ips.append(ip)

        for ip in expired_ips:
            del self.flows[ip]

    def reset(self):
        """Xoa trang toan bo luu luong va cac IP dang theo doi."""
        self.flows.clear()
