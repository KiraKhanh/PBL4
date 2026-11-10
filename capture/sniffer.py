"""
Packet Sniffer Module for PBL4 Network IDS.
------------------------------------------
Trach nhiem:
1. Bat goi tin tu giao dien mang duoc chi dinh (Loopback hoac Card vat ly).
2. Hoat dong bat dong bo (AsyncSniffer) voi Producer - Consumer pattern.
3. Day goi tin vao Bounded Queue de ngan chan tran bo nho RAM.
4. Quan ly vong doi va trang thai ro rang: STOPPED, STARTING, RUNNING, STOPPING, ERROR.
5. Cung cap thong ke thoi gian thuc (CaptureStats).
"""

import threading
import queue
import time
from typing import Optional, Callable
from scapy.all import AsyncSniffer, conf

from common.models import CaptureStats


class SnifferStatus:
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class PacketSniffer:
    """
    Quan ly qua trinh bat goi tin mang Scapy tren Windows.
    """

    def __init__(self, iface: Optional[str] = None, max_queue_size: int = 10000, bpf_filter: Optional[str] = None):
        """
        :param iface: Ten hoac GUID cua giao dien mang (vi du: conf.loopback_name hoac ten Wi-Fi).
        :param max_queue_size: Gioi han so goi tin toi da trong hang doi dem.
        :param bpf_filter: Bo loc BPF tuy chon (vi du: 'ip', 'tcp or udp').
        """
        self.iface = iface or getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")
        self.max_queue_size = max_queue_size
        self.bpf_filter = bpf_filter

        # Hang doi co gioi han giua Producer (Sniffer) va Consumer (Worker)
        self.packet_queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        
        # Trang thai va thong ke
        self.status: str = SnifferStatus.STOPPED
        self.error_message: Optional[str] = None
        self.stats = CaptureStats()
        
        # Luong AsyncSniffer va khoa bao ve trang thai
        self._async_sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()

    def _on_packet_received(self, pkt):
        """
        Callback duoc goi ngay lap tuc moi khi co 1 goi tin den card mang.
        Thuc hien cuc ky toi gian: chi day vao queue, khong I/O, khong xu ly nang.
        """
        try:
            self.packet_queue.put_nowait(pkt)
        except queue.Full:
            # Neu hang doi day, bo qua goi va tang bo dem dropped
            with self._lock:
                self.stats.dropped_packets += 1

    def start(self) -> bool:
        """
        Khoi dong qua trinh bat goi tin tren luong nen.
        Tra ve True neu khoi dong thanh cong, False neu that bai.
        """
        with self._lock:
            if self.status in [SnifferStatus.RUNNING, SnifferStatus.STARTING]:
                return True
            
            self.status = SnifferStatus.STARTING
            self.error_message = None
            self._stop_requested.clear()
            self.stats = CaptureStats(start_time=time.time())

        try:
            # Khoi tao Scapy AsyncSniffer
            # store=False de Scapy khong tich luy goi tin trong RAM
            self._async_sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self._on_packet_received,
                store=False,
                filter=self.bpf_filter
            )
            self._async_sniffer.start()
            
            with self._lock:
                self.status = SnifferStatus.RUNNING
            return True

        except Exception as e:
            with self._lock:
                self.status = SnifferStatus.ERROR
                self.error_message = str(e)
            return False

    def stop(self, timeout: float = 3.0) -> bool:
        """
        Dung qua trinh bat goi tin mot cach co kiem soat.
        Giai phong socket va join luong an toan.
        """
        with self._lock:
            if self.status in [SnifferStatus.STOPPED, SnifferStatus.STOPPING]:
                return True
            self.status = SnifferStatus.STOPPING

        try:
            if self._async_sniffer is not None:
                self._async_sniffer.stop()
                self._async_sniffer = None
            
            with self._lock:
                self.status = SnifferStatus.STOPPED
            return True
        except Exception as e:
            with self._lock:
                self.status = SnifferStatus.ERROR
                self.error_message = str(e)
            return False

    def get_status(self) -> dict:
        """Tra ve trang thai tong the de phuc vu Dashboard va Logging."""
        with self._lock:
            duration = (time.time() - self.stats.start_time) if self.stats.start_time and self.status == SnifferStatus.RUNNING else 0.0
            return {
                "status": self.status,
                "interface": self.iface,
                "error": self.error_message,
                "queue_size": self.packet_queue.qsize(),
                "dropped_packets": self.stats.dropped_packets,
                "uptime_seconds": round(duration, 2)
            }
