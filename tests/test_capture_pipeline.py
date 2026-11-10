"""
Integration test for Phase 2: Sniffer -> Queue -> Consumer Worker -> Parser -> Stats.
"""

import time
import socket
import threading
import pytest
from scapy.all import conf

from capture.sniffer import PacketSniffer, SnifferStatus
from parser.packet_parser import PacketParser
from common.models import ParsedPacket, CaptureStats
from storage.file_logger import FileLogger


class TestCapturePipeline:

    def test_end_to_end_capture_and_parse(self, tmp_path):
        """
        Kiem thu tich hop toan bo pipeline Giai doan 2:
        1. Sniffer bat goi tin tren loopback
        2. Consumer worker rut goi tin tu queue
        3. Parser chuan hoa thanh ParsedPacket
        4. Cap nhat CaptureStats
        5. Dung sniffer co kiem soat.
        """
        TEST_PORT = 49876
        loopback_iface = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")
        
        logger = FileLogger(log_dir=str(tmp_path))
        sniffer = PacketSniffer(iface=loopback_iface, bpf_filter=f"udp port {TEST_PORT}")
        
        parsed_results = []
        stats = CaptureStats()
        stop_worker = threading.Event()
        
        def consumer_worker():
            while not stop_worker.is_set():
                try:
                    raw_pkt = sniffer.packet_queue.get(timeout=0.2)
                    parsed: ParsedPacket = PacketParser.parse(raw_pkt)
                    if parsed:
                        parsed_results.append(parsed)
                        stats.total_packets += 1
                        if parsed.protocol == "UDP":
                            stats.udp_packets += 1
                        elif parsed.protocol == "TCP":
                            stats.tcp_packets += 1
                    sniffer.packet_queue.task_done()
                except Exception:
                    continue

        worker_thread = threading.Thread(target=consumer_worker, daemon=True)
        worker_thread.start()
        
        # 1. Start sniffer
        started = sniffer.start()
        assert started is True
        assert sniffer.status == SnifferStatus.RUNNING
        logger.log_info(f"Bat dau sniffer tren {loopback_iface}")
        
        # Cho 0.5s de Npcap bat dau lang nghe
        time.sleep(0.5)
        
        # 2. Phat 2 goi tin UDP that qua socket
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(2):
            sender.sendto(f"PIPELINE_TEST_MSG_{i}".encode(), ("127.0.0.1", TEST_PORT))
            time.sleep(0.05)
        sender.close()
        
        # 3. Cho worker xu ly
        time.sleep(1.0)
        
        # 4. Dung sniffer va worker
        sniffer.stop()
        stop_worker.set()
        worker_thread.join(timeout=2.0)
        logger.close()
        
        # 5. Kiem tra ket qua
        assert sniffer.status == SnifferStatus.STOPPED
        assert len(parsed_results) == 2
        assert stats.udp_packets == 2
        assert stats.total_packets == 2
        
        first_pkt = parsed_results[0]
        assert first_pkt.protocol == "UDP"
        assert first_pkt.dst_port == TEST_PORT
        assert first_pkt.src_ip == "127.0.0.1"
        assert first_pkt.dst_ip == "127.0.0.1"
