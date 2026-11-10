"""
Traffic Generator / Simulation Module for PBL4 Network IDS.
-----------------------------------------------------------
Trach nhiem:
1. Sinh luu luong kiem thu co kiem soat tren loopback (127.0.0.1).
2. Tao cac kich ban kiem thu thuc te (Positive & Negative tests):
   - Kiem thu Port Scan: Ket noi den N cong dich khac nhau trong thoi gian ngan.
   - Kiem thu luu luong binh thuong (Normal traffic): Gui nhieu goi den cung 1 cong.
   - Kiem thu SYN Flood, UDP Flood, ICMP Flood (chuan bi cho Giai doan 6).
3. Hoan toan su dung socket that cua he dieu hanh, de goi tin di qua
   card Loopback va duoc IDS bat mot cach tu nhien (KHONG mock, KHONG goi thang engine).
4. Co gioi han toc do, so luong goi tin an toan va co the dung ngay lap tuc.
"""

import time
import socket
from typing import List, Dict, Any, Optional


class TrafficGenerator:
    """
    Cong cu tao luu luong mang kiem thu an toan cho IDS.
    """

    def __init__(self, target_ip: str = "127.0.0.1"):
        self.target_ip = target_ip

    def simulate_port_scan(
        self,
        start_port: int = 20000,
        port_count: int = 25,
        delay_seconds: float = 0.02
    ) -> Dict[str, Any]:
        """
        Mo phong hanh vi quet cong (TCP Port Scan):
        Gui cac ket noi TCP SYN toi port_count cong dich khac nhau.
        """
        ports_scanned: List[int] = []
        start_time = time.time()

        for i in range(port_count):
            port = start_port + i
            try:
                # connect_ex se phat goi TCP SYN that tu Windows Network Stack
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect_ex((self.target_ip, port))
                s.close()
                ports_scanned.append(port)
            except Exception:
                pass

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        elapsed = time.time() - start_time
        return {
            "mode": "PORT_SCAN",
            "target_ip": self.target_ip,
            "distinct_ports_count": len(ports_scanned),
            "ports_range": f"{start_port} - {start_port + port_count - 1}",
            "elapsed_seconds": round(elapsed, 3)
        }

    def simulate_normal_traffic(
        self,
        target_port: int = 8080,
        packet_count: int = 15,
        delay_seconds: float = 0.05
    ) -> Dict[str, Any]:
        """
        Mo phong luu luong binh thuong (Negative Test):
        Gui nhieu goi tin toi CUNG MOT CONG dich duy nhat.
        IDS khong duoc coi day la quet cong!
        """
        sent_count = 0
        start_time = time.time()

        for _ in range(packet_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect_ex((self.target_ip, target_port))
                s.close()
                sent_count += 1
            except Exception:
                pass

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        elapsed = time.time() - start_time
        return {
            "mode": "NORMAL_TRAFFIC",
            "target_ip": self.target_ip,
            "target_port": target_port,
            "packets_sent": sent_count,
            "elapsed_seconds": round(elapsed, 3)
        }

    def simulate_syn_flood(
        self,
        target_port: int = 80,
        packet_count: int = 120,
        delay_seconds: float = 0.002
    ) -> Dict[str, Any]:
        """
        Mo phong SYN Flood DoS:
        Gui lien tuc cac goi TCP SYN toi mot cong dich duy nhat voi toc do cao.
        """
        sent_count = 0
        start_time = time.time()

        for _ in range(packet_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.02)
                s.connect_ex((self.target_ip, target_port))
                s.close()
                sent_count += 1
            except Exception:
                pass

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        elapsed = time.time() - start_time
        return {
            "mode": "SYN_FLOOD",
            "target_ip": self.target_ip,
            "target_port": target_port,
            "packets_sent": sent_count,
            "elapsed_seconds": round(elapsed, 3),
            "rate_per_sec": round(sent_count / max(0.001, elapsed), 1)
        }

    def simulate_udp_flood(
        self,
        target_port: int = 9999,
        packet_count: int = 100,
        delay_seconds: float = 0.002
    ) -> Dict[str, Any]:
        """
        Mo phong UDP Flood DoS:
        Gui lien tuc hang loat goi tin UDP datagram toi muc tieu.
        """
        sent_count = 0
        start_time = time.time()
        payload = b"PBL4_UDP_FLOOD_SIMULATION_DATA_TEST"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for _ in range(packet_count):
            try:
                s.sendto(payload, (self.target_ip, target_port))
                sent_count += 1
            except Exception:
                pass

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        s.close()
        elapsed = time.time() - start_time
        return {
            "mode": "UDP_FLOOD",
            "target_ip": self.target_ip,
            "target_port": target_port,
            "packets_sent": sent_count,
            "elapsed_seconds": round(elapsed, 3),
            "rate_per_sec": round(sent_count / max(0.001, elapsed), 1)
        }

    def simulate_icmp_flood(
        self,
        packet_count: int = 60,
        delay_seconds: float = 0.005
    ) -> Dict[str, Any]:
        """
        Mo phong ICMP Ping Flood:
        Gui lien tuc cac goi tin ICMP Echo Request toi muc tieu qua Npcap Loopback.
        """
        from scapy.all import send, IP, ICMP, conf
        sent_count = 0
        start_time = time.time()
        loopback_iface = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")

        for _ in range(packet_count):
            try:
                send(
                    IP(dst=self.target_ip) / ICMP(),
                    iface=loopback_iface,
                    verbose=False
                )
                sent_count += 1
            except Exception:
                pass

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        elapsed = time.time() - start_time
        return {
            "mode": "ICMP_FLOOD",
            "target_ip": self.target_ip,
            "packets_sent": sent_count,
            "elapsed_seconds": round(elapsed, 3),
            "rate_per_sec": round(sent_count / max(0.001, elapsed), 1)
        }


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="PBL4 IDS - Controlled Traffic Generator")
    parser.add_argument("--mode", choices=["scan", "normal", "syn", "icmp", "udp"], default="scan",
                        help="Che do: scan, normal, syn, icmp, udp")
    parser.add_argument("--target", default="127.0.0.1", help="IP dich (mac dinh: 127.0.0.1)")
    parser.add_argument("--ports", type=int, default=25, help="So cong quet trong che do scan")
    parser.add_argument("--count", type=int, default=100, help="So goi tin cho che do flood / normal")

    args = parser.parse_args()

    generator = TrafficGenerator(target_ip=args.target)
    print("=" * 70)
    print("   PBL4 NETWORK IDS - CONG CU MO PHONG LUU LUONG KIEM THU")
    print("=" * 70)
    print(f"[+] Che do mo phong : {args.mode.upper()}")
    print(f"[+] Muc tieu        : {args.target}")

    if args.mode == "scan":
        print(f"[+] Dang phat goi tin quet {args.ports} cong...")
        res = generator.simulate_port_scan(port_count=args.ports)
        print(f"[OK] Da gui thanh cong toi {res['distinct_ports_count']} cong khac nhau.")
    elif args.mode == "syn":
        print(f"[+] Dang phat SYN Flood ({args.count} goi)...")
        res = generator.simulate_syn_flood(packet_count=args.count)
        print(f"[OK] Da phat {res['packets_sent']} goi SYN (Toc do: {res['rate_per_sec']} SYN/s).")
    elif args.mode == "icmp":
        print(f"[+] Dang phat ICMP Flood ({args.count} goi)...")
        res = generator.simulate_icmp_flood(packet_count=args.count)
        print(f"[OK] Da phat {res['packets_sent']} goi ICMP (Toc do: {res['rate_per_sec']} ICMP/s).")
    elif args.mode == "udp":
        print(f"[+] Dang phat UDP Flood ({args.count} goi)...")
        res = generator.simulate_udp_flood(packet_count=args.count)
        print(f"[OK] Da phat {res['packets_sent']} goi UDP (Toc do: {res['rate_per_sec']} UDP/s).")
    else:
        print(f"[+] Dang gui {args.count} goi tin den cung mot cong 8080...")
        res = generator.simulate_normal_traffic(target_port=8080, packet_count=args.count)
        print(f"[OK] Da gui thanh cong {res['packets_sent']} goi tin trong {res['elapsed_seconds']}s.")
    print("=" * 70)
