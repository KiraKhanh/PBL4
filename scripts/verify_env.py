"""
Environment & Packet Capture Verification Script for PBL4 - Network IDS
-----------------------------------------------------------------------
Muc tieu:
1. Kiem tra phien ban Python va he dieu hanh Windows.
2. Xac minh driver Npcap va backend libpcap cua Scapy.
3. Liet ke danh sach cac giao dien mang (Network Interfaces) kha dung.
4. Thuc hien kiem thu thuc te (Smoke Test) bat goi tin that tren Loopback adapter.
"""

import sys
import os
import platform
import socket
import threading
import time

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title.upper()}")
    print("=" * 70)

def verify_system_and_python():
    print_header("1. Kiem tra He dieu hanh & Python")
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    py_version = sys.version
    
    print(f"[+] OS: {os_name} {os_release} (Version: {os_version})")
    print(f"[+] Python executable: {sys.executable}")
    print(f"[+] Python version: {py_version.split()[0]}")
    
    if os_name != "Windows":
        print("[!] Canh bao: He thong duoc thiet ke toi uu cho Windows 11.")
    else:
        print("[OK] He dieu hanh Windows phu hop.")
        
    if sys.version_info < (3, 9):
        print("[ERROR] Yeu cau Python >= 3.9.")
        return False
    print("[OK] Phien ban Python dat yeu cau (>= 3.9).")
    return True

def verify_scapy_and_npcap():
    print_header("2. Kiem tra Scapy & Npcap")
    try:
        import scapy
        from scapy.all import conf
        print(f"[+] Scapy version: {scapy.__version__}")
    except ImportError as e:
        print(f"[ERROR] Chua cai dat Scapy hoac loi import: {e}")
        print("        Vui long chay: pip install -r requirements.txt")
        return False, None
    
    # Kiem tra pcap backend cua Scapy
    use_pcap = getattr(conf, "use_pcap", False)
    print(f"[+] conf.use_pcap: {use_pcap}")
    if not use_pcap:
        print("[ERROR] Scapy khong su dung pcap backend (Npcap chua cai dat dung cach hoac thieu quyen).")
        print("        Vui long kiem tra xem Npcap da duoc cai dat tai C:\\Program Files\\Npcap chua.")
        return False, None
    
    print("[OK] Scapy da nhan dien va ket noi thanh cong voi Npcap.")
    return True, conf

def list_network_interfaces(conf):
    print_header("3. Danh sach Giao dien Mang (Network Interfaces)")
    from scapy.arch.windows import get_windows_if_list
    
    win_ifaces = get_windows_if_list()
    print(f"Tong so giao dien phat hien: {len(win_ifaces)}\n")
    print(f"{'Index':<6} {'Name':<32} {'IP Addresses':<25} {'Description'}")
    print("-" * 90)
    
    recommended_loopback = None
    recommended_wifi = None
    
    for iface in win_ifaces:
        idx = iface.get("index", "")
        name = iface.get("name", "")[:30]
        ips = ", ".join(iface.get("ips", []))
        desc = iface.get("description", "")
        
        # Loc cac giao dien chinh de hien thi ngan gon
        if ips or "Wi-Fi" in name or "Ethernet" in name or "Loopback" in desc or "Loopback" in name:
            print(f"{idx:<6} {name:<32} {ips:<25} {desc}")
            if "127.0.0.1" in iface.get("ips", []) or "Loopback" in desc:
                recommended_loopback = iface
            if "Wi-Fi" in name and ips:
                recommended_wifi = iface

    print("\n[+] Giao dien Loopback mac dinh cua Scapy:")
    loopback_name = getattr(conf, "loopback_name", "\\Device\\NPF_Loopback")
    print(f"    conf.loopback_name = {loopback_name}")
    
    return loopback_name

def test_loopback_packet_capture(loopback_name):
    print_header("4. Kiem thu Thuc te (Smoke Test): Bat goi tin Loopback")
    from scapy.all import sniff
    
    TEST_PORT = 49152
    TEST_PAYLOAD = b"PBL4_IDS_VERIFY_PAYLOAD_OK"
    captured_packets = []
    sniffer_ready = threading.Event()
    stop_sniff = threading.Event()
    
    def packet_callback(pkt):
        captured_packets.append(pkt)
    
    def run_sniffer():
        try:
            # Cho phep callback thong bao ready qua timeout ngan ban dau
            sniff(
                iface=loopback_name,
                filter=f"udp port {TEST_PORT}",
                prn=packet_callback,
                count=1,
                timeout=4,
                stop_filter=lambda x: len(captured_packets) >= 1
            )
        except Exception as err:
            print(f"[ERROR khi sniff]: {err}")
    
    # Bat thread sniffer
    sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniff_thread.start()
    
    # Nghi ngan de Npcap bat dau lang nghe tren socket
    time.sleep(1.0)
    
    # Gui goi tin UDP bang standard socket cua Python
    print(f"[+] Dang phat goi UDP toi 127.0.0.1:{TEST_PORT} qua loopback socket...")
    try:
        sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender_sock.sendto(TEST_PAYLOAD, ("127.0.0.1", TEST_PORT))
        sender_sock.close()
    except Exception as e:
        print(f"[ERROR khi gui goi tin]: {e}")
        return False
        
    sniff_thread.join(timeout=5)
    
    if len(captured_packets) > 0:
        pkt = captured_packets[0]
        print("\n[THANH CONG!] Da bat duoc goi tin thuc te tu Npcap:")
        print(f"    - Layer summary : {pkt.summary()}")
        print(f"    - Packet length : {len(pkt)} bytes")
        if pkt.haslayer("Raw"):
            raw_payload = bytes(pkt["Raw"].load)
            print(f"    - Payload data  : {raw_payload.decode(errors='replace')}")
            if raw_payload == TEST_PAYLOAD:
                print("    - Payload match : CHINH XAC 100%!")
        print("\n[KET LUAN]: Môi truong Windows 11 + Npcap + Scapy san sang 100% cho Du an!")
        return True
    else:
        print("\n[THAT BAI]: Khong bat duoc goi tin sau 4 giay.")
        print("Kiem tra:")
        print("1. Npcap co duoc cai voi tuy chon 'Support loopback traffic' khong?")
        print("2. Co can chay terminal voi quyen Administrator khong?")
        return False

def main():
    print("=" * 70)
    print("  PBL4 IDS - CHUONG TRINH XAC MINH MOI TRUONG & CAPTURE WINDOWS 11")
    print("=" * 70)
    
    if not verify_system_and_python():
        sys.exit(1)
        
    ok, conf = verify_scapy_and_npcap()
    if not ok:
        sys.exit(1)
        
    loopback_name = list_network_interfaces(conf)
    
    success = test_loopback_packet_capture(loopback_name)
    if not success:
        sys.exit(1)
        
    print_header("5. Huong dan tiep theo cho Nhom")
    print("[1] Khi kiem thu tren cung 1 may (Localhost):")
    print("    -> Dung interface: conf.loopback_name ('\\\\Device\\\\NPF_Loopback')")
    print("[2] Khi kiem thu tren mang Wi-Fi thuc te:")
    print("    -> Dung interface Wi-Fi (MediaTek/Intel/Realtek) tuong ung voi IP LAN.")
    print("=" * 70)

if __name__ == "__main__":
    main()
