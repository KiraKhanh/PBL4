# PBL4: HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (RULE-BASED NIDS) TRÊN WINDOWS 11

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8.0-orange.svg)](https://scapy.net/)
[![Npcap](https://img.shields.io/badge/Npcap-Windows%2011-success.svg)](https://npcap.com/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://palletsprojects.com/p/flask/)
[![Tests](https://img.shields.io/badge/Tests-43%2F43%20Passed-brightgreen.svg)]()

> Đồ án học phần Project-Based Learning (PBL) ngành Công nghệ Thông tin  
> Mục tiêu: Xây dựng hệ thống phát hiện xâm nhập mạng dựa trên luật (Rule-based NIDS) giám sát thời gian thực, tự động xoay vòng nhật ký và hiển thị qua Web Dashboard trực quan.  
> 
> 📖 **Tài liệu thuyết minh chi tiết**: [THUYET_MINH_THUAT_TOAN_VA_KIEN_TRUC.md](THUYET_MINH_THUAT_TOAN_VA_KIEN_TRUC.md) (Toàn bộ nguyên lý, thuật toán, công thức toán học và bảng tham số).  
> 📋 **Kịch bản demo & 15 câu hỏi vấn đáp**: [pbl4_presentation_and_defense_guide.md](pbl4_presentation_and_defense_guide.md)  
> 🚀 **Hướng dẫn vận hành thủ công**: [HUONG_DAN_SU_DUNG.md](HUONG_DAN_SU_DUNG.md)

---

## 1. Giới thiệu & Kiến trúc tổng thể

Hệ thống được thiết kế theo mô hình đường ống tuần tự (**Pipeline Architecture**) với cơ chế bất đồng bộ **Producer – Consumer** để đảm bảo quá trình bắt gói tin ở tầng kernel không bị nghẽn bởi các tác vụ I/O ghi đĩa hoặc hiển thị giao diện:

```
[Card mạng (Loopback/Wi-Fi)]
          │ (Npcap Driver)
          ▼
   [Packet Sniffer]  ──(Async / Bounded Queue: 10,000 pkts)──► [Consumer Worker]
                                                                      │
                                                                      ▼
                                                              [Packet Parser]
                                                       (Chuẩn hóa ParsedPacket)
                                                                      │
                                                                      ▼
                                                                [Flow Engine]
                                                       (Sliding Window 5.0s per IP)
                                                                      │
                                                                      ▼
                                                             [Detection Engine]
                                                  (PortScan, SYN, ICMP, UDP Flood)
                                                                      │
                                                                      ▼
                                                               [Alert Manager]
                                                       (Deduplication & Cooldown 10s)
                                                                      │
                                          ┌───────────────────────────┴───────────────────────────┐
                                          ▼                                                       ▼
                                [File Logger (JSONL)]                                   [Flask Web Dashboard]
                       (Rotating 5MB / Retention 90 days)                             (Real-time Chart.js / REST API)
```

---

## 2. Các luật phát hiện tấn công (Detection Rules)

| STT | Loại tấn công | File mã nguồn | Cơ sở nhận diện & Ngưỡng | Bằng chứng (Evidence) |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Port Scan** | `detection/port_scan.py` | Quét $\ge 20$ cổng đích khác nhau bằng gói TCP SYN (`SYN=1, ACK=0`) trong 5.0 giây. | `distinct_ports_count`, `ports_sample`, `window_seconds`, `packet_count` |
| **2** | **SYN Flood** | `detection/syn_flood.py` | Bão gói tin TCP SYN dồn dập $\ge 100$ gói trong 5.0 giây (Tốc độ $\ge 20$ SYN/s). | `syn_packet_count`, `rate_per_second`, `threshold`, `target_port` |
| **3** | **ICMP Flood** | `detection/icmp_flood.py` | Bão gói tin ICMP Echo Request $\ge 50$ gói trong 5.0 giây (Tốc độ $\ge 10$ ICMP/s). | `icmp_packet_count`, `rate_per_second`, `threshold`, `window_seconds` |
| **4** | **UDP Flood** | `detection/udp_flood.py` | Bão gói tin UDP datagram $\ge 80$ gói trong 5.0 giây (Tốc độ $\ge 16$ UDP/s). | `udp_packet_count`, `rate_per_second`, `threshold`, `target_port` |

> **Phòng chống cảnh báo giả**:
> - Hệ thống phân biệt rõ cờ TCP (`SYN=1, ACK=0`) để tránh tính nhầm các gói dữ liệu HTTP hay phản hồi ACK/RST của ứng dụng nền trên Localhost.
> - `AlertManager` tích hợp cơ chế **Cooldown 10 giây** cho mỗi cặp `(src_ip, attack_type)`, loại bỏ hiện tượng spam hàng trăm cảnh báo trùng lặp khi cuộc tấn công kéo dài.

---

## 3. Cấu trúc thư mục dự án

```text
d:/C++/PBL4/
├── capture/                  # Bắt gói tin Scapy bất đồng bộ
│   ├── __init__.py
│   └── sniffer.py            # PacketSniffer với Bounded Queue
├── parser/                   # Chuẩn hóa dữ liệu gói tin
│   ├── __init__.py
│   └── packet_parser.py      # Bóc tách IP, TCP flags, UDP, ICMP
├── features/                 # Theo dõi lưu lượng & Cửa sổ trượt
│   ├── __init__.py
│   └── flow_engine.py        # FlowEngine sliding window 5.0s
├── detection/                # Bộ điều phối & Các luật phát hiện
│   ├── __init__.py
│   ├── base_rule.py          # Lớp cơ sở trừu tượng BaseRule
│   ├── port_scan.py          # Luật phát hiện Port Scan
│   ├── syn_flood.py          # Luật phát hiện SYN Flood
│   ├── icmp_flood.py         # Luật phát hiện ICMP Flood
│   └── udp_flood.py          # Luật phát hiện UDP Flood
├── alert/                    # Quản lý cảnh báo & Cooldown
│   ├── __init__.py
│   └── manager.py            # AlertManager (Deduplication, ID format)
├── storage/                  # Nhật ký file & Xoay vòng log
│   ├── __init__.py
│   └── file_logger.py        # RotatingFileHandler (JSONL & text)
├── core/                     # Service tích hợp trung tâm
│   ├── __init__.py
│   └── ids_service.py        # IDSService Singleton cho Dashboard
├── dashboard/                # Web Dashboard Flask
│   ├── __init__.py
│   ├── app.py                # REST API backend (Bind 127.0.0.1)
│   ├── templates/
│   │   └── index.html        # Giao diện HTML5 Dark Mode
│   └── static/
│       ├── css/style.css     # Vanilla CSS Cybersecurity Theme
│       └── js/dashboard.js   # Chart.js & Real-time Polling
├── simulator/                # Công cụ sinh lưu lượng kiểm thử
│   ├── __init__.py
│   └── traffic_generator.py  # Socket testing (Scan, SYN, ICMP, UDP)
├── config/                   # Quản lý cấu hình tập trung
│   ├── config.json           # File cấu hình hoạt động
│   ├── config.example.json   # File cấu hình mẫu
│   └── config_loader.py      # Bộ nạp cấu hình đệ quy an toàn
├── logs/                     # Thư mục lưu trữ nhật ký
│   ├── system.log            # Nhật ký vận hành hệ thống
│   └── alerts.jsonl          # Nhật ký cảnh báo chuẩn JSON Lines
├── scripts/
│   └── verify_env.py         # Script xác minh môi trường Windows 11
├── tests/                    # Bộ kiểm thử tự động (43 pytest tests)
├── requirements.txt          # Danh sách thư viện Python
├── main.py                   # Điểm khởi động chính của ứng dụng
└── README.md                 # Tài liệu hướng dẫn dự án
```

---

## 4. Hướng dẫn cài đặt & Thiết lập môi trường

### 4.1. Yêu cầu tiên quyết
- **Hệ điều hành**: Windows 11 (hoặc Windows 10).
- **Python**: Phiên bản 3.9 trở lên (đã kiểm chứng ổn định trên Python 3.12).
- **Npcap Driver**: Bắt buộc cài đặt [Npcap](https://npcap.com/#download) và tích chọn:
  - `Install Npcap in WinPcap API-compatible Mode`.
  - `Support loopback traffic` (để bắt gói tin trên `127.0.0.1`).

### 4.2. Khởi tạo môi trường ảo Python
Mở PowerShell trong thư mục dự án:
```powershell
# Tạo môi trường ảo
python -m venv .venv

# Kích hoạt môi trường ảo
# Nếu dùng MSYS2 / Git Python:
.\.venv\bin\Activate.ps1
# Hoặc nếu dùng Windows Python chuẩn:
.\.venv\Scripts\Activate.ps1

# Cài đặt các thư viện cần thiết
pip install -r requirements.txt
```

### 4.3. Xác minh môi trường bắt gói tin
Chạy công cụ kiểm tra tự động trước khi vận hành:
```powershell
python scripts/verify_env.py
```
*Kết quả mong đợi*: Hiển thị `conf.use_pcap: True`, nhận diện `\Device\NPF_Loopback` và bắt thành công gói tin Smoke Test với độ chính xác 100%.

---

## 5. Hướng dẫn vận hành

> 💡 **Cẩm nang dành riêng cho sinh viên**: Xem tài liệu hướng dẫn vận hành thủ công chi tiết từ A-Z tại: **[HUONG_DAN_SU_DUNG.md](HUONG_DAN_SU_DUNG.md)**.

### 5.1. Khởi động 1-Click nhanh nhất (Khuyên dùng khi Demo)
- Nhấp đúp chuột vào file **`start_dashboard.bat`** tại thư mục gốc của dự án.
- Máy chủ sẽ tự động khởi động và tự động mở trình duyệt truy cập: **`http://127.0.0.1:5000`**.
- Để chạy nhanh toàn bộ 43 bài test tự động: Nhấp đúp chuột vào file **`run_tests.bat`**.

### 5.2. Khởi động thủ công qua Terminal
Khởi động máy chủ Web Dashboard:
```powershell
.\.venv\bin\python.exe main.py
```
Mở trình duyệt truy cập: **`http://127.0.0.1:5000`**

Các tính năng chính trên Web Dashboard:
1. **Theo dõi trạng thái**: Nút trạng thái `STOPPED` / `RUNNING` phát sáng theo thời gian thực.
2. **Chọn card mạng**: Dropdown cho phép chuyển đổi giữa `Software Loopback` (kiểm thử nội bộ) và `Wi-Fi / Ethernet` (giám sát mạng LAN).
3. **Điều khiển Start / Stop**: Khởi động hoặc dừng sniffer chỉ với một click chuột.
4. **Biểu đồ thời gian thực**:
   - Throughput Chart (Line): Tốc độ gói tin trên giây (pps) cập nhật liên tục không giật lag.
   - Protocol Chart (Doughnut): Tỷ lệ các giao thức TCP, UDP, ICMP.
5. **Thử nghiệm 1-click**: Các nút phím tắt kích hoạt ngay cuộc tấn công mô phỏng (`Port Scan`, `SYN Flood`, `ICMP Flood`, `UDP Flood`, `Normal Traffic`).
6. **Bảng Cảnh báo**: Danh sách cảnh báo động, lọc theo mức độ `HIGH / MEDIUM / LOW`, tìm kiếm IP, và nút xem chi tiết bằng chứng kỹ thuật (Evidence Modal).
7. **Nhật ký Vận hành**: Xem trực tiếp file `logs/system.log` dưới dạng cửa sổ dòng lệnh terminal.
8. **Quản lý Lưu trữ**: Xem dung lượng thư mục `logs/` và nút dọn dẹp thủ công.

### 5.2. Vận hành Terminal CLI (Dành cho Server không giao diện)
```powershell
# Chạy giám sát CLI trong 30 giây
python main.py --mode cli --duration 30

# Chạy giám sát CLI liên tục cho đến khi nhấn Ctrl+C
python main.py --mode cli
```

---

## 6. Kịch bản kiểm thử & Demo thực tế

Để thực hiện bài demo thực tế trước hội đồng đánh giá, mở **2 cửa sổ PowerShell**:

### Kịch bản 1: Kiểm thử phát hiện Port Scan (Dương tính)
- **Terminal 1**: Đang chạy `python main.py` (hoặc mở Web Dashboard).
- **Terminal 2**: Phát 25 kết nối TCP SYN quét cổng:
  ```powershell
  python simulator/traffic_generator.py --mode scan --ports 25
  ```
- **Kết quả**: Dashboard hiển thị toast thông báo, bảng Cảnh báo ghi nhận mã `ALT-YYYYMMDD-XXXX` (Loại: `PORT_SCAN`, Mức độ: `HIGH`). Bằng chứng ghi rõ danh sách 20 cổng đích đã bị quét.

### Kịch bản 2: Kiểm thử tấn công DoS Flood (SYN, ICMP, UDP)
- **Terminal 2**: Chạy lần lượt các kịch bản DoS:
  ```powershell
  # SYN Flood DoS (120 gói SYN tới cổng 80)
  python simulator/traffic_generator.py --mode syn --count 120

  # ICMP Ping Flood (60 gói ICMP)
  python simulator/traffic_generator.py --mode icmp --count 60

  # UDP Flood (100 gói UDP)
  python simulator/traffic_generator.py --mode udp --count 100
  ```
- **Kết quả**: Hệ thống kích hoạt tương ứng các cảnh báo `SYN_FLOOD`, `ICMP_FLOOD`, `UDP_FLOOD` kèm tốc độ gói/giây trong phần bằng chứng.

### Kịch bản 3: Kiểm thử âm tính (Negative Test — Lưu lượng bình thường)
- **Terminal 2**: Gửi 15 gói tin tới cùng một cổng 8080:
  ```powershell
  python simulator/traffic_generator.py --mode normal --count 15
  ```
- **Kết quả**: Bộ đếm gói tin tăng lên, nhưng **tuyệt đối không phát sinh cảnh báo giả nào** (Tỷ lệ False Positive = 0%).

---

## 7. Kiểm thử tự động (Unit & Integration Tests)

Dự án sở hữu bộ kiểm thử tự động toàn diện với **43 bài test** độc lập sử dụng `pytest`:

```powershell
pytest -v
```

Danh mục các nhóm bài test:
- `test_parser.py` (8 tests): Bóc tách cờ TCP, UDP, ICMP, IPv6, ARP, xử lý an toàn dữ liệu dị dạng.
- `test_flow_engine.py` (4 tests): Cửa sổ trượt 5s, tính distinct ports, hết hạn gói, giải phóng RAM.
- `test_port_scan_rule.py` (4 tests): Dương tính, âm tính, loại trừ gói non-TCP.
- `test_flood_rules.py` (7 tests): Dương tính & âm tính cho SYN Flood, ICMP Flood, UDP Flood.
- `test_alert_manager.py` (3 tests): Sinh mã ID, chống spam bằng Cooldown 10s, bảo toàn alert đa nguồn.
- `test_logger.py` (5 tests): Xoay vòng file 5MB, xóa file quá hạn 90 ngày, bảo vệ file active, lọc log.
- `test_config.py` (2 tests): Hợp nhất cấu hình đệ quy sâu (Deep Merge).
- `test_dashboard_api.py` (7 tests): Các REST endpoint và vòng đời Start/Stop.
- `test_capture_pipeline.py` & `test_full_suite_integration.py` (3 tests): Tích hợp luồng mạng thật trên Loopback.

---

## 8. Phân chia công việc thành viên nhóm

| Thành viên | Trách nhiệm chính | Các module phụ trách |
| :--- | :--- | :--- |
| **Thành viên 1** | Tầng Thu thập & Xử lý mạng | `capture/sniffer.py`, `parser/packet_parser.py`, `features/flow_engine.py`, `simulator/traffic_generator.py`, Unit tests tầng mạng. |
| **Thành viên 2** | Tầng Phát hiện & Giao diện | `detection/` (toàn bộ 4 luật), `alert/manager.py`, `storage/file_logger.py`, `dashboard/` (Flask & UI), Unit tests nghiệp vụ & API. |

---

## 9. Hạn chế kỹ thuật & Hướng phát triển

### Hạn chế phiên bản hiện tại
1. **Môi trường giám sát**: Tập trung tối ưu cho máy cục bộ Windows 11 (Loopback / Wi-Fi NIC của máy chạy IDS). Không thể quan sát toàn bộ mạng LAN nếu switch không bật chế độ Port Mirroring (SPAN).
2. **Lưu lượng mã hóa**: Các lưu lượng TLS/HTTPS hoặc SSH không thể bóc tách nội dung payload (tuy nhiên NIDS vẫn phát hiện tốt dựa trên hành vi header, IP, Port và tần suất).
3. **Phản ứng tự động**: Chưa tự động thêm luật Windows Firewall để chặn IP (chủ động tránh khóa nhầm kết nối của người dùng).

### Hướng phát triển tương lai
1. Mở rộng mô hình 2 máy tính: Chạy công cụ tấn công trên máy Kali Linux riêng biệt qua mạng Wi-Fi LAN.
2. Tích hợp module tự động chặn IP (IPS) qua Windows Defender Firewall API khi mức độ cảnh báo là `CRITICAL`.
3. Bổ sung mô hình Machine Learning (Random Forest hoặc Autoencoder) để phát hiện bất thường bên cạnh tập luật tĩnh.
