# BÁO CÁO THUYẾT MINH KIẾN TRÚC, THUẬT TOÁN & NGUYÊN LÝ HOẠT ĐỘNG
# HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG DỰA TRÊN LUẬT (RULE-BASED NIDS)
### Đồ án học phần: PBL4 - Công nghệ Thông tin / An toàn Thông tin
### Nền tảng thực thi: Python 3.12 • Scapy 2.8 • Npcap • Windows 11 64-bit

---

## MỤC LỤC
1. [TỔNG QUAN HỆ THỐNG & ĐẶT VẤN ĐỀ](#1-tổng-quan-hệ-thống--đặt-vấn-đề)
2. [KIẾN TRÚC ĐƯỜNG ỐNG DỮ LIỆU TỔNG THỂ (PIPELINE ARCHITECTURE)](#2-kiến-trúc-đường-ống-dữ-liệu-tổng-thể-pipeline-architecture)
3. [NGUYÊN LÝ VÀ THUẬT TOÁN BẮT GÓI TIN (PACKET SNIFFING ENGINE)](#3-nguyên-lý-và-thuật-toán-bắt-gói-tin-packet-sniffing-engine)
4. [THUẬT TOÁN BÓC TÁCH & CHUẨN HÓA GÓI TIN (PACKET PARSER)](#4-thuật-toán-bóc-tách--chuẩn-hóa-gói-tin-packet-parser)
5. [THUẬT TOÁN GOM LUỒNG & CỬA SỔ TRƯỢT THỜI GIAN (FLOW ENGINE & SLIDING WINDOW)](#5-thuật-toán-gom-luồng--cửa-sổ-trượt-thời-gian-flow-engine--sliding-window)
6. [CHI TIẾT 4 THUẬT TOÁN PHÁT HIỆN XÂM NHẬP (DETECTION RULES)](#6-chi-tiết-4-thuật-toán-phát-hiện-xâm-nhập-detection-rules)
7. [THUẬT TOÁN QUẢN LÝ CẢNH BÁO & CƠ CHẾ COOLDOWN (ALERT MANAGER)](#7-thuật-toán-quản-lý-cảnh-báo--cơ-chế-cooldown-alert-manager)
8. [KIẾN TRÚC LƯU TRỮ NHẬT KÝ & XOAY VÒNG DỮ LIỆU (FILE LOGGER & STORAGE)](#8-kiến-trúc-lưu-trữ-nhật-ký--xoay-vòng-dữ-liệu-file-logger--storage)
9. [CƠ CHẾ ĐO LƯỜNG CHỈ SỐ & TRUYỀN DỮ LIỆU THỜI GIAN THỰC (TELEMETRY & DASHBOARD)](#9-cơ-chế-đo-lường-chỉ-số--truyền-dữ-liệu-thời-gian-thực-telemetry--dashboard)
10. [BẢNG THỐNG KÊ THAM SỐ TOÀN HỆ THỐNG (SYSTEM CONFIGURATION MATRIX)](#10-bảng-thống-kê-tham-số-toàn-hệ-thống-system-configuration-matrix)

---

## 1. TỔNG QUAN HỆ THỐNG & ĐẶT VẤN ĐỀ

### 1.1. Mục tiêu đồ án
Hệ thống **Rule-Based Network Intrusion Detection System (NIDS)** trong đồ án PBL4 được xây dựng nhằm mục đích:
* Giám sát liên tục các gói tin lưu thông qua card mạng máy tính (cả card mạng nội bộ ảo `Loopback` lẫn card mạng vật lý `Wi-Fi` / `Ethernet`).
* Tự động bóc tách các tầng tiêu chuẩn của mô hình mạng TCP/IP.
* Nhận diện và phát hiện các hành vi tấn công mạng phổ biến thời gian thực: **TCP Port Scan (Quét cổng)**, **TCP SYN Flood (Tấn công từ chối dịch vụ DoS)**, **ICMP Ping Flood** và **UDP Flood**.
* Cung cấp cơ chế chống ngập lụt cảnh báo rác (Anti-Alert Fatigue) bằng kỹ thuật Cooldown.
* Ghi nhật ký đồng bộ kép theo chuẩn công nghiệp (`alerts.jsonl` cho máy đọc và `system.log` cho con người đọc).
* Hiển thị trực quan qua giao diện **Web Dashboard phong cách SOC/SIEM hiện đại** với độ trễ thấp ($< 1.5$ giây).

### 1.2. Tại sao chọn phương pháp dựa trên luật (Rule-Based) thay vì Machine Learning?
Trong phạm vi đồ án kỹ sư năm thứ 3 và môi trường mạng thực tế:
1. **Tính giải thích được (Explainability / Interpretability)**: Mỗi cảnh báo sinh ra đều có bằng chứng số liệu rõ ràng (số lượng gói tin, địa chỉ IP, cổng đích, dấu cờ TCP). Quản trị viên an ninh mạng có thể kiểm tra trực tiếp vì sao hệ thống báo động, trong khi các mô hình Machine Learning thường là "hộp đen" (Black Box) khó giải trình trong điều tra số (Digital Forensics).
2. **Độ trễ cực thấp (Ultra-low Latency & Deterministic)**: Thuật toán so khớp ngưỡng toán học trên cửa sổ trượt tốn chi phí tính toán $\mathcal{O}(1)$ đến $\mathcal{O}(N)$ cực nhỏ, không cần nạp mô hình nặng hay đòi hỏi GPU, đảm bảo xử lý được hàng chục nghìn gói tin/giây.
3. **Không cần tập dữ liệu huấn luyện (No Training Dataset Bias)**: Tránh được bài toán thiếu dữ liệu dán nhãn chuẩn trong mạng cục bộ Windows 11.

---

## 2. KIẾN TRÚC ĐƯỜNG ỐNG DỮ LIỆU TỔNG THỂ (PIPELINE ARCHITECTURE)

Hệ thống được thiết kế theo mô hình **Đường ống tuần tự (Sequential Pipeline)** kết hợp mẫu kiến trúc **Producer – Consumer (Nhà sản xuất – Người tiêu thụ)** chạy đa luồng bất đồng bộ:

```
                      [ GIAO DIỆN MẠNG: Wi-Fi / Loopback / Ethernet ]
                                             │
                                             ▼
                 ┌────────────────────────────────────────────────────────┐
                 │       LUỒNG 1: PRODUCER THREAD (AsyncSniffer)          │
                 │   - Gắn hook vào Npcap Kernel Driver (NDIS 6)          │
                 │   - Bắt gói tin nhị phân thô (Raw Byte Packet)         │
                 │   - KHÔNG xử lý nặng, KHÔNG I/O ghi đĩa               │
                 └───────────────────────────┬────────────────────────────┘
                                             │  put_nowait()
                                             ▼
                 ┌────────────────────────────────────────────────────────┐
                 │        HÀNG ĐỢI ĐỆM: packet_queue (Bounded Queue)       │
                 │   - Dung lượng trần giới hạn: 10,000 gói tin           │
                 │   - Chống tràn bộ nhớ RAM (Chống Out-Of-Memory)        │
                 │   - Nếu đầy (queue.Full): Tự động Drop gói an toàn     │
                 └───────────────────────────┬────────────────────────────┘
                                             │  get(timeout=0.3)
                                             ▼
                 ┌────────────────────────────────────────────────────────┐
                 │       LUỒNG 2: CONSUMER THREAD (Worker Engine)         │
                 │                                                        │
                 │  1. [PacketParser]: Phân giải Byte nhị phân            │
                 │     Ethernet Frame -> IP Header -> TCP/UDP/ICMP        │
                 │     ==> Chuẩn hóa thành đối tượng `ParsedPacket`       │
                 │                                                        │
                 │  2. [FlowEngine]: Gom luồng thống kê                   │
                 │     Sliding Window 5.0 giây theo từng Source IP        │
                 │                                                        │
                 │  3. [DetectionEngine]: Đánh giá song song 4 Luật       │
                 │     ├── PortScanRule  (Unique Ports >= 15 | HIGH)      │
                 │     ├── SynFloodRule  (SYN/ACK > 3.0 & SYN >= 50|HIGH) │
                 │     ├── IcmpFloodRule (Echo Request >= 40 | MEDIUM)    │
                 │     └── UdpFloodRule  (UDP count >= 80 | MEDIUM)       │
                 │                                                        │
                 │  4. [AlertManager]: Bộ lọc chống ngập cảnh báo         │
                 │     - Kiểm tra Cooldown 10 giây / IP / Luật             │
                 │     - Nếu trong thời gian Cooldown: Ghi nhận Suppress  │
                 │     - Nếu hợp lệ: Cấp mã `ALT-YYYYMMDD-XXXX`           │
                 └───────────────────────────┬────────────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
         ┌───────────────────────────┐               ┌───────────────────────────┐
         │     BỘ GHI NHẬT KÝ        │               │      FLASK WEB SERVER     │
         │     [FileLogger]          │               │      [IDSService API]     │
         │ - alerts.jsonl (Máy đọc)  │               │ - REST APIs: /api/stats   │
         │ - system.log (Người đọc)  │               │ - Polling thời gian thực  │
         │ - Xoay vòng file: 5MB/file│               │ - Giao diện Web Dashboard │
         └───────────────────────────┘               └───────────────────────────┘
```

---

## 3. NGUYÊN LÝ VÀ THUẬT TOÁN BẮT GÓI TIN (PACKET SNIFFING ENGINE)

*File cài đặt:* `capture/sniffer.py`

### 3.1. Cơ chế bắt gói ở tầng nhân (Kernel Level Hooking)
* **Npcap Driver**: Trên Windows 11, các socket người dùng thông thường (`AF_INET`) không thể bắt được toàn bộ gói tin thô trên mạng (Raw Sockets bị Windows hạn chế quyền). Hệ thống sử dụng thư viện **Npcap** – driver lọc gói tin mạng đạt chuẩn NDIS 6 của Windows.
* **Scapy AsyncSniffer**: Hệ thống khởi tạo đối tượng `scapy.sendrecv.AsyncSniffer` chạy trên một luồng nền C riêng biệt. Tham số cốt lõi:
  * `store=False`: **Cực kỳ quan trọng!** Mặc định Scapy sẽ lưu toàn bộ gói tin bắt được vào một danh sách trong RAM. Nếu chạy lâu dài hoặc gặp tấn công, máy sẽ tràn RAM ngay lập tức. Thiết lập `store=False` giúp gói tin sau khi xử lý xong sẽ được Python Garbage Collector giải phóng ngay.
  * `prn=self._on_packet_received`: Đăng ký hàm callback xử lý tức thời mỗi khi có 1 gói tin xuất hiện trên card mạng.

### 3.2. Thuật toán Hàng đợi có giới hạn (Bounded Queue & Drop Policy)
* Cấu trúc dữ liệu: `queue.Queue(maxsize=10000)`.
* **Mã giải thuật tại Callback Producer:**
  ```python
  def _on_packet_received(pkt):
      try:
          packet_queue.put_nowait(pkt)  # Đẩy vào queue với độ phức tạp O(1)
      except queue.Full:
          stats.dropped_packets += 1     # Hàng đợi đã đầy 10,000 gói -> Bỏ qua gói
  ```
* **Mục đích:** Khi xảy ra tấn công DDoS với lưu lượng vượt quá năng lực xử lý của CPU, cơ chế này giúp bảo vệ chương trình không bị sập và không làm đơ hệ điều hành Windows.

---

## 4. THUẬT TOÁN BÓC TÁCH & CHUẨN HÓA GÓI TIN (PACKET PARSER)

*File cài đặt:* `parser/packet_parser.py`

### 4.1. Quy trình phân giải tầng giao thức
Mỗi gói tin thô từ Scapy đi qua bộ bóc tách tĩnh `PacketParser.parse(raw_pkt)` theo quy trình từng bước:

```
[Raw Byte Frame]
      │
      ├─► 1. Kiểm tra Lớp 3 (Network Layer):
      │      - Có lớp `IP` (IPv4) không?
      │      - Nếu không: Bỏ qua (hệ thống tập trung vào IPv4).
      │      - Trích xuất: `src_ip`, `dst_ip`, `ip_proto_code`, `ttl`.
      │
      ├─► 2. Kiểm tra Lớp 4 (Transport Layer):
      │      │
      │      ├─► Nếu có lớp `TCP`:
      │      │   - Giao thức = "TCP"
      │      │   - Trích xuất: `src_port`, `dst_port`
      │      │   - Phân giải cờ TCP Flags (dưới dạng bitmask):
      │      │     * Cờ SYN: `(flags & 0x02) != 0`
      │      │     * Cờ ACK: `(flags & 0x10) != 0`
      │      │     * Cờ FIN: `(flags & 0x01) != 0`
      │      │     * Cờ RST: `(flags & 0x04) != 0`
      │      │     * Cờ PSH: `(flags & 0x08) != 0`
      │      │     * Cờ URG: `(flags & 0x20) != 0`
      │      │
      │      ├─► Nếu có lớp `UDP`:
      │      │   - Giao thức = "UDP"
      │      │   - Trích xuất: `src_port`, `dst_port`
      │      │
      │      └─► Nếu có lớp `ICMP`:
      │          - Giao thức = "ICMP"
      │          - Trích xuất `icmp_type`: Type 8 (Echo Request - Ping) hoặc Type 0 (Echo Reply).
      │
      └─► 3. Đóng gói thành dataclass `ParsedPacket`:
             Chứa dữ liệu chuẩn hóa, timestamp thực tế, kích thước payload (bytes).
```

### 4.2. Khả năng chống chịu lỗi (Fault Tolerance)
* Toàn bộ phương thức bóc tách được bao bọc trong khối `try...except Exception`. Nếu gói tin bị phân mảnh (Fragmented), lỗi Checksum hoặc dị dạng (Malformed Packet), bộ phân giải trả về `None` an toàn thay vì làm gián đoạn luồng Consumer.

---

## 5. THUẬT TOÁN GOM LUỒNG & CỬA SỔ TRƯỢT THỜI GIAN (FLOW ENGINE & SLIDING WINDOW)

*File cài đặt:* `features/flow_engine.py`

Đây là trái tim phân tích của hệ thống IDS, giải quyết bài toán: **Làm sao để biết một địa chỉ IP đã gửi bao nhiêu gói tin hoặc quét bao nhiêu cổng trong đúng 5.0 giây vừa qua?**

### 5.1. Cấu trúc dữ liệu trong bộ nhớ RAM
Để đạt hiệu năng $\mathcal{O}(1)$ khi thêm gói và $\mathcal{O}(K)$ khi kiểm tra:
* `_ip_ports`: `defaultdict(list)` lưu danh sách các bộ tuple `(timestamp, dst_port)` theo từng IP nguồn.
* `_ip_syn_packets`: `defaultdict(list)` lưu các mốc thời gian `timestamp` của các gói TCP SYN.
* `_ip_ack_packets`: `defaultdict(list)` lưu các mốc thời gian `timestamp` của các gói TCP ACK.
* `_ip_icmp_packets`: `defaultdict(list)` lưu các mốc thời gian `timestamp` của các gói ICMP.
* `_ip_udp_packets`: `defaultdict(list)` lưu các mốc thời gian `timestamp` của các gói UDP.

### 5.2. Thuật toán Cửa sổ trượt (Time-based Sliding Window)
Khi đánh giá một địa chỉ IP tại thời điểm hiện tại $T_{\text{now}}$ với cửa sổ thời gian $W = 5.0$ giây:
1. Mốc thời gian bắt đầu cửa sổ:
   $$T_{\text{start}} = T_{\text{now}} - W$$
2. **Loại bỏ phần tử hết hạn (Eviction):**
   Hệ thống lọc bỏ tất cả các bản ghi có $\text{timestamp} < T_{\text{start}}$. Vì dữ liệu được ghi theo thứ tự thời gian tăng dần, thao tác loại bỏ này diễn ra rất nhanh:
   ```python
   # Chỉ giữ lại các gói tin nằm trong khoảng [T_now - 5.0s, T_now]
   valid_records = [rec for rec in records if rec.timestamp >= cutoff_time]
   ```
3. **Tính toán đặc trưng:**
   * Số cổng đích duy nhất (Distinct Ports):
     $$\text{DistinctPorts} = \left| \{ \text{dst\_port} \mid (t, \text{dst\_port}) \in \text{valid\_records} \} \right|$$
   * Tần suất gói tin trên giây (Rate per second):
     $$\text{Rate} = \frac{\text{Số lượng bản ghi hợp lệ trong cửa sổ}}{W}$$

### 5.3. Thuật toán giải phóng bộ nhớ (Garbage Collection / Flow Cleanup)
Nếu hệ thống chạy liên tục nhiều ngày, số lượng IP lưu trong từ điển `defaultdict` sẽ tăng lên. `FlowEngine` định kỳ chạy hàm dọn dẹp: Các IP không có hoạt động nào trong vòng 60 giây gần nhất sẽ bị xóa hoàn toàn khỏi bộ nhớ, giải phóng 100% dung lượng RAM không cần thiết.

---

## 6. CHI TIẾT 4 THUẬT TOÁN PHÁT HIỆN XÂM NHẬP (DETECTION RULES)

*Thư mục cài đặt:* `detection/`

Hệ thống triển khai 4 bộ luật độc lập kế thừa từ lớp trừu tượng `BaseRule`:

### 6.1. Luật 1: Phát hiện Quét cổng (Port Scan Detection)
* *File:* `detection/port_scan.py`
* *Mức độ nghiêm trọng:* **`HIGH`**
* **Cơ sở toán học & Điều kiện kích hoạt:**
  Một gói tin $P$ được đưa vào đánh giá nếu thỏa mãn cờ TCP SYN hợp lệ:
  $$P.\text{protocol} = \text{"TCP"} \quad \land \quad P.\text{flags.SYN} = 1 \quad \land \quad P.\text{flags.ACK} = 0$$
  Hệ thống truy vấn số lượng cổng đích duy nhất mà IP nguồn đã kết nối trong 5.0 giây qua:
  $$\text{DistinctPorts}(P.\text{src\_ip}, W=5.0\text{s}) \ge \mathbf{15 \text{ cổng}}$$
* **Tại sao cờ SYN=1, ACK=0 lại quan trọng?**
  Kỹ thuật quét Stealth SYN Scan (như công cụ Nmap) chỉ gửi gói mở đầu SYN để xem cổng có phản hồi SYN-ACK hay không, sau đó lập tức gửi RST để hủy kết nối mà không hoàn tất bắt tay 3 bước. Bằng cách lọc đúng cờ này, hệ thống không bao giờ bị báo nhầm khi một ứng dụng hợp lệ gửi nhiều dữ liệu ACK trên các kết nối đã thiết lập.

---

### 6.2. Luật 2: Phát hiện TCP SYN Flood (DoS Attack)
* *File:* `detection/syn_flood.py`
* *Mức độ nghiêm trọng:* **`HIGH`**
* **Cơ sở toán học & Điều kiện kích hoạt:**
  SYN Flood là đòn tấn công gửi ồ ạt gói SYN nhưng cố tình không gửi gói ACK hoàn tất để làm tràn bảng hàng đợi bán mở (Half-open Connection / SYN Backlog Queue) của máy chủ nạn nhân.
  Luật kích hoạt khi đồng thời thỏa mãn 2 tiêu chí:
  $$\text{Tốc độ gói SYN} = \frac{\text{SYN\_Count}(P.\text{src\_ip}, W=5.0\text{s})}{5.0} \ge \mathbf{20.0 \text{ gói/giây}} \quad (\ge 100 \text{ gói / 5s})$$
  $$\text{Tỷ lệ bất đối xứng } \frac{\text{SYN\_Count}}{\max(1, \text{ACK\_Count})} \ge \mathbf{3.0}$$
* **Ý nghĩa:** Trong giao tiếp mạng bình thường, số gói SYN và ACK luôn cân bằng (tỷ lệ $\approx 1.0$). Khi tỷ lệ này vọt lên $> 3.0$ đi kèm tốc độ cao, đó là dấu hiệu chắc chắn của đòn tấn công từ chối dịch vụ SYN Flood.

---

### 6.3. Luật 3: Phát hiện ICMP Ping Flood
* *File:* `detection/icmp_flood.py`
* *Mức độ nghiêm trọng:* **`MEDIUM`**
* **Cơ sở toán học & Điều kiện kích hoạt:**
  Hệ thống chỉ đánh giá các gói tin ping thăm dò:
  $$P.\text{protocol} = \text{"ICMP"} \quad \land \quad P.\text{icmp\_type} = 8 \text{ (Echo Request)}$$
  Cảnh báo kích hoạt khi tốc độ gửi ping vượt ngưỡng:
  $$\text{ICMP\_Count}(P.\text{src\_ip}, W=5.0\text{s}) \ge \mathbf{40 \text{ gói / 5.0 giây}} \quad (\ge 8.0 \text{ gói/s})$$
* **Ý nghĩa:** Lệnh `ping` mặc định của Windows chỉ gửi đúng 1 gói/giây. Việc một IP gửi hàng chục gói ping/giây là hành vi cố tình làm nghẽn băng thông hoặc làm cạn kiệt tài nguyên xử lý ngắt của CPU máy đích.

---

### 6.4. Luật 4: Phát hiện UDP Flood
* *File:* `detection/udp_flood.py`
* *Mức độ nghiêm trọng:* **`MEDIUM`**
* **Cơ sở toán học & Điều kiện kích hoạt:**
  $$P.\text{protocol} = \text{"UDP"}$$
  $$\text{UDP\_Count}(P.\text{src\_ip}, W=5.0\text{s}) \ge \mathbf{80 \text{ gói / 5.0 giây}} \quad (\ge 16.0 \text{ gói/s})$$
* **Lưu ý thực tế (Bài học False Positive khi xem video):**
  Khi người dùng xem YouTube trên card Wi-Fi, giao thức HTTP/3 (QUIC chạy trên nền UDP cổng 443) có thể tải video với tốc độ hàng trăm gói UDP/s. Hiện tượng này giúp sinh viên giải trình xuất sắc về bản chất của **Dương tính giả (False Positive)** và đưa ra hướng phát triển: áp dụng kiểm tra độ phân tán ngẫu nhiên của cổng đích (Port Entropy) hoặc Whitelist cổng 443 trong tương lai.

---

## 7. THUẬT TOÁN QUẢN LÝ CẢNH BÁO & CƠ CHẾ COOLDOWN (ALERT MANAGER)

*File cài đặt:* `alert/manager.py`

### 7.1. Bài toán ngập lụt cảnh báo (Alert Fatigue Problem)
Nếu kẻ tấn công duy trì một đòn UDP Flood với 2.000 gói/giây trong suốt 10 giây:
* Nếu không có bộ lọc: Hệ thống sẽ sinh ra đúng $2000 \times 10 = 20.000$ cảnh báo!
* Hậu quả: Bảng web bị tràn, CPU bị nghẽn vì ghi file liên tục, người quản trị SOC hoàn toàn bị rối loạn không thể nhận biết được các sự kiện quan trọng khác.

### 7.2. Thuật toán Cooldown Khóa kép (Deduplication Algorithm)
* **Khóa nhận diện (Deduplication Key):**
  $$\text{Key} = (P.\text{src\_ip}, \text{attack\_type})$$
* **Lưu vết thời gian:** Hệ thống duy trì bảng băm `_last_alert_time: Dict[Key, float]`.
* **Quy trình quyết định:**
  ```python
  current_time = time.time()
  key = (alert.src_ip, alert.attack_type)

  if key in _last_alert_time:
      elapsed = current_time - _last_alert_time[key]
      if elapsed < cooldown_seconds (10.0 giây):
          # TRONG THỜI GIAN COOLDOWN:
          total_alerts_suppressed += 1  # Kìm hãm cảnh báo trùng lặp
          return None                   # Không phát tán cảnh báo ra ngoài!

  # HẾT COOLDOWN HOẶC ĐÒN ĐÁNH MỚI:
  _last_alert_time[key] = current_time
  total_alerts_emitted += 1
  alert.alert_id = generate_id()       # Cấp mã định danh chuẩn ALT-YYYYMMDD-XXXX
  return alert                         # Ghi vào file log và gửi lên Dashboard
  ```

---

## 8. KIẾN TRÚC LƯU TRỮ NHẬT KÝ & XOAY VÒNG DỮ LIỆU (FILE LOGGER & STORAGE)

*File cài đặt:* `storage/file_logger.py`

Hệ thống thiết lập cơ chế **Đồng bộ hóa Nhật ký Kép (Dual Logging System)** chuẩn công nghiệp:

### 8.1. Hai luồng file log độc lập
1. **`logs/alerts.jsonl` (Định dạng JSON Lines - Dành cho máy đọc):**
   * Mỗi cảnh báo lưu trên đúng 1 dòng JSON độc lập.
   * Chứa đầy đủ cấu trúc: `alert_id`, `timestamp` (chuẩn ISO 8601 UTC `...Z`), `attack_type`, `severity`, `src_ip`, `dst_ip`, `description`, và từ điển `evidence`.
   * Phù hợp để các hệ thống SIEM (Splunk, ElasticSearch/Kibana) nạp dữ liệu phân tích mà không cần phân tích chuỗi văn bản phức tạp.
2. **`logs/system.log` (Định dạng Văn bản Syslog - Dành cho người đọc):**
   * Lưu các sự kiện vận hành hệ thống (`[INFO]`) và **đồng bộ trực tiếp các cảnh báo an ninh**:
     * Cảnh báo `HIGH` (Port Scan, SYN Flood) $\rightarrow$ Ghi nhãn **`[ERROR]`**.
     * Cảnh báo `MEDIUM` (UDP, ICMP Flood) $\rightarrow$ Ghi nhãn **`[WARNING]`**.
   * Cú pháp dòng:
     `[Timestamp] [LEVEL] [ids.system]: [CANH BAO XAM NHAP - LOAI_DON] [MA_ALERT] Tu IP_Nguon -> IP_Dich | Mo_Ta`

### 8.2. Thuật toán Xoay vòng file (Log Rotation) & Chính sách lưu trữ (Retention Policy)
* Sử dụng `logging.handlers.RotatingFileHandler`.
* **Ngưỡng xoay vòng:** Khi file đạt kích thước **`maxBytes = 5 MB`**, file hiện tại được đổi tên thành `alerts.jsonl.1` và tạo file mới tinh để tiếp tục ghi. Tối đa lưu giữ **5 file backup** (`.1` đến `.5`).
* **Thuật toán Dọn dẹp tự động (`cleanup_logs`):**
  * Quét thư mục `logs/`: Xóa tất cả các file backup cũ đã vượt quá thời hạn **`retention_days = 90 ngày`**.
  * Nếu tổng dung lượng toàn bộ thư mục vượt quá **`max_total_bytes = 100 MB`**, hệ thống tự động xóa các file backup cũ nhất cho đến khi dung lượng hạ xuống mức an toàn.
  * **Quy tắc bất biến:** Tuyệt đối không bao giờ xóa 2 file chính đang mở (`system.log`, `alerts.jsonl`) để bảo đảm tiến trình Python trên Windows không bị lỗi khóa file (`PermissionError`).

---

## 9. CƠ CHẾ ĐO LƯỜNG CHỈ SỐ & TRUYỀN DỮ LIỆU THỜI GIAN THỰC (TELEMETRY & DASHBOARD)

*Thư mục cài đặt:* `core/ids_service.py` & `dashboard/`

### 9.1. Công thức đo lường các chỉ số thời gian thực
Cứ mỗi chu kỳ $\Delta t \ge 1.0$ giây, phương thức `get_telemetry()` tính toán:

1. **Tốc độ lưu lượng tức thời (Throughput - Packets Per Second):**
   $$\text{pps} = \frac{\text{total\_packets}(t) - \text{total\_packets}(t - \Delta t)}{\Delta t}$$
   Lịch sử 20 mốc pps gần nhất được lưu vào hàng đợi xoay vòng `collections.deque(maxlen=20)` để vẽ biểu đồ đường (Line Chart).

2. **Chỉ số Sức khỏe hàng đợi (Queue Health %):**
   $$\text{Queue Health} = \min\left(100, \text{Round}\left(\frac{\text{packet\_queue.qsize()}}{10.000} \times 100\right)\right)$$
   * Tỷ lệ $0\%$: Hệ thống lý tưởng, Consumer xử lý gói tức thời.
   * Tỷ lệ $> 50\%$: Hệ thống đang chịu tải nặng.
   * Tỷ lệ $100\%$: Xuất hiện `dropped_packets > 0` (kích hoạt chế độ tự bảo vệ).

3. **Tỷ trọng Giao thức mạng (Protocol Breakdown %):**
   $$\%_{\text{TCP}} = \frac{\text{TCP\_Packets}}{\text{Total\_Packets}} \times 100\% \quad ; \quad \%_{\text{UDP}} = \frac{\text{UDP\_Packets}}{\text{Total\_Packets}} \times 100\%$$

### 9.2. Cơ chế truyền thông Dashboard
* Backend: Flask REST API cung cấp các endpoint JSON:
  * `GET /api/status`: Trả về toàn bộ số liệu thống kê, throughput, trạng thái hàng đợi.
  * `GET /api/alerts`: Trả về danh sách cảnh báo có hỗ trợ lọc mức độ (`severity`) và tìm kiếm địa chỉ IP.
  * `GET /api/logs`: Trả về dòng sự kiện từ `system.log`.
  * `POST /api/control/start` & `POST /api/control/stop`: Điều khiển bật/tắt luồng bắt gói.
  * `POST /api/simulate`: Kích hoạt bộ sinh gói tin kiểm thử an toàn trên Localhost.
* Frontend: JavaScript phía Client thiết lập vòng lặp thăm dò `setInterval(updateStats, 1500)` định kỳ **1.5 giây**. Thời gian hiển thị cảnh báo được chuyển đổi tự động sang múi giờ thực tế của laptop sinh viên (`Date.toLocaleTimeString()` - GMT+7).

---

## 10. BẢNG THỐNG KÊ THAM SỐ TOÀN HỆ THỐNG (SYSTEM CONFIGURATION MATRIX)

Toàn bộ các tham số kỹ thuật được cấu hình tập trung trong file `config/config.json`:

| Phân hệ (Module) | Tham số (Parameter) | Giá trị mặc định | Ý nghĩa kỹ thuật |
| :--- | :--- | :---: | :--- |
| **Capture (Bắt gói)** | `interface` | `\Device\NPF_Loopback` | Tên card mạng mặc định (hỗ trợ chuyển Wi-Fi/Ethernet) |
| | `max_queue_size` | `10000` | Giới hạn hàng đợi Bounded Queue (chống tràn RAM) |
| | `bpf_filter` | `""` (Tất cả) | Bộ lọc Berkeley Packet Filter (hỗ trợ ip, tcp, udp...) |
| **Flow Engine** | `sliding_window_seconds` | `5.0` giây | Cửa sổ trượt lưu vết hành vi của các IP |
| | `flow_cleanup_interval` | `60.0` giây | Chu kỳ dọn dẹp các IP không còn hoạt động |
| **Detection Rules** | `port_scan.threshold` | `15` cổng | Số cổng đích duy nhất tối thiểu để kết luận Port Scan |
| | `syn_flood.threshold` | `100` gói / 5s | Ngưỡng gói SYN tối thiểu để kết luận DoS SYN Flood |
| | `syn_flood.syn_ack_ratio`| `3.0` | Tỷ lệ bất đối xứng giữa gói SYN và ACK |
| | `icmp_flood.threshold` | `40` gói / 5s | Ngưỡng gói Echo Request tối thiểu để kết luận ICMP Flood |
| | `udp_flood.threshold` | `80` gói / 5s | Ngưỡng gói UDP tối thiểu để kết luận UDP Flood |
| **Alert Manager** | `cooldown_seconds` | `10.0` giây | Thời gian kìm hãm cảnh báo trùng lặp (chống spam) |
| | `max_recent_alerts` | `200` bản ghi | Bộ nhớ đệm RAM lưu cảnh báo gần nhất cho web |
| **Storage (Lưu trữ)** | `max_bytes_per_file` | `5,242,880` (5 MB) | Kích thước tối đa của 1 file log trước khi xoay vòng |
| | `backup_count` | `5` file | Số lượng file sao lưu nén tối đa |
| | `retention_days` | `90` ngày | Thời hạn lưu trữ tối đa của file nhật ký |
| | `max_total_dir_size_mb` | `100` MB | Dung lượng tối đa của thư mục `logs/` |
| **Dashboard** | `host` | `127.0.0.1` | Địa chỉ mạng của Web Dashboard (cục bộ an toàn) |
| | `port` | `5000` | Cổng dịch vụ Web |
| | `polling_interval_ms` | `1500` ms (1.5s) | Chu kỳ làm mới dữ liệu biểu đồ và số liệu |

---

> [!TIP]
> **Hướng dẫn sử dụng tài liệu này khi bảo vệ đồ án:**
> * Các bạn có thể in tài liệu này hoặc sao chép các mục (Mục 2 đến Mục 8) đưa trực tiếp vào **Chương 3 (Thiết kế & Cài đặt hệ thống)** của Báo cáo đồ án PBL4.
> * Khi thầy cô hỏi về bất kỳ công thức, thuật toán nào (Cửa sổ trượt, Bounded Queue, Cooldown, cơ chế bắt gói Npcap), các bạn chỉ cần tra cứu đúng đề mục tương ứng trong tài liệu này để trả lời chuẩn xác 100%!

