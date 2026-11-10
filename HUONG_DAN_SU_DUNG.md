# HƯỚNG DẪN KHỞI ĐỘNG & VẬN HÀNH THỦ CÔNG DỰ ÁN PBL4
## HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (NIDS) TRÊN WINDOWS 11

> **Mục đích tài liệu**: Hướng dẫn chi tiết từng bước cho sinh viên tự khởi động, vận hành và kiểm thử dự án bằng tay sau này mà **không cần bất kỳ sự hỗ trợ tự động nào từ trợ lý AI**, tự tin 100% khi lên máy giảng đường để demo trước Hội đồng bảo vệ.

---

## MỤC LỤC
1. [Cách 1: Khởi động 1-Click nhanh nhất (Khuyên dùng khi bảo vệ)](#1-cách-1-khởi-động-1-click-nhanh-nhất-khuyên-dùng-khi-bảo-vệ)
2. [Cách 2: Khởi động thủ công từng bước bằng Terminal](#2-cách-2-khởi-động-thủ-công-từng-bước-bằng-terminal)
3. [Quy trình thao tác & Demo trên Web Dashboard](#3-quy-trình-thao-tác--demo-trên-web-dashboard)
4. [Kịch bản kiểm thử độc lập bằng Terminal thứ 2 (Đóng vai kẻ tấn công)](#4-kịch-bản-kiểm-thử-độc-lập-bằng-terminal-thứ-2-đóng-vai-kẻ-tấn-công)
5. [Kịch bản kiểm thử bằng 2 máy tính qua mạng Wi-Fi](#5-kịch-bản-kiểm-thử-bằng-2-máy-tính-qua-mạng-wi-fi)
6. [Chạy bộ kiểm thử tự động (43/43 Tests)](#6-chạy-bộ-kiểm-thử-tự-động-4343-tests)
7. [Bảng tra cứu xử lý sự cố thường gặp (Troubleshooting)](#7-bảng-tra-cứu-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 1. CÁCH 1: KHỞI ĐỘNG 1-CLICK NHANH NHẤT (KHUYÊN DÙNG KHI BẢO VỆ)

Nhóm đã tích hợp sẵn file thực thi tự động. Bạn không cần gõ bất kỳ câu lệnh nào:

1. Mở thư mục dự án `D:\C++\PBL4` trên Windows File Explorer.
2. **Nhấp đúp chuột vào file**: **`start_dashboard.bat`**
3. **Hiện tượng**:
   - Một cửa sổ dòng lệnh màu đen hiện lên thông báo máy chủ đang chạy.
   - Trình duyệt mặc định của máy tính (Chrome/Edge) sẽ **tự động bật lên** và mở sẵn trang web: **`http://127.0.0.1:5000`**.
4. **Để tắt hệ thống**: Chỉ cần quay lại cửa sổ dòng lệnh đen đó và nhấn tổ hợp phím **`Ctrl + C`** (hoặc bấm dấu `X` tắt cửa sổ).

---

## 2. CÁCH 2: KHỞI ĐỘNG THỦ CÔNG TỪNG BƯỚC BẰNG TERMINAL

Nếu bạn muốn thao tác chuyên nghiệp bằng Terminal trong Antigravity IDE hoặc VS Code:

### Bước 1: Mở Terminal tích hợp trong IDE
- Nhấn tổ hợp phím **`Ctrl + ~`** (phím dấu ngã / huyền cạnh số 1 trên bàn phím).
- Hoặc trên thanh menu trên cùng: Chọn **`Terminal`** $\rightarrow$ **`New Terminal`**.
- *Lưu ý*: Dòng nhắc lệnh sẽ tự động đứng đúng tại thư mục: `PS D:\C++\PBL4>`.

### Bước 2: Gõ lệnh khởi chạy máy chủ
Gõ lệnh sau và nhấn Enter:
```powershell
.\.venv\bin\python.exe main.py
```
*(Nếu sau này chuyển sang máy dùng Windows Python chuẩn thì lệnh là: `.\.venv\Scripts\python.exe main.py`)*.

Khi terminal hiển thị:
```text
======================================================================
   PBL4 NETWORK IDS - WEB DASHBOARD DANG CHAY TAI:
   http://127.0.0.1:5000
======================================================================
 * Running on http://127.0.0.1:5000
```
Nghĩa là máy chủ đã sẵn sàng 100%!

### Bước 3: Mở trình duyệt Web
Mở Chrome hoặc Edge và gõ địa chỉ: **`http://127.0.0.1:5000`**

---

## 3. QUY TRÌNH THAO TÁC & DEMO TRÊN WEB DASHBOARD

Khi giao diện Dashboard đã mở:

1. **Chọn Card mạng (Interface)**:
   - Trên thanh điều khiển trên cùng, tại ô dropdown **Interface**:
     - Nếu test trên 1 máy laptop: Chọn **`Software Loopback (Localhost 127.0.0.1)`**.
     - Nếu bắt gói tin từ máy khác trong mạng LAN: Chọn **`Wi-Fi`** hoặc **`Ethernet`**.
2. **Bắt đầu giám sát**:
   - Bấm nút **`Start IDS`**.
   - Đèn trạng thái chuyển sang xanh lá **`RUNNING`**.
   - Biểu đồ Throughput bắt đầu vẽ lưu lượng thời gian thực.
3. **Thực hiện các bài test tấn công 1-Click (Các nút màu vàng)**:
   - Bấm nút **`Port Scan`**: Bắn 25 kết nối TCP SYN quét cổng $\rightarrow$ Xuất hiện cảnh báo `PORT_SCAN` mức `HIGH`.
   - Bấm nút **`SYN Flood`**: Phát 120 gói SYN DoS dồn dập $\rightarrow$ Biểu đồ vọt lên đỉnh nhọn, xuất hiện cảnh báo `SYN_FLOOD`.
   - Bấm nút **`ICMP Flood`**: Bão gói ICMP Ping $\rightarrow$ Xuất hiện cảnh báo `ICMP_FLOOD`.
   - Bấm nút **`UDP Flood`**: Bão gói tin UDP $\rightarrow$ Biểu đồ tròn đổi sang màu vàng cam, xuất hiện cảnh báo `UDP_FLOOD`.
   - Bấm nút **`Normal Traffic`** *(Kiểm thử âm tính)*: Gửi 15 gói tin bình thường $\rightarrow$ Bộ đếm gói tin tăng nhưng **0 cảnh báo nào sinh ra** (chứng minh hệ thống không báo động giả).
4. **Xem bằng chứng kỹ thuật (Evidence)**:
   - Bấm nút **`Xem chi tiết`** ở cột cuối cùng của bất kỳ dòng cảnh báo nào $\rightarrow$ Modal popup hiển thị cấu trúc JSON đầy đủ (danh sách cổng quét, tốc độ pps, số gói tin, thời gian).
5. **Dọn sạch dữ liệu để làm lại (Reset)**:
   - Bấm nút **`Reset`** (ở thanh trên cùng) hoặc nút **`Xóa lịch sử`** (ở tab cảnh báo):
   - Hệ thống xóa sạch toàn bộ các dòng cũ, đưa bộ đếm về 0 để bạn bắt đầu đợt demo tiếp theo.
6. **Dừng giám sát**:
   - Bấm nút đỏ **`Stop IDS`** khi muốn kết thúc phiên giám sát.

---

## 4. KỊCH BẢN KIỂM THỬ ĐỘC LẬP BẰNG TERMINAL THỨ 2 (ĐÓNG VAI KẺ TẤN CÔNG)

Nếu bạn muốn chứng minh cho Thầy/Cô thấy kẻ tấn công sử dụng công cụ độc lập từ bên ngoài:

- **Cửa sổ Terminal 1**: Đang chạy Web Dashboard (`python main.py`).
- **Mở thêm Cửa sổ Terminal 2**:
  - Nhấn dấu **`+`** ở góc trên bên phải khung Terminal để mở tab thứ 2.
  - Gõ các lệnh tấn công tùy chọn:
    ```powershell
    # 1. Tấn công quét cổng (Port Scan 25 cổng)
    .\.venv\bin\python.exe simulator/traffic_generator.py --mode scan --ports 25

    # 2. Tấn công SYN Flood (120 gói SYN)
    .\.venv\bin\python.exe simulator/traffic_generator.py --mode syn --count 120

    # 3. Tấn công ICMP Ping Flood (60 gói Ping)
    .\.venv\bin\python.exe simulator/traffic_generator.py --mode icmp --count 60

    # 4. Tấn công UDP Flood (100 gói UDP)
    .\.venv\bin\python.exe simulator/traffic_generator.py --mode udp --count 100

    # 5. Lưu lượng bình thường (Negative test)
    .\.venv\bin\python.exe simulator/traffic_generator.py --mode normal --count 15
    ```

---

## 5. KỊCH BẢN KIỂM THỬ BẰNG 2 MÁY TÍNH QUA MẠNG WI-FI

Khi mang 2 máy tính lên phòng bảo vệ (Máy A chạy IDS, Máy B đóng vai Hacker):

1. Cả 2 máy cùng kết nối vào một mạng Wi-Fi (hoặc phát Wi-Fi từ điện thoại).
2. **Trên Máy A (Máy chạy IDS)**:
   - Mở PowerShell gõ `ipconfig` để lấy địa chỉ IP Wi-Fi (ví dụ: `192.168.1.25`).
   - Mở Dashboard `http://127.0.0.1:5000` $\rightarrow$ Chọn Interface **`Wi-Fi`** $\rightarrow$ Bấm **`Start IDS`**.
3. **Trên Máy B (Máy tấn công)**:
   - Copy file `traffic_generator.py` sang máy B và chạy:
     ```powershell
     python traffic_generator.py --target 192.168.1.25 --mode scan --ports 25
     python traffic_generator.py --target 192.168.1.25 --mode syn --count 120
     ```
   - Hoặc nếu dùng Kali Linux:
     ```bash
     nmap -sS -p 1-100 192.168.1.25
     ```
4. **Kết quả**: Dashboard trên Máy A lập tức ghi nhận IP nguồn là địa chỉ IP của Máy B!

---

## 6. CHẠY BỘ KIỂM THỬ TỰ ĐỘNG (43/43 TESTS)

Để chứng minh chất lượng kiểm thử phần mềm trước Hội đồng:
- **Cách nhanh**: Nhấp đúp chuột vào file **`run_tests.bat`**.
- **Hoặc gõ trong Terminal**:
  ```powershell
  .\.venv\bin\python.exe -m pytest -v
  ```
Toàn bộ 43 bài test sẽ chạy và in ra màu xanh lá cây **`100% PASSED`** trong khoảng 14 giây.

---

## 7. BẢNG TRA CỨU XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

| Hiện tượng / Báo lỗi | Nguyên nhân gốc | Cách khắc phục trong 30 giây |
| :--- | :--- | :--- |
| **`Address already in use`** (Port 5000 bị chiếm) | Lần chạy trước bạn tắt Terminal nhưng tiến trình Python chưa kịp giải phóng cổng 5000. | Chạy lệnh đổi sang cổng khác: `.\.venv\bin\python.exe main.py --port 5050` rồi truy cập `http://127.0.0.1:5050`. |
| **`The term '.\.venv\bin\python.exe' is not recognized`** | Terminal đang đứng ở thư mục khác (ví dụ `C:\WINDOWS\system32`) chứ không phải ở `D:\C++\PBL4`. | Gõ lệnh chuyển thư mục: `cd D:\C++\PBL4` rồi chạy lại lệnh. |
| **Bấm Start IDS báo lỗi không bắt được gói tin** | Dịch vụ Npcap trong Windows chưa được bật. | Mở PowerShell quyền Admin gõ: `net start npcap` để bật lại dịch vụ. |
| **Bấm Port Scan nhưng không hiện cảnh báo thứ 2** | Cơ chế Cooldown 10 giây chống spam đang hoạt động (hiện ở thẻ *suppressed*). | Đợi đủ 10 giây rồi bấm lại; hoặc bấm thử nút tấn công khác như `SYN Flood`. |
| **Trình duyệt hiện giao diện cũ** | Trình duyệt Chrome/Edge lưu cache giao diện. | Bấm tổ hợp phím **`Ctrl + F5`** trên bàn phím để xóa sạch cache. |
