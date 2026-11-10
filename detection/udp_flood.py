"""
UDP Flood Detection Rule for PBL4 Network IDS.
----------------------------------------------
Muc tieu:
Phat hien luu luong goi tin UDP bat thuong (UDP Flood DoS) trong mot cua so thoi gian.

Co so lua chon dac trung:
- UDP la giao thuc khong huong ket noi (connectionless), khong can bat tay 3 buoc.
- Ke tan cong thuong gia mao hoac phat hang loat goi tin UDP toi cac cong ngau nhien
  hoac dich vu DNS/NTP/SNMP de tieu hao tai nguyen xu ly cua he thong.
- Rule theo doi so luong goi tin UDP tu mot IP nguon trong sliding window.
- Nguong phat hien: mac dinh >= 80 goi UDP trong 5.0 giay.
"""

from datetime import datetime, timezone
from typing import Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.base_rule import BaseRule


class UDPFloodRule(BaseRule):
    """
    Luat phat hien luu luong UDP bat thuong (UDP Flood DoS).
    """

    def __init__(
        self,
        enabled: bool = True,
        udp_rate_threshold: int = 80,
        time_window_seconds: float = 5.0,
        severity: str = "MEDIUM"
    ):
        super().__init__(name="UDP_FLOOD", enabled=enabled, severity=severity)
        self.threshold = udp_rate_threshold
        self.time_window = time_window_seconds

    def evaluate(self, packet: ParsedPacket, flow_engine: FlowEngine, now: Optional[float] = None) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Chi danh gia goi tin UDP
        if packet.protocol != "UDP":
            return None

        # Dem so goi UDP tu IP nguon trong cua so thoi gian
        udp_count = flow_engine.get_udp_count(packet.src_ip, now=now)

        if udp_count >= self.threshold:
            rate_per_sec = round(udp_count / self.time_window, 1)
            timestamp_str = datetime.now(timezone.utc).isoformat()
            alert_id = f"ALT-UDP-{int(now * 1000) if now else int(datetime.now().timestamp() * 1000)}"

            return Alert(
                alert_id=alert_id,
                timestamp=timestamp_str,
                attack_type=self.name,
                severity=self.severity,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=(
                    f"Phat hien luu luong UDP Flood: Gui {udp_count} goi UDP trong {self.time_window}s "
                    f"(Toc do: ~{rate_per_sec} UDP/s)"
                ),
                evidence={
                    "udp_packet_count": udp_count,
                    "rate_per_second": rate_per_sec,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window,
                    "target_port": packet.dst_port
                }
            )

        return None
