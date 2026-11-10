"""
ICMP Flood Detection Rule for PBL4 Network IDS.
-----------------------------------------------
Muc tieu:
Phat hien luu luong goi tin ICMP (Ping Flood) bat thuong trong mot cua so thoi gian.

Co so lua chon dac trung:
- ICMP thuong duoc su dung cho chuan doan mang (Echo Request / Reply qua lenh ping).
- Hoat dong ping binh thuong chi phat tu 1 den 4 goi tin voi do tre nhat dinh.
- Khi xay ra ICMP Flood DoS, ke tan cong gui hang chuc den hang tram goi tin ICMP
  voi tan suat cao de lam ngheo bang thong va tieu hao tai nguyen CPU cua muc tieu.
- Nguong phat hien: mac dinh >= 50 goi ICMP trong 5.0 giay.
"""

from datetime import datetime, timezone
from typing import Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.base_rule import BaseRule


class ICMPFloodRule(BaseRule):
    """
    Luat phat hien luu luong ICMP bat thuong (ICMP Ping Flood).
    """

    def __init__(
        self,
        enabled: bool = True,
        icmp_rate_threshold: int = 50,
        time_window_seconds: float = 5.0,
        severity: str = "MEDIUM"
    ):
        super().__init__(name="ICMP_FLOOD", enabled=enabled, severity=severity)
        self.threshold = icmp_rate_threshold
        self.time_window = time_window_seconds

    def evaluate(self, packet: ParsedPacket, flow_engine: FlowEngine, now: Optional[float] = None) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Chi danh gia goi tin giao thuc ICMP
        if packet.protocol != "ICMP":
            return None

        # Dem so goi ICMP tu IP nguon trong cua so thoi gian
        icmp_count = flow_engine.get_icmp_count(packet.src_ip, now=now)

        if icmp_count >= self.threshold:
            rate_per_sec = round(icmp_count / self.time_window, 1)
            timestamp_str = datetime.now(timezone.utc).isoformat()
            alert_id = f"ALT-ICMP-{int(now * 1000) if now else int(datetime.now().timestamp() * 1000)}"

            return Alert(
                alert_id=alert_id,
                timestamp=timestamp_str,
                attack_type=self.name,
                severity=self.severity,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=(
                    f"Phat hien luu luong ICMP Flood: Nhan {icmp_count} goi ICMP trong {self.time_window}s "
                    f"(Toc do: ~{rate_per_sec} ICMP/s)"
                ),
                evidence={
                    "icmp_packet_count": icmp_count,
                    "rate_per_second": rate_per_sec,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window
                }
            )

        return None
