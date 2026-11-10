"""
SYN Flood Detection Rule for PBL4 Network IDS.
----------------------------------------------
Muc tieu:
Phat hien toc do hoac so luong goi tin TCP SYN bat thuong tu mot nguon IP
trong mot cua so thoi gian ngan.

Co so lua chon dac trung:
- SYN Flood la hinh thuc tan cong DoS co dien, ke tan cong lien tuc gui cac goi tin
  khoi tao ket noi (SYN=1, ACK=0) toi muc tieu de lam tran bo dem backlog cua he dieu hanh.
- Rule chi dem cac goi TCP co SYN=1 va ACK=0 tu mot IP nguon trong sliding window.
- Khong tinh cac goi SYN-ACK (phan hoi tu server) hay ACK du lieu thong thuong.
- Nguong phat hien: mac dinh >= 100 goi SYN trong 5.0 giay (toc do >= 20 SYN/giay).
"""

from datetime import datetime, timezone
from typing import Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.base_rule import BaseRule


class SYNFloodRule(BaseRule):
    """
    Luat phat hien luu luong SYN bat thuong (SYN Flood DoS).
    """

    def __init__(
        self,
        enabled: bool = True,
        syn_rate_threshold: int = 100,
        time_window_seconds: float = 5.0,
        severity: str = "HIGH"
    ):
        super().__init__(name="SYN_FLOOD", enabled=enabled, severity=severity)
        self.threshold = syn_rate_threshold
        self.time_window = time_window_seconds

    def evaluate(self, packet: ParsedPacket, flow_engine: FlowEngine, now: Optional[float] = None) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Chi danh gia goi tin TCP SYN khoi tao (SYN=1, ACK=0)
        if packet.protocol != "TCP":
            return None

        if "SYN" not in packet.tcp_flags or "ACK" in packet.tcp_flags:
            return None

        # Dem tong so goi SYN ma IP nguon nay da gui trong cua so thoi gian
        syn_count = flow_engine.get_syn_count(packet.src_ip, now=now)

        if syn_count >= self.threshold:
            rate_per_sec = round(syn_count / self.time_window, 1)
            timestamp_str = datetime.now(timezone.utc).isoformat()
            alert_id = f"ALT-SYN-{int(now * 1000) if now else int(datetime.now().timestamp() * 1000)}"

            return Alert(
                alert_id=alert_id,
                timestamp=timestamp_str,
                attack_type=self.name,
                severity=self.severity,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=(
                    f"Phat hien luu luong SYN Flood: Gui {syn_count} goi SYN trong {self.time_window}s "
                    f"(Toc do: ~{rate_per_sec} SYN/s)"
                ),
                evidence={
                    "syn_packet_count": syn_count,
                    "rate_per_second": rate_per_sec,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window,
                    "target_port": packet.dst_port
                }
            )

        return None
