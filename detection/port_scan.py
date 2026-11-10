"""
Port Scan Detection Rule for PBL4 Network IDS.
----------------------------------------------
Muc tieu:
Phat hien nguon IP tiep can nhieu cong dich khac nhau trong mot khoang thoi gian ngan.

Nguyen tac phat hien:
- Chi xet cac goi tin TCP co thong tin cong dich.
- Tinh so luong cong dich DUY NHAT (distinct destination ports) ma IP nguon da gui den.
- Phat canh bao khi so cong khac nhau >= distinct_ports_threshold trong cua so thoi gian.
- Tuyet doi KHONG chi dem tong so goi tin de ket luan la quet cong.
"""

from datetime import datetime, timezone
from typing import Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.base_rule import BaseRule


class PortScanRule(BaseRule):
    """
    Luat phat hien Port Scan dua tren nguong so cong dich duy nhat.
    """

    def __init__(
        self,
        enabled: bool = True,
        distinct_ports_threshold: int = 20,
        time_window_seconds: float = 5.0,
        severity: str = "HIGH"
    ):
        super().__init__(name="PORT_SCAN", enabled=enabled, severity=severity)
        self.threshold = distinct_ports_threshold
        self.time_window = time_window_seconds

    def evaluate(self, packet: ParsedPacket, flow_engine: FlowEngine, now: Optional[float] = None) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Chi danh gia goi tin TCP co port dich va la goi SYN khoi tao ket noi (SYN=1, ACK=0)
        # Khong danh gia cac goi ACK, RST hoac PSH data
        if packet.protocol != "TCP" or packet.dst_port is None:
            return None

        if "SYN" not in packet.tcp_flags or "ACK" in packet.tcp_flags:
            return None

        # Lay danh sach cac cong dich duy nhat tu FlowEngine
        distinct_ports = flow_engine.get_distinct_ports(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            now=now,
            syn_only=True
        )

        distinct_count = len(distinct_ports)

        # Kiem tra nguong
        if distinct_count >= self.threshold:
            # Mau mot vai cong de hien thi trong evidence
            ports_sample = sorted(list(distinct_ports))[:10]
            total_pkts = flow_engine.get_packet_count(packet.src_ip, now=now)

            timestamp_str = datetime.now(timezone.utc).isoformat()
            alert_id = f"ALT-PS-{int(now * 1000) if now else int(datetime.now().timestamp() * 1000)}"

            return Alert(
                alert_id=alert_id,
                timestamp=timestamp_str,
                attack_type=self.name,
                severity=self.severity,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Phat hien hanh vi quet cong: Tiep can {distinct_count} cong dich khac nhau trong {self.time_window} giay",
                evidence={
                    "distinct_ports_count": distinct_count,
                    "ports_sample": ports_sample,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window,
                    "packet_count": total_pkts
                }
            )

        return None
