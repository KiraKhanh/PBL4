"""
Detection Engine Module for PBL4 Network IDS.
--------------------------------------------
Trach nhiem:
1. Dieu phoi cac luat phat hien doc lap (BaseRule).
2. Nhan ParsedPacket va cap nhat vao FlowEngine.
3. Cho tung luat danh gia goi tin va dac trung luu luong.
4. Tra ve danh sach cac canh bao duoc sinh ra.
5. Hoan toan tach biet khoi Flask Web Dashboard va Logging I/O.
"""

from typing import List, Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine
from detection.base_rule import BaseRule
from detection.port_scan import PortScanRule


class DetectionEngine:
    """
    Bo phat hien trung tam cua he thong IDS.
    """

    def __init__(self, flow_engine: Optional[FlowEngine] = None):
        self.flow_engine = flow_engine or FlowEngine()
        self.rules: List[BaseRule] = []

    def add_rule(self, rule: BaseRule):
        """Dang ky mot luat phat hien vao he thong."""
        self.rules.append(rule)

    def process_packet(self, packet: ParsedPacket, now: Optional[float] = None) -> List[Alert]:
        """
        Xu ly 1 goi tin da chuan hoa:
        1. Cap nhat dac trung vao FlowEngine.
        2. Chay qua tat ca cac luat duoc kich hoat.
        3. Tra ve danh sach Alert sinh ra.
        """
        # 1. Cap nhat vao FlowEngine
        self.flow_engine.add_packet(packet, now=now)

        alerts: List[Alert] = []

        # 2. Danh gia qua cac luat
        for rule in self.rules:
            if not rule.enabled:
                continue
            alert = rule.evaluate(packet, self.flow_engine, now=now)
            if alert is not None:
                alerts.append(alert)

        return alerts
