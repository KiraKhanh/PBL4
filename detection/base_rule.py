"""
Base Rule Interface for PBL4 Detection Engine.
"""

from abc import ABC, abstractmethod
from typing import Optional
from common.models import ParsedPacket, Alert
from features.flow_engine import FlowEngine


class BaseRule(ABC):
    """
    Interface truu tuong cho tat ca cac luat phat hien cua he thong IDS.
    Moi luat hoat dong doc lap, co nguong rieng va co the bat/tat qua cau hinh.
    """

    def __init__(self, name: str, enabled: bool = True, severity: str = "MEDIUM"):
        self.name = name
        self.enabled = enabled
        self.severity = severity

    @abstractmethod
    def evaluate(self, packet: ParsedPacket, flow_engine: FlowEngine, now: Optional[float] = None) -> Optional[Alert]:
        """
        Danh gia goi tin vua nhan cung cac dac trung tu FlowEngine.
        Neu thoa man dieu kien tan cong cua luat, tra ve Alert object.
        Neu khong thoa man, tra ve None.
        """
        pass
