"""
Alert Manager Module for PBL4 Network IDS.
-----------------------------------------
Trach nhiem:
1. Quan ly vong doi cac canh bao (Alert Lifecycle).
2. Chong tao canh bao trung lap (Alert Deduplication & Cooldown):
   - Tranh sinh hang chuc canh bao lien tuc cho cung mot cuoc quet cong dang dien ra.
   - Ap dung cooldown theo cap (src_ip, attack_type).
3. Gioi han toc do sinh canh bao (Rate Limiting).
4. Tu dong sinh Alert ID duy nhat: ALT-YYYYMMDD-XXXX.
5. Ghi canh bao da duoc loc vao FileLogger (alerts.jsonl).
"""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from common.models import Alert
from storage.file_logger import FileLogger


class AlertManager:
    """
    Quan ly va dieu phoi cac canh bao an ninh cua IDS.
    """

    def __init__(
        self,
        file_logger: Optional[FileLogger] = None,
        cooldown_seconds: float = 10.0,
        rate_limit_per_minute: int = 60
    ):
        self.file_logger = file_logger
        self.cooldown_seconds = cooldown_seconds
        self.rate_limit_per_minute = rate_limit_per_minute

        # Map: (src_ip, attack_type) -> timestamp_epoch cuoi cung phat canh bao
        self._last_alert_time: Dict[Tuple[str, str], float] = {}
        
        # Bo dem thong ke
        self.total_alerts_received = 0
        self.total_alerts_emitted = 0
        self.total_alerts_suppressed = 0
        self._sequence_counter = 0

        # Bo nho dem gan nhat (In-memory buffer) cho Dashboard
        self.recent_alerts: List[Dict[str, Any]] = []
        self.max_recent_buffer = 100

    def _generate_alert_id(self) -> str:
        """Sinh ma canh bao duy nhat co tinh thu tu: ALT-YYYYMMDD-XXXX."""
        self._sequence_counter += 1
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"ALT-{date_str}-{self._sequence_counter:04d}"

    def process_alert(self, alert: Alert, now: Optional[float] = None) -> Optional[Alert]:
        """
        Kiem tra va xu ly 1 canh bao:
        - Neu vi pham cooldown: chan canh bao (suppress).
        - Neu vuot qua kiem tra: gan Alert ID, ghi log alerts.jsonl va luu vao recent buffer.
        """
        current_time = now if now is not None else time.time()
        self.total_alerts_received += 1

        key = (alert.src_ip, alert.attack_type)
        last_time = self._last_alert_time.get(key, 0.0)

        # 1. Kiem tra Cooldown (chong spam canh bao trung)
        if current_time - last_time < self.cooldown_seconds:
            self.total_alerts_suppressed += 1
            return None

        # 2. Cap nhat thoi gian phat canh bao
        self._last_alert_time[key] = current_time

        # 3. Gan ID chuan
        alert.alert_id = self._generate_alert_id()
        self.total_alerts_emitted += 1

        alert_dict = alert.to_dict()

        # 4. Ghi file alerts.jsonl qua FileLogger
        if self.file_logger:
            self.file_logger.write_alert(alert_dict)

        # 5. Luu vao cache gan nhat cho Dashboard
        self.recent_alerts.append(alert_dict)
        if len(self.recent_alerts) > self.max_recent_buffer:
            self.recent_alerts.pop(0)

        return alert

    def get_summary(self) -> Dict[str, Any]:
        """Tra ve thong ke tong the ve canh bao."""
        return {
            "total_received": self.total_alerts_received,
            "total_emitted": self.total_alerts_emitted,
            "total_suppressed": self.total_alerts_suppressed,
            "recent_count": len(self.recent_alerts)
        }

    def reset(self):
        """Xoa trang cac bo dem va danh sach canh bao tam thoi."""
        self.total_alerts_received = 0
        self.total_alerts_emitted = 0
        self.total_alerts_suppressed = 0
        self._sequence_counter = 0
        self._last_alert_time.clear()
        self.recent_alerts.clear()
