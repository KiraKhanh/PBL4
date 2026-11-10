"""
Unit tests for AlertManager: ID generation, deduplication, and cooldown.
"""

import time
import pytest
from common.models import Alert
from alert.manager import AlertManager
from storage.file_logger import FileLogger


class TestAlertManager:

    def test_alert_processing_and_id_generation(self, tmp_path):
        logger = FileLogger(log_dir=str(tmp_path))
        manager = AlertManager(file_logger=logger, cooldown_seconds=10.0)

        raw_alert = Alert(
            alert_id="",
            timestamp="2026-10-23T00:00:00Z",
            attack_type="PORT_SCAN",
            severity="HIGH",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            description="Test alert"
        )

        emitted = manager.process_alert(raw_alert, now=1000.0)
        assert emitted is not None
        assert emitted.alert_id.startswith("ALT-")
        assert manager.total_alerts_emitted == 1
        assert manager.total_alerts_suppressed == 0
        logger.close()

    def test_alert_deduplication_within_cooldown(self, tmp_path):
        logger = FileLogger(log_dir=str(tmp_path))
        manager = AlertManager(file_logger=logger, cooldown_seconds=10.0)

        alert1 = Alert(
            alert_id="",
            timestamp="2026-10-23T00:00:00Z",
            attack_type="PORT_SCAN",
            severity="HIGH",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            description="Scan 1"
        )
        alert2 = Alert(
            alert_id="",
            timestamp="2026-10-23T00:00:03Z",
            attack_type="PORT_SCAN",
            severity="HIGH",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            description="Scan 2 (tiep dien)"
        )

        # Alert 1 phat vao giay 1000.0 -> thanh cong
        res1 = manager.process_alert(alert1, now=1000.0)
        assert res1 is not None

        # Alert 2 phat vao giay 1003.0 (trong cooldown 10s cua cung IP + type) -> bi chan (suppress)
        res2 = manager.process_alert(alert2, now=1003.0)
        assert res2 is None
        assert manager.total_alerts_suppressed == 1
        assert manager.total_alerts_emitted == 1

        # Alert 3 phat vao giay 1015.0 (sau khi cooldown 10s ket thuc) -> thanh cong
        alert3 = Alert(
            alert_id="",
            timestamp="2026-10-23T00:00:15Z",
            attack_type="PORT_SCAN",
            severity="HIGH",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            description="Scan 3 (dot moi)"
        )
        res3 = manager.process_alert(alert3, now=1015.0)
        assert res3 is not None
        assert manager.total_alerts_emitted == 2
        logger.close()

    def test_different_ips_or_attack_types_not_suppressed(self, tmp_path):
        logger = FileLogger(log_dir=str(tmp_path))
        manager = AlertManager(file_logger=logger, cooldown_seconds=10.0)

        # 2 IP khac nhau deu quet cong -> ca 2 phai duoc phat canh bao
        a1 = Alert("", "2026-10-23T00:00:00Z", "PORT_SCAN", "HIGH", "1.1.1.1", "1.1.1.2", "Scan IP1")
        a2 = Alert("", "2026-10-23T00:00:01Z", "PORT_SCAN", "HIGH", "2.2.2.2", "1.1.1.2", "Scan IP2")

        r1 = manager.process_alert(a1, now=1000.0)
        r2 = manager.process_alert(a2, now=1001.0)

        assert r1 is not None
        assert r2 is not None
        assert manager.total_alerts_emitted == 2
        logger.close()
