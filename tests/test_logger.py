"""
Unit tests for FileLogger module: rotation, JSONL alerts, and cleanup.
"""

import os
import time
import json
import tempfile
import pytest

from storage.file_logger import FileLogger


class TestFileLogger:

    @pytest.fixture
    def temp_log_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_logger_creates_directory_and_writes_system_log(self, temp_log_dir):
        logger = FileLogger(log_dir=temp_log_dir)
        try:
            logger.log_info("Khoi dong he thong thu nghiem")
            
            system_log_file = os.path.join(temp_log_dir, "system.log")
            assert os.path.exists(system_log_file)
            
            with open(system_log_file, "r", encoding="utf-8") as f:
                content = f.read()
                assert "Khoi dong he thong thu nghiem" in content
                assert "[INFO]" in content
        finally:
            logger.close()

    def test_write_and_read_alerts_jsonl(self, temp_log_dir):
        logger = FileLogger(log_dir=temp_log_dir)
        try:
            alert_sample = {
                "alert_id": "ALT-001",
                "attack_type": "PORT_SCAN",
                "severity": "HIGH",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "description": "Quet cong 127.0.0.1",
                "evidence": {"distinct_ports": 25}
            }
            
            success = logger.write_alert(alert_sample)
            assert success is True
            
            alerts_file = os.path.join(temp_log_dir, "alerts.jsonl")
            assert os.path.exists(alerts_file)
            
            recent = logger.read_recent_alerts(limit=10)
            assert len(recent) == 1
            assert recent[0]["alert_id"] == "ALT-001"
            assert recent[0]["attack_type"] == "PORT_SCAN"
        finally:
            logger.close()

    def test_log_rotation_on_size_limit(self, temp_log_dir):
        # Dat max_bytes rat nho (300 bytes) de kich hoat rotation nhanh
        logger = FileLogger(log_dir=temp_log_dir, max_bytes=300, backup_count=3)
        try:
            for i in range(20):
                logger.write_alert({"id": i, "data": "A" * 50})
                
            alerts_file = os.path.join(temp_log_dir, "alerts.jsonl")
            alerts_backup = os.path.join(temp_log_dir, "alerts.jsonl.1")
            
            assert os.path.exists(alerts_file)
            # File backup .1 phai duoc tao ra do xoay vong
            assert os.path.exists(alerts_backup)
        finally:
            logger.close()

    def test_cleanup_logs_retention_and_protection_of_active_files(self, temp_log_dir):
        logger = FileLogger(log_dir=temp_log_dir, retention_days=1, max_total_dir_size_mb=1)
        try:
            logger.log_info("Active system log")
            logger.write_alert({"test": "active alert"})
            
            # Tao mot file backup cu gia lap (qua 2 ngay truoc)
            old_backup_file = os.path.join(temp_log_dir, "system.log.1")
            with open(old_backup_file, "w", encoding="utf-8") as f:
                f.write("OLD_DATA")
            
            # Dat st_mtime lui ve 3 ngay truoc
            old_time = time.time() - (3 * 86400)
            os.utime(old_backup_file, (old_time, old_time))
            
            # Chay don dep
            cleanup_result = logger.cleanup_logs()
            
            # File cu phai bi xoa
            assert "system.log.1" in cleanup_result["deleted_files"]
            assert not os.path.exists(old_backup_file)
            
            # File active khong bao gio bi xoa
            assert os.path.exists(os.path.join(temp_log_dir, "system.log"))
            assert os.path.exists(os.path.join(temp_log_dir, "alerts.jsonl"))
        finally:
            logger.close()

    def test_filtered_alerts_and_system_logs(self, temp_log_dir):
        logger = FileLogger(log_dir=temp_log_dir)
        try:
            # Ghi 3 alerts voi muc do khac nhau va IP khac nhau
            logger.write_alert({"alert_id": "1", "severity": "HIGH", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
            logger.write_alert({"alert_id": "2", "severity": "MEDIUM", "src_ip": "192.168.1.5", "dst_ip": "192.168.1.1"})
            logger.write_alert({"alert_id": "3", "severity": "HIGH", "src_ip": "172.16.0.10", "dst_ip": "172.16.0.1"})

            # Loc theo severity HIGH
            high_alerts = logger.read_recent_alerts(limit=10, severity_filter="HIGH")
            assert len(high_alerts) == 2
            assert all(a["severity"] == "HIGH" for a in high_alerts)

            # Loc theo search IP "192.168"
            ip_alerts = logger.read_recent_alerts(limit=10, search_ip="192.168")
            assert len(ip_alerts) == 1
            assert ip_alerts[0]["src_ip"] == "192.168.1.5"

            # Ghi system logs
            logger.log_info("Info message 1")
            logger.log_warning("Warning message 2")
            logger.log_error("Error message 3")

            # Doc system logs co loc (bao gom 2 alert HIGH va 1 log_error thu cong)
            err_logs = logger.read_system_logs(limit=10, level_filter="ERROR")
            assert len(err_logs) == 3
            assert any("Error message 3" in log for log in err_logs)

            # Kiem tra storage stats
            stats = logger.get_storage_stats()
            assert stats["file_count"] >= 2
            assert stats["total_size_bytes"] > 0
        finally:
            logger.close()
