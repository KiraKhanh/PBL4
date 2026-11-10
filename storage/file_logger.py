"""
File Logger Module for PBL4 Network IDS.
---------------------------------------
Trach nhiem:
1. Su dung module logging chuan cua Python va RotatingFileHandler.
2. Tach biet nhat ky van hanh (system.log) va nhat ky canh bao (alerts.jsonl).
3. Tu dong xoay vong file (Log Rotation) theo dung luong (mac dinh 5MB, toi da 5 file).
4. Co che don dep file log theo thoi gian (mac dinh 90 ngay) va tong dung luong thu muc (mac dinh 100MB).
5. Ghi thoi gian theo ISO 8601, an toan tuyet doi, khong ghi de hoac lam crash ung dung.
"""

import os
import json
import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List


class FileLogger:
    """
    Quan ly he thong nhat ky file cua IDS voi tinh nang xoay vong va don dep tu dong.
    """

    def __init__(
        self,
        log_dir: str = "logs",
        max_bytes: int = 5 * 1024 * 1024,  # 5 MB moi file
        backup_count: int = 5,              # Giu toi da 5 file backup
        max_total_dir_size_mb: int = 100,   # Tong dung luong thu muc toi da 100MB
        retention_days: int = 90            # Giu file toi da 90 ngay
    ):
        self._lock = threading.Lock()
        self.log_dir = os.path.abspath(log_dir)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.max_total_bytes = max_total_dir_size_mb * 1024 * 1024
        self.retention_seconds = retention_days * 86400

        # Dam bao thu muc logs ton tai
        os.makedirs(self.log_dir, exist_ok=True)

        self.system_log_path = os.path.join(self.log_dir, "system.log")
        self.alerts_log_path = os.path.join(self.log_dir, "alerts.jsonl")

        # Dung logger name rieng de tranh xung dot singleton giua cac instance va unit test
        instance_id = hex(id(self))
        self.system_logger_name = f"ids.system.{instance_id}"
        self.alerts_logger_name = f"ids.alerts.{instance_id}"

        self.system_handler: Optional[RotatingFileHandler] = None
        self.alerts_handler: Optional[RotatingFileHandler] = None

        self.system_logger = self._setup_system_logger()
        self.alerts_logger = self._setup_alerts_logger()

    def _setup_system_logger(self) -> logging.Logger:
        """Thiet lap logger van hanh he thong (dinh dang text co timestamp ISO 8601)."""
        logger = logging.getLogger(self.system_logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.handlers.clear()

        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z"
        )

        # Handler xoay vong file
        self.system_handler = RotatingFileHandler(
            filename=self.system_log_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        self.system_handler.setFormatter(formatter)
        logger.addHandler(self.system_handler)

        return logger

    def _setup_alerts_logger(self) -> logging.Logger:
        """Thiet lap logger canh bao (dinh dang JSON Lines, 1 record/dong)."""
        logger = logging.getLogger(self.alerts_logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.handlers.clear()

        formatter = logging.Formatter(fmt="%(message)s")

        self.alerts_handler = RotatingFileHandler(
            filename=self.alerts_log_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        self.alerts_handler.setFormatter(formatter)
        logger.addHandler(self.alerts_handler)

        return logger

    def close(self):
        """Dong cac file handlers de giai phong tai nguyen va file lock tren Windows."""
        for handler in [self.system_handler, self.alerts_handler]:
            if handler:
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass
        logging.getLogger(self.system_logger_name).handlers.clear()
        logging.getLogger(self.alerts_logger_name).handlers.clear()

    def log_info(self, message: str):
        """Ghi nhat ky thong tin van hanh."""
        try:
            self.system_logger.info(message)
        except Exception:
            pass

    def log_warning(self, message: str):
        """Ghi nhat ky canh bao van hanh."""
        try:
            self.system_logger.warning(message)
        except Exception:
            pass

    def log_error(self, message: str):
        """Ghi nhat ky loi he thong."""
        try:
            self.system_logger.error(message)
        except Exception:
            pass

    def write_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Ghi 1 ban ghi canh bao vao alerts.jsonl (JSON Lines cho may doc)
        va dong thoi ghi mot dong nhat ky ro rang vao system.log (cho quan tri vien doc).
        Tra ve True neu ghi thanh cong.
        """
        try:
            # 1. Dam bao co timestamp hop le
            if "timestamp" not in alert_data:
                alert_data["timestamp"] = datetime.now(timezone.utc).isoformat()

            json_line = json.dumps(alert_data, ensure_ascii=False)
            self.alerts_logger.info(json_line)

            # 2. Dong thoi ghi thong tin canh bao vao system.log
            alert_id = alert_data.get("alert_id", "N/A")
            attack_type = alert_data.get("attack_type", "UNKNOWN")
            severity = str(alert_data.get("severity", "MEDIUM")).upper()
            src_ip = alert_data.get("src_ip", "0.0.0.0")
            dst_ip = alert_data.get("dst_ip", "0.0.0.0")
            desc = alert_data.get("description", "")

            msg = f"[CANH BAO XAM NHAP - {attack_type}] [{alert_id}] Tu IP {src_ip} -> {dst_ip} | {desc}"

            if severity == "HIGH":
                self.system_logger.error(msg)
            elif severity == "MEDIUM":
                self.system_logger.warning(msg)
            else:
                self.system_logger.info(msg)

            return True
        except Exception as e:
            self.log_error(f"Khong the ghi alert vao log: {e}")
            return False

    def read_recent_alerts(
        self,
        limit: int = 50,
        severity_filter: Optional[str] = None,
        search_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Doc N ban ghi canh bao gan nhat tu alerts.jsonl, co ho tro loc theo severity va search IP.
        """
        alerts: List[Dict[str, Any]] = []
        if not os.path.exists(self.alerts_log_path):
            return alerts

        try:
            with open(self.alerts_log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    # Ap dung bo loc neu co
                    if severity_filter and severity_filter.upper() != "ALL":
                        if record.get("severity", "").upper() != severity_filter.upper():
                            continue
                    if search_ip:
                        ip_lower = search_ip.lower()
                        src = record.get("src_ip", "").lower()
                        dst = record.get("dst_ip", "").lower()
                        if ip_lower not in src and ip_lower not in dst:
                            continue

                    alerts.append(record)
                    if len(alerts) >= limit:
                        break
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            self.log_error(f"Loi khi doc recent alerts: {e}")

        return alerts

    def read_system_logs(self, limit: int = 50, level_filter: Optional[str] = None) -> List[str]:
        """
        Doc N dong nhat ky he thong gan nhat tu system.log, co the loc theo muc level (INFO, WARNING, ERROR).
        """
        log_lines: List[str] = []
        if not os.path.exists(self.system_log_path):
            return log_lines

        try:
            with open(self.system_log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                if level_filter and level_filter.upper() != "ALL":
                    if f"[{level_filter.upper()}]" not in line:
                        continue
                log_lines.append(line)
                if len(log_lines) >= limit:
                    break
        except Exception as e:
            self.log_error(f"Loi khi doc system.log: {e}")

        return log_lines

    def get_storage_stats(self) -> Dict[str, Any]:
        """Tra ve thong ke dung luong va so luong file log trong thu muc."""
        total_size = 0
        file_count = 0
        files_info = []

        try:
            if os.path.exists(self.log_dir):
                for entry in os.scandir(self.log_dir):
                    if entry.is_file():
                        stat = entry.stat()
                        total_size += stat.st_size
                        file_count += 1
                        files_info.append({
                            "name": entry.name,
                            "size_bytes": stat.st_size,
                            "size_kb": round(stat.st_size / 1024, 2),
                            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                        })
        except Exception:
            pass

        return {
            "log_dir": self.log_dir,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "max_total_mb": round(self.max_total_bytes / (1024 * 1024), 2),
            "file_count": file_count,
            "retention_days": self.retention_seconds // 86400,
            "files": files_info
        }

    def cleanup_logs(self) -> Dict[str, Any]:
        """
        Don dep cac file log luu tru theo 2 tieu chi:
        1. Xoa file log luu tru da vuot qua thoi han retention_days (90 ngay).
        2. Neu tong dung luong thu muc logs vuot max_total_bytes (100MB),
           xoa cac file backup cu nhat (.1, .2, ...) cho den khi duoi nguong.
        Luu y: KHONG bao gio xoa file dang hoat dong (system.log, alerts.jsonl).
        """
        current_time = time.time()
        deleted_files: List[str] = []
        active_files = {os.path.abspath(self.system_log_path), os.path.abspath(self.alerts_log_path)}

        try:
            # 1. Kiem tra va don file het han
            log_files = []
            for entry in os.scandir(self.log_dir):
                if entry.is_file() and entry.path not in active_files:
                    # Chi quan ly cac file log backup cua ung dung
                    if entry.name.startswith("system.log.") or entry.name.startswith("alerts.jsonl."):
                        stat = entry.stat()
                        age = current_time - stat.st_mtime
                        if age > self.retention_seconds:
                            try:
                                os.remove(entry.path)
                                deleted_files.append(entry.name)
                            except OSError:
                                pass
                        else:
                            log_files.append((entry.path, stat.st_size, stat.st_mtime))

            # 2. Kiem tra tong dung luong thu muc
            total_size = sum(f[1] for f in log_files)
            for active_file in active_files:
                if os.path.exists(active_file):
                    total_size += os.path.getsize(active_file)

            # Neu vuot nguong tong dung luong, xoa file luu tru cu nhat
            if total_size > self.max_total_bytes:
                # Sap xep file luu tru theo mtime tang dan (cu nhat truoc)
                log_files.sort(key=lambda x: x[2])
                for path, size, _ in log_files:
                    if total_size <= self.max_total_bytes:
                        break
                    try:
                        os.remove(path)
                        total_size -= size
                        deleted_files.append(os.path.basename(path))
                    except OSError:
                        pass

            return {
                "deleted_count": len(deleted_files),
                "deleted_files": deleted_files,
                "current_total_bytes": total_size
            }
        except Exception as e:
            self.log_error(f"Loi trong qua trinh don dep log: {e}")
            return {"error": str(e)}

    def clear_alerts(self):
        """Xoa sach toan bo file alerts.jsonl."""
        with self._lock:
            try:
                if self.alerts_handler:
                    self.alerts_handler.flush()
                with open(self.alerts_log_path, "w", encoding="utf-8") as f:
                    f.truncate(0)
            except Exception as e:
                self.log_error(f"Khong the lam sach file alerts.jsonl: {e}")
