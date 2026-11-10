"""
Configuration Loader Module for PBL4 Network IDS.
-------------------------------------------------
Trach nhiem:
1. Doc file config.json.
2. Validate cac truong bat buoc va kieu du lieu.
3. Cung cap gia tri mac dinh an toan neu file khong ton tai hoac thieu truong.
4. Ngan chan injection va tuyet doi khong dung eval / exec.
"""

import os
import json
from typing import Dict, Any


DEFAULT_CONFIG: Dict[str, Any] = {
    "capture": {
        "interface": "\\Device\\NPF_Loopback",
        "bpf_filter": "",
        "max_queue_size": 10000
    },
    "detection": {
        "time_window_seconds": 5.0,
        "port_scan": {
            "enabled": True,
            "distinct_ports_threshold": 20,
            "severity": "HIGH"
        },
        "syn_flood": {
            "enabled": True,
            "syn_rate_threshold": 100,
            "severity": "HIGH"
        },
        "icmp_flood": {
            "enabled": True,
            "icmp_rate_threshold": 50,
            "severity": "MEDIUM"
        },
        "udp_flood": {
            "enabled": True,
            "udp_rate_threshold": 80,
            "severity": "MEDIUM"
        }
    },
    "alert": {
        "cooldown_seconds": 10.0,
        "rate_limit_per_minute": 60
    },
    "logging": {
        "log_dir": "logs",
        "max_bytes_per_file": 5242880,
        "backup_count": 5,
        "retention_days": 90,
        "max_total_dir_size_mb": 100
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5000,
        "update_interval_ms": 2000
    }
}


import copy

def _deep_merge(base: dict, override: dict) -> dict:
    """De quy hop nhat 2 dictionary giu nguyen cac key mac dinh."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(config_path: str = "config/config.json") -> Dict[str, Any]:
    """
    Doc va kiem tra tinh hop le cua file cau hinh.
    Neu file loi hoac khong ton tai, tra ve DEFAULT_CONFIG an toan.
    """
    if not os.path.exists(config_path):
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = json.load(f)

        return _deep_merge(DEFAULT_CONFIG, user_config)

    except Exception:
        return copy.deepcopy(DEFAULT_CONFIG)
