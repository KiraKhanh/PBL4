"""
Unit tests for configuration loading and validation.
"""

import os
import json
import tempfile
import pytest

from config.config_loader import load_config, DEFAULT_CONFIG


def test_load_default_config_when_file_not_found():
    cfg = load_config("non_existent_file.json")
    assert cfg["capture"]["max_queue_size"] == 10000
    assert cfg["detection"]["port_scan"]["enabled"] is True


def test_load_custom_config(tmp_path):
    custom_cfg_file = tmp_path / "custom.json"
    data = {
        "detection": {
            "time_window_seconds": 10.0,
            "port_scan": {
                "distinct_ports_threshold": 30
            }
        }
    }
    with open(custom_cfg_file, "w") as f:
        json.dump(data, f)

    cfg = load_config(str(custom_cfg_file))
    assert cfg["detection"]["time_window_seconds"] == 10.0
    assert cfg["detection"]["port_scan"]["distinct_ports_threshold"] == 30
    # Gia tri khong ghi de phai duoc giu nguyen tu default
    assert cfg["detection"]["port_scan"]["severity"] == "HIGH"
    assert cfg["logging"]["retention_days"] == 90
