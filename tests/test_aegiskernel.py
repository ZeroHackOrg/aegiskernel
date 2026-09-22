import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegiskernel.cli.core import main
from aegiskernel.engine import PolicyEngine
from aegiskernel.cli.webserver import TELEMETRY_LOGS
import pytest


def test_aegisk_test_command():
    code = main(["test"])
    assert code == 0


def test_policy_engine_rules():
    engine = PolicyEngine()
    # Test path pattern matching /tmp
    action, rule = engine.evaluate({"comm": "gcc", "filename": "/tmp/malware_exec"})
    assert action == "terminate"
    assert rule == "AEGIS-001"

    # Test safe path
    action, rule = engine.evaluate({"comm": "python3", "filename": "/usr/bin/python3"})
    assert action == "allow"


def test_telemetry_store():
    TELEMETRY_LOGS.clear()
    TELEMETRY_LOGS.append({"timestamp": 12345, "pid": 99, "uid": 0, "comm": "test", "action": "alert"})
    assert len(TELEMETRY_LOGS) == 1
    assert TELEMETRY_LOGS[0]["comm"] == "test"
