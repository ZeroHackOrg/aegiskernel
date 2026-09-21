# tests/test_aegiskernel.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegiskernel.cli.core import main
import pytest


def test_aegisk_test_command():
    code = main(["test"])
    assert code == 0