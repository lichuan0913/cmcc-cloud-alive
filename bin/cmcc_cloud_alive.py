#!/usr/bin/env python3
"""Compatibility wrapper for the split cmcc_cloud_alive package."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root_str = str(ROOT)
if root_str in sys.path:
    sys.path.remove(root_str)
sys.path.insert(0, root_str)

from cmcc_cloud_alive import core
from cmcc_cloud_alive.main import main


LEGACY_COMMANDS = {
    "password-login",
    "protocol-check",
    "cloud-status",
    "firm-auth",
    "heartbeat",
    "alive-once",
    "api-probe",
    "cag-https-connect",
    "analyze-session-capture",
    "source-audit",
    "state",
}


if __name__ == "__main__":
    cmd = next((arg for arg in sys.argv[1:] if not arg.startswith("-")), "")
    if cmd in LEGACY_COMMANDS:
        raise SystemExit(core.main())
    raise SystemExit(main())
