from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from typing import Any

MONITORED_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
]

DEFAULT_THRESHOLDS = {
    "failed_login_attempts": {"count": 5, "window_seconds": 60},
    "unusual_login_times": {"start_hour": 6, "end_hour": 22},
    "high_network_traffic": {"bytes": 100 * 1024 * 1024, "window_seconds": 60},
    "repeated_port_connections": {"count": 10, "window_seconds": 30},
    "large_data_transfers": {"bytes": 500 * 1024 * 1024, "window_seconds": 3600},
}

SEVERITY_BY_ANOMALY = {
    "failed_login_attempts": "CRITICAL",
    "unusual_login_times": "CRITICAL",
    "repeated_port_connections": "HIGH",
    "high_network_traffic": "MEDIUM",
    "large_data_transfers": "MEDIUM",
    "general_suspicious_entries": "LOW",
}

OUTPUT_ROOT = Path(__file__).resolve().parent
APP_LOG_FILE = OUTPUT_ROOT / "logs" / "app.log"
JSON_REPORT_FILE = OUTPUT_ROOT / "reports" / "report.json"
CSV_REPORT_FILE = OUTPUT_ROOT / "reports" / "report.csv"

THRESHOLD_OVERRIDE_HELP = {
    "failed-logins": "Failed login attempt count in the active window",
    "failed-window": "Failed login window in seconds",
    "login-hours": "Allowed login hour range, formatted as start-end (e.g. 6-22)",
    "high-traffic-mb": "High network traffic threshold in MB",
    "high-traffic-window": "High network traffic window in seconds",
    "port-connections": "Repeated port connection count threshold",
    "port-window": "Repeated port connection window in seconds",
    "large-transfer-mb": "Large transfer threshold in MB",
    "large-transfer-window": "Large transfer window in seconds",
}

CLI_THRESHOLD_KEYS = tuple(THRESHOLD_OVERRIDE_HELP.keys())

def clone_default_thresholds() -> dict[str, dict[str, Any]]:
    return deepcopy(DEFAULT_THRESHOLDS)