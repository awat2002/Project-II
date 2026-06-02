from __future__ import annotations
import csv
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any
from config import CSV_REPORT_FILE, JSON_REPORT_FILE

CSV_COLUMNS = [
    "detected_at",
    "anomaly_type",
    "severity",
    "source_file",
    "indicator",
    "message",
    "raw_line",
    "details",
]

def generate_reports(
    anomalies: list[dict[str, Any]],
    session_metadata: dict[str, Any],
    json_report_path: Path | str = JSON_REPORT_FILE,
    csv_report_path: Path | str = CSV_REPORT_FILE,
    app_logger: logging.Logger | None = None,
) -> tuple[str, str]:
    json_path = Path(json_report_path)
    csv_path = Path(csv_report_path)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    severity_counts = Counter(anomaly["severity"] for anomaly in anomalies)
    type_counts = Counter(anomaly["anomaly_type"] for anomaly in anomalies)

    payload = {
        "session": session_metadata,
        "totals": {
            "anomalies": len(anomalies),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
        },
        "anomalies": anomalies,
    }

    with json_path.open("w", encoding="utf-8") as json_file:
        json.dump(payload, json_file, indent=2)

    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for anomaly in anomalies:
            writer.writerow(
                {
                    "detected_at": anomaly.get("detected_at", ""),
                    "anomaly_type": anomaly.get("anomaly_type", ""),
                    "severity": anomaly.get("severity", ""),
                    "source_file": anomaly.get("source_file", ""),
                    "indicator": anomaly.get("indicator", ""),
                    "message": anomaly.get("message", ""),
                    "raw_line": anomaly.get("raw_line", ""),
                    "details": json.dumps(anomaly.get("details", {}), sort_keys=True),
                }
            )

    if app_logger:
        app_logger.info("JSON report generated at %s", json_path)
        app_logger.info("CSV report generated at %s", csv_path)

    return str(json_path), str(csv_path)