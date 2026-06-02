from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime
import logging
from typing import Any
from config import SEVERITY_BY_ANOMALY
from log_parser import ParsedLogEntry

class AnomalyAnalyzer:
    
    def __init__(self, thresholds: dict[str, dict[str, Any]], app_logger: logging.Logger) -> None:
        self.thresholds = thresholds
        self.logger = app_logger

        self.failed_login_events: dict[str, deque[datetime]] = defaultdict(deque)
        self.port_connection_events: dict[str, deque[datetime]] = defaultdict(deque)
        self.transfer_events: deque[tuple[datetime, int]] = deque()

        self.last_alert_at: dict[tuple[str, str], datetime] = {}

    def analyze_entry(self, entry: ParsedLogEntry) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        event_time = entry.timestamp

        anomalies.extend(self._detect_failed_logins(entry, event_time))
        anomalies.extend(self._detect_unusual_login_times(entry, event_time))
        anomalies.extend(self._detect_repeated_port_connections(entry, event_time))
        anomalies.extend(self._detect_network_transfer_anomalies(entry, event_time))

        if not anomalies and self._is_general_suspicious(entry):
            anomalies.append(
                self._build_anomaly(
                    anomaly_type="general_suspicious_entries",
                    entry=entry,
                    event_time=event_time,
                    indicator="Suspicious keyword pattern",
                    details={"event_type": entry.event_type},
                )
            )

        for anomaly in anomalies:
            self.logger.info(
                "Anomaly detected | type=%s | severity=%s | source=%s | indicator=%s",
                anomaly["anomaly_type"],
                anomaly["severity"],
                anomaly["source_file"],
                anomaly["indicator"],
            )

        return anomalies

    def _detect_failed_logins(self, entry: ParsedLogEntry, event_time: datetime) -> list[dict[str, Any]]:
        if entry.event_type != "failed_login":
            return []

        rule = self.thresholds["failed_login_attempts"]
        key = entry.src_ip or entry.username or "unknown"
        events = self.failed_login_events[key]

        self._append_and_prune(events, event_time, rule["window_seconds"])

        if len(events) < rule["count"]:
            return []
        if not self._should_emit("failed_login_attempts", key, event_time, rule["window_seconds"]):
            return []

        indicator = f"{len(events)} failed logins from {key} in {rule['window_seconds']}s"
        return [
            self._build_anomaly(
                anomaly_type="failed_login_attempts",
                entry=entry,
                event_time=event_time,
                indicator=indicator,
                details={"source": key, "count": len(events), "window_seconds": rule["window_seconds"]},
            )
        ]

    def _detect_unusual_login_times(self, entry: ParsedLogEntry, event_time: datetime) -> list[dict[str, Any]]:
        if entry.event_type != "successful_login":
            return []

        rule = self.thresholds["unusual_login_times"]
        start_hour = int(rule["start_hour"])
        end_hour = int(rule["end_hour"])
        hour = event_time.hour

        if self._is_hour_in_allowed_range(hour, start_hour, end_hour):
            return []

        indicator = f"Login observed at {hour:02d}:00 outside {start_hour:02d}-{end_hour:02d}"
        return [
            self._build_anomaly(
                anomaly_type="unusual_login_times",
                entry=entry,
                event_time=event_time,
                indicator=indicator,
                details={
                    "allowed_hours": f"{start_hour}-{end_hour}",
                    "observed_hour": hour,
                    "username": entry.username,
                },
            )
        ]

    def _detect_repeated_port_connections(
        self,
        entry: ParsedLogEntry,
        event_time: datetime,
    ) -> list[dict[str, Any]]:
        if entry.dst_port is None:
            return []

        rule = self.thresholds["repeated_port_connections"]
        key = f"{entry.src_ip or 'unknown'}:{entry.dst_port}"
        events = self.port_connection_events[key]

        self._append_and_prune(events, event_time, rule["window_seconds"])

        if len(events) < rule["count"]:
            return []
        if not self._should_emit("repeated_port_connections", key, event_time, rule["window_seconds"]):
            return []

        indicator = (
            f"{len(events)} connections from {entry.src_ip or 'unknown'} "
            f"to port {entry.dst_port} in {rule['window_seconds']}s"
        )
        return [
            self._build_anomaly(
                anomaly_type="repeated_port_connections",
                entry=entry,
                event_time=event_time,
                indicator=indicator,
                details={
                    "source": entry.src_ip,
                    "destination_port": entry.dst_port,
                    "count": len(events),
                    "window_seconds": rule["window_seconds"],
                },
            )
        ]

    def _detect_network_transfer_anomalies(
        self,
        entry: ParsedLogEntry,
        event_time: datetime,
    ) -> list[dict[str, Any]]:
        if entry.bytes_count <= 0:
            return []

        anomalies: list[dict[str, Any]] = []

        high_rule = self.thresholds["high_network_traffic"]
        large_rule = self.thresholds["large_data_transfers"]

        max_window_seconds = max(high_rule["window_seconds"], large_rule["window_seconds"])
        self.transfer_events.append((event_time, entry.bytes_count))
        self._prune_transfer_events(event_time, max_window_seconds)

        high_bytes = self._sum_transfer_bytes(event_time, high_rule["window_seconds"])
        if high_bytes >= high_rule["bytes"] and self._should_emit(
            "high_network_traffic", "global", event_time, high_rule["window_seconds"]
        ):
            indicator = f"{self._bytes_to_mb(high_bytes):.2f} MB in {high_rule['window_seconds']}s"
            anomalies.append(
                self._build_anomaly(
                    anomaly_type="high_network_traffic",
                    entry=entry,
                    event_time=event_time,
                    indicator=indicator,
                    details={
                        "total_bytes": high_bytes,
                        "window_seconds": high_rule["window_seconds"],
                    },
                )
            )

        large_bytes = self._sum_transfer_bytes(event_time, large_rule["window_seconds"])
        if large_bytes >= large_rule["bytes"] and self._should_emit(
            "large_data_transfers", "global", event_time, large_rule["window_seconds"]
        ):
            indicator = f"{self._bytes_to_mb(large_bytes):.2f} MB in {large_rule['window_seconds']}s"
            anomalies.append(
                self._build_anomaly(
                    anomaly_type="large_data_transfers",
                    entry=entry,
                    event_time=event_time,
                    indicator=indicator,
                    details={
                        "total_bytes": large_bytes,
                        "window_seconds": large_rule["window_seconds"],
                    },
                )
            )

        return anomalies

    def _append_and_prune(self, events: deque[datetime], timestamp: datetime, window_seconds: int) -> None:
        events.append(timestamp)
        while events and (timestamp - events[0]).total_seconds() > window_seconds:
            events.popleft()

    def _prune_transfer_events(self, now: datetime, max_window_seconds: int) -> None:
        while self.transfer_events and (now - self.transfer_events[0][0]).total_seconds() > max_window_seconds:
            self.transfer_events.popleft()

    def _sum_transfer_bytes(self, now: datetime, window_seconds: int) -> int:
        total = 0
        for timestamp, byte_count in reversed(self.transfer_events):
            if (now - timestamp).total_seconds() > window_seconds:
                break
            total += byte_count
        return total

    def _should_emit(
        self,
        anomaly_type: str,
        key: str,
        event_time: datetime,
        cooldown_seconds: int,
    ) -> bool:
        alert_key = (anomaly_type, key)
        last_alert_time = self.last_alert_at.get(alert_key)
        if last_alert_time and (event_time - last_alert_time).total_seconds() < cooldown_seconds:
            return False

        self.last_alert_at[alert_key] = event_time
        return True

    def _build_anomaly(
        self,
        anomaly_type: str,
        entry: ParsedLogEntry,
        event_time: datetime,
        indicator: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        severity = SEVERITY_BY_ANOMALY.get(anomaly_type, "LOW")

        return {
            "detected_at": event_time.isoformat(timespec="seconds"),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "source_file": entry.source_file,
            "indicator": indicator,
            "message": entry.message,
            "raw_line": entry.raw_line,
            "details": details,
        }

    def _is_hour_in_allowed_range(self, hour: int, start_hour: int, end_hour: int) -> bool:
        if start_hour <= end_hour:
            return start_hour <= hour <= end_hour
        return hour >= start_hour or hour <= end_hour

    def _is_general_suspicious(self, entry: ParsedLogEntry) -> bool:
        if entry.event_type == "suspicious":
            return True

        suspicious_keywords = (
            "multiple failures",
            "tamper",
            "escalation",
            "forbidden",
            "malicious",
        )
        message_lower = entry.message.lower()
        return any(keyword in message_lower for keyword in suspicious_keywords)

    def _bytes_to_mb(self, byte_count: int) -> float:
        return byte_count / (1024 * 1024)