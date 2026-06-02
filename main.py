from __future__ import annotations
import argparse
from datetime import datetime
import sys
from typing import Any
from analyzer import AnomalyAnalyzer
from config import CLI_THRESHOLD_KEYS, MONITORED_LOG_FILES, THRESHOLD_OVERRIDE_HELP, clone_default_thresholds
from display import DisplayManager
from log_monitor import LogMonitor
from log_parser import LogParser
from logger import setup_app_logger
from reporter import generate_reports

THRESHOLD_SPEC = {
    "failed-logins": ("failed_login_attempts", "count", "int"),
    "failed-window": ("failed_login_attempts", "window_seconds", "int"),
    "login-hours": ("unusual_login_times", ("start_hour", "end_hour"), "hour-range"),
    "high-traffic-mb": ("high_network_traffic", "bytes", "mb"),
    "high-traffic-window": ("high_network_traffic", "window_seconds", "int"),
    "port-connections": ("repeated_port_connections", "count", "int"),
    "port-window": ("repeated_port_connections", "window_seconds", "int"),
    "large-transfer-mb": ("large_data_transfers", "bytes", "mb"),
    "large-transfer-window": ("large_data_transfers", "window_seconds", "int"),
}

def build_argument_parser() -> argparse.ArgumentParser:
    threshold_help = "\n".join(f"  {key}: {description}" for key, description in THRESHOLD_OVERRIDE_HELP.items())

    parser = argparse.ArgumentParser(
        description="focused real-time anomaly detection for Linux log files.",
        epilog=f"Threshold override keys:\n{threshold_help}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--threshold",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override thresholds (repeatable). Example: --threshold failed-logins=10",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Optional session duration in seconds. If omitted, runs until interrupted.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="Fallback polling interval in seconds for new line checks.",
    )
    return parser

def apply_threshold_overrides(
    thresholds: dict[str, dict[str, Any]],
    overrides: list[str],
) -> None:
    for override in overrides:
        if "=" not in override:
            raise ValueError(f"Invalid threshold override format: {override}")

        key, value = override.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key not in THRESHOLD_SPEC:
            raise ValueError(f"Unknown threshold key: {key}. Available keys: {', '.join(CLI_THRESHOLD_KEYS)}")

        section, setting, value_type = THRESHOLD_SPEC[key]

        if value_type == "int":
            parsed_value = int(value)
            if parsed_value <= 0:
                raise ValueError(f"{key} must be a positive integer")
            thresholds[section][setting] = parsed_value
            continue

        if value_type == "mb":
            parsed_value = float(value)
            if parsed_value <= 0:
                raise ValueError(f"{key} must be greater than zero")
            thresholds[section][setting] = int(parsed_value * 1024 * 1024)
            continue

        if value_type == "hour-range":
            start_hour, end_hour = parse_hour_range(value)
            start_key, end_key = setting
            thresholds[section][start_key] = start_hour
            thresholds[section][end_key] = end_hour
            continue

        raise ValueError(f"Unsupported threshold value type: {value_type}")

def parse_hour_range(value: str) -> tuple[int, int]:
    if "-" not in value:
        raise ValueError("login-hours must be in start-end format, e.g. 6-22")

    start_text, end_text = value.split("-", 1)
    start_hour = int(start_text)
    end_hour = int(end_text)

    if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
        raise ValueError("login-hours values must be between 0 and 23")

    return start_hour, end_hour

def run_interactive_menu() -> tuple[list[str], list[str], int | None, float]:
    print("\nInteractive configuration mode")
    print("Press Enter to keep defaults.")

    log_files = list(MONITORED_LOG_FILES)

    threshold_overrides: list[str] = []
    customize_thresholds = input("Override thresholds for this session? [y/N]: ").strip().lower()

    if customize_thresholds in ("y", "yes"):
        defaults = clone_default_thresholds()
        prompts = [
            ("failed-logins", "Failed login count", str(defaults["failed_login_attempts"]["count"])),
            ("failed-window", "Failed login window seconds", str(defaults["failed_login_attempts"]["window_seconds"])),
            (
                "login-hours",
                "Allowed login hours start-end",
                f"{defaults['unusual_login_times']['start_hour']}-{defaults['unusual_login_times']['end_hour']}",
            ),
            ("high-traffic-mb", "High network traffic MB", str(defaults["high_network_traffic"]["bytes"] // (1024 * 1024))),
            (
                "high-traffic-window",
                "High network traffic window seconds",
                str(defaults["high_network_traffic"]["window_seconds"]),
            ),
            (
                "port-connections",
                "Repeated port connection count",
                str(defaults["repeated_port_connections"]["count"]),
            ),
            (
                "port-window",
                "Repeated port connection window seconds",
                str(defaults["repeated_port_connections"]["window_seconds"]),
            ),
            (
                "large-transfer-mb",
                "Large transfer MB",
                str(defaults["large_data_transfers"]["bytes"] // (1024 * 1024)),
            ),
            (
                "large-transfer-window",
                "Large transfer window seconds",
                str(defaults["large_data_transfers"]["window_seconds"]),
            ),
        ]

        for key, label, default_value in prompts:
            user_value = input(f"{label} [{default_value}]: ").strip()
            if user_value:
                threshold_overrides.append(f"{key}={user_value}")

    duration_input = input("Optional session duration in seconds (Enter for manual stop): ").strip()
    duration_seconds: int | None = None
    if duration_input:
        try:
            parsed_duration = int(duration_input)
            if parsed_duration > 0:
                duration_seconds = parsed_duration
            else:
                print("Invalid duration value. Using manual stop mode.")
        except ValueError:
            print("Invalid duration value. Using manual stop mode.")

    poll_input = input("Polling interval in seconds [0.5]: ").strip()
    poll_interval = 0.5
    if poll_input:
        try:
            parsed_poll = float(poll_input)
            if parsed_poll > 0:
                poll_interval = parsed_poll
            else:
                print("Invalid poll interval. Using default 0.5s.")
        except ValueError:
            print("Invalid poll interval. Using default 0.5s.")

    return log_files, threshold_overrides, duration_seconds, poll_interval

def main() -> int:
    interactive_mode = len(sys.argv) == 1

    if interactive_mode:
        log_files, threshold_inputs, duration_seconds, poll_interval = run_interactive_menu()
        execution_mode = "INTERACTIVE"
    else:
        parser = build_argument_parser()
        args = parser.parse_args()
        log_files = list(MONITORED_LOG_FILES)
        threshold_inputs = args.threshold
        duration_seconds = args.duration
        poll_interval = args.poll_interval
        execution_mode = "CLI"

    thresholds = clone_default_thresholds()
    display = DisplayManager()
    app_logger = setup_app_logger()

    try:
        apply_threshold_overrides(thresholds, threshold_inputs)
    except ValueError as exc:
        display.show_error(str(exc))
        app_logger.error("Invalid threshold override: %s", exc)
        return 1

    parser_engine = LogParser()
    analyzer_engine = AnomalyAnalyzer(thresholds=thresholds, app_logger=app_logger)
    anomalies: list[dict[str, Any]] = []

    def handle_anomaly(anomaly: dict[str, Any]) -> None:
        anomalies.append(anomaly)
        display.show_anomaly(anomaly)

    monitor = LogMonitor(
        log_files=log_files,
        parser=parser_engine,
        analyzer=analyzer_engine,
        app_logger=app_logger,
        on_anomaly=handle_anomaly,
        poll_interval=poll_interval,
    )

    session_start = datetime.now()
    display.show_banner()
    display.show_session_start(execution_mode, log_files, thresholds, session_start)
    app_logger.info(
        "Session started | mode=%s | logs=%s | thresholds=%s",
        execution_mode,
        ",".join(log_files),
        thresholds,
    )

    session_error: str | None = None

    try:
        monitor.start(duration_seconds=duration_seconds)
    except KeyboardInterrupt:
        display.console.print("[bold yellow]Stopping monitoring session...[/bold yellow]")
    except Exception as exc:
        session_error = str(exc)
        display.show_error(f"Monitoring session failed: {exc}")
        app_logger.exception("Monitoring session failed: %s", exc)
    finally:
        session_end = datetime.now()

        session_metadata = {
            "mode": execution_mode,
            "start_time": session_start.isoformat(timespec="seconds"),
            "end_time": session_end.isoformat(timespec="seconds"),
            "monitored_logs": log_files,
            "active_thresholds": thresholds,
            "session_error": session_error,
        }

        json_report_path, csv_report_path = generate_reports(
            anomalies=anomalies,
            session_metadata=session_metadata,
            app_logger=app_logger,
        )

        display.show_session_summary(
            anomalies=anomalies,
            session_start=session_start,
            session_end=session_end,
            json_report_path=json_report_path,
            csv_report_path=csv_report_path,
        )

        app_logger.info(
            "Session ended | total_anomalies=%s | error=%s",
            len(anomalies),
            session_error,
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())