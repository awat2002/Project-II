from __future__ import annotations
from collections import Counter
from datetime import datetime
from typing import Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange3",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}

class DisplayManager:

    def __init__(self) -> None:
        self.console = Console()

    def show_banner(self) -> None:
        banner = (
            "Anomaly Detection System\n"
            "Real-time log monitoring and anomaly alerting"
        )
        self.console.print(Panel.fit(banner, title="Analyst Tool", border_style="bright_blue"))

    def show_session_start(
        self,
        mode: str,
        log_files: list[str],
        thresholds: dict[str, dict[str, Any]],
        session_start: datetime,
    ) -> None:
        self.console.print(f"[bold green]Session started:[/bold green] {session_start.isoformat(timespec='seconds')}")
        self.console.print(f"[bold]Mode:[/bold] {mode}")

        files_table = Table(title="Monitored Log Files", show_header=True, header_style="bold white")
        files_table.add_column("Path", style="cyan")
        for log_file in log_files:
            files_table.add_row(log_file)
        self.console.print(files_table)

        threshold_table = Table(title="Active Thresholds", show_header=True, header_style="bold white")
        threshold_table.add_column("Anomaly", style="magenta")
        threshold_table.add_column("Threshold", style="white")

        failed = thresholds["failed_login_attempts"]
        login = thresholds["unusual_login_times"]
        high = thresholds["high_network_traffic"]
        ports = thresholds["repeated_port_connections"]
        large = thresholds["large_data_transfers"]

        threshold_table.add_row(
            "Failed login attempts",
            f"{failed['count']} in {failed['window_seconds']}s",
        )
        threshold_table.add_row(
            "Unusual login times",
            f"Outside {login['start_hour']:02d}:00-{login['end_hour']:02d}:00",
        )
        threshold_table.add_row(
            "High network traffic",
            f"{self._bytes_to_mb(high['bytes']):.2f} MB in {high['window_seconds']}s",
        )
        threshold_table.add_row(
            "Repeated port connections",
            f"{ports['count']} in {ports['window_seconds']}s",
        )
        threshold_table.add_row(
            "Large data transfers",
            f"{self._bytes_to_mb(large['bytes']):.2f} MB in {large['window_seconds']}s",
        )

        self.console.print(threshold_table)

    def show_anomaly(self, anomaly: dict[str, Any]) -> None:
        severity = anomaly["severity"]
        severity_style = SEVERITY_STYLE.get(severity, "white")
        anomaly_name = anomaly["anomaly_type"].replace("_", " ").title()

        table = Table(show_header=True, header_style="bold white")
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Type", style="magenta")
        table.add_column("Source", style="white")
        table.add_column("Indicator", style="white")

        table.add_row(
            anomaly["detected_at"],
            f"[{severity_style}]{severity}[/{severity_style}]",
            anomaly_name,
            anomaly["source_file"],
            anomaly["indicator"],
        )

        self.console.print(table)
        self.console.print(f"[dim]{anomaly['message']}[/dim]")

    def show_session_summary(
        self,
        anomalies: list[dict[str, Any]],
        session_start: datetime,
        session_end: datetime,
        json_report_path: str,
        csv_report_path: str,
    ) -> None:
        duration_seconds = int((session_end - session_start).total_seconds())
        severity_counter = Counter(item["severity"] for item in anomalies)
        anomaly_counter = Counter(item["anomaly_type"] for item in anomalies)

        summary_table = Table(title="Session Summary", show_header=True, header_style="bold white")
        summary_table.add_column("Field", style="cyan")
        summary_table.add_column("Value", style="white")
        summary_table.add_row("Session start", session_start.isoformat(timespec="seconds"))
        summary_table.add_row("Session end", session_end.isoformat(timespec="seconds"))
        summary_table.add_row("Duration", f"{duration_seconds} seconds")
        summary_table.add_row("Total anomalies", str(len(anomalies)))
        summary_table.add_row("JSON report", json_report_path)
        summary_table.add_row("CSV report", csv_report_path)
        self.console.print(summary_table)

        severity_table = Table(title="Severity Breakdown", show_header=True, header_style="bold white")
        severity_table.add_column("Severity", style="magenta")
        severity_table.add_column("Count", justify="right")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity_table.add_row(level, str(severity_counter.get(level, 0)))
        self.console.print(severity_table)

        anomaly_table = Table(title="Anomaly Type Breakdown", show_header=True, header_style="bold white")
        anomaly_table.add_column("Anomaly Type", style="magenta")
        anomaly_table.add_column("Count", justify="right")
        for anomaly_type, count in sorted(anomaly_counter.items()):
            anomaly_table.add_row(anomaly_type, str(count))
        if not anomaly_counter:
            anomaly_table.add_row("None", "0")
        self.console.print(anomaly_table)

    def show_error(self, message: str) -> None:
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def _bytes_to_mb(self, byte_count: int) -> float:
        return byte_count / (1024 * 1024)