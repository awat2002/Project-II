from __future__ import annotations
import os
import threading
import time
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from analyzer import AnomalyAnalyzer
from log_parser import LogParser

AnomalyCallback = Callable[[dict[str, Any]], None]

def _normalize_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))

class _LogFileEventHandler(FileSystemEventHandler):
    
    def __init__(self, monitor: "LogMonitor") -> None:
        self.monitor = monitor

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.monitor.process_file(event.src_path)

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.monitor.process_file(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.monitor.process_file(event.dest_path)

class LogMonitor:

    def __init__(
        self,
        log_files: list[str],
        parser: LogParser,
        analyzer: AnomalyAnalyzer,
        app_logger: logging.Logger,
        on_anomaly: AnomalyCallback | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        if not log_files:
            raise ValueError("At least one log file path is required.")

        self.parser = parser
        self.analyzer = analyzer
        self.app_logger = app_logger
        self.on_anomaly = on_anomaly
        self.poll_interval = poll_interval

        self.monitored_files = {_normalize_path(path): path for path in log_files}
        self.file_offsets: dict[str, int] = {path: 0 for path in self.monitored_files}

        self._observer = Observer()
        self._handler = _LogFileEventHandler(self)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def start(self, duration_seconds: int | None = None) -> None:
        self._stop_event.clear()
        self._initialize_offsets()
        self._schedule_directories()

        self._observer.start()
        started_at = time.monotonic()

        try:
            while not self._stop_event.is_set():
                self.scan_all_files()
                if duration_seconds is not None and (time.monotonic() - started_at) >= duration_seconds:
                    break
                time.sleep(self.poll_interval)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()

        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)

    def process_file(self, file_path: str) -> None:
        normalized_path = _normalize_path(file_path)
        if normalized_path not in self.monitored_files:
            return

        with self._lock:
            self._read_new_lines(normalized_path)

    def scan_all_files(self) -> None:
        for normalized_path in self.monitored_files:
            self.process_file(normalized_path)

    def _initialize_offsets(self) -> None:
        for normalized_path in self.monitored_files:
            if os.path.exists(normalized_path):
                self.file_offsets[normalized_path] = os.path.getsize(normalized_path)
            else:
                self.file_offsets[normalized_path] = 0
                self.app_logger.warning("Log file not found at startup: %s", normalized_path)

    def _schedule_directories(self) -> None:
        directories = {str(Path(path).parent) for path in self.monitored_files}
        for directory in directories:
            if os.path.isdir(directory):
                self._observer.schedule(self._handler, directory, recursive=False)
            else:
                self.app_logger.warning("Log directory is not accessible: %s", directory)

    def _read_new_lines(self, normalized_path: str) -> None:
        if not os.path.exists(normalized_path):
            return

        try:
            current_size = os.path.getsize(normalized_path)
            previous_offset = self.file_offsets.get(normalized_path, 0)

            if current_size < previous_offset:
                previous_offset = 0

            with open(normalized_path, "r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(previous_offset)

                for line in handle:
                    stripped = line.rstrip("\n")
                    if stripped:
                        self._process_line(stripped, normalized_path)

                self.file_offsets[normalized_path] = handle.tell()
        except OSError as exc:
            self.app_logger.error("Error reading log file %s: %s", normalized_path, exc)
        except Exception as exc:
            self.app_logger.exception("Unexpected monitor error for %s: %s", normalized_path, exc)

    def _process_line(self, line: str, normalized_path: str) -> None:
        source_file = self.monitored_files.get(normalized_path, normalized_path)
        parsed_entry = self.parser.parse_line(line, source_file)
        anomalies = self.analyzer.analyze_entry(parsed_entry)

        if not self.on_anomaly:
            return

        for anomaly in anomalies:
            self.on_anomaly(anomaly)