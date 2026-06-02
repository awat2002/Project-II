from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"[^\s\[:]+(?:\[\d+\])?:\s*(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
SRC_IP_PATTERN = re.compile(r"\bSRC=((?:\d{1,3}\.){3}\d{1,3})\b")
FROM_IP_PATTERN = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)

PORT_PATTERNS = [
    re.compile(r"\bDPT=(\d+)\b"),
    re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE),
    re.compile(r":(\d{1,5})\b"),
]

BYTE_PATTERNS = [
    re.compile(r"\b(?:LEN|length|bytes|size|BYTES)\s*[=:]\s*(\d+)\b", re.IGNORECASE),
    re.compile(r"\b(?:transferred|sent|received)\s+(\d+)\s+bytes\b", re.IGNORECASE),
]
UNIT_BYTES_PATTERN = re.compile(r"\b(\d+(?:\.\d+)?)\s*(GB|MB|KB|B)\b", re.IGNORECASE)

USERNAME_PATTERNS = [
    re.compile(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"Accepted\s+\S+\s+for\s+([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"session\s+opened\s+for\s+user\s+([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"user[=: ]+([A-Za-z0-9_.-]+)", re.IGNORECASE),
]

FAILED_LOGIN_TOKENS = (
    "failed password",
    "authentication failure",
    "failed login",
    "invalid user",
)
SUCCESS_LOGIN_TOKENS = (
    "accepted password",
    "accepted publickey",
    "session opened for user",
    "login successful",
)
SUSPICIOUS_TOKENS = (
    "scan",
    "nmap",
    "exploit",
    "unauthorized",
    "intrusion",
    "suspicious",
)

@dataclass(slots=True)
class ParsedLogEntry:
    source_file: str
    raw_line: str
    timestamp: datetime
    message: str = ""
    event_type: str = "generic"
    username: str | None = None
    src_ip: str | None = None
    dst_port: int | None = None
    bytes_count: int = 0

class LogParser:

    def parse_line(self, raw_line: str, source_file: str) -> ParsedLogEntry:
        line = raw_line.rstrip("\n")
        match = SYSLOG_PATTERN.match(line)

        if match:
            timestamp = self._parse_syslog_timestamp(
                match.group("month"),
                match.group("day"),
                match.group("time"),
            )
            message = match.group("message").strip()
        else:
            timestamp = datetime.now()
            message = line.strip()

        username = self._extract_username(message)
        src_ip = self._extract_src_ip(message)
        dst_port = self._extract_port(message)
        bytes_count = self._extract_bytes(message)
        event_type = self._classify_event_type(message, bytes_count)

        return ParsedLogEntry(
            source_file=source_file,
            raw_line=line,
            timestamp=timestamp,
            message=message,
            event_type=event_type,
            username=username,
            src_ip=src_ip,
            dst_port=dst_port,
            bytes_count=bytes_count,
        )

    def _parse_syslog_timestamp(self, month: str, day: str, time_value: str) -> datetime:
        now = datetime.now()
        try:
            timestamp = datetime.strptime(f"{month} {int(day):02d} {time_value}", "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=now.year)
            if timestamp > now + timedelta(days=1):
                timestamp = timestamp.replace(year=now.year - 1)
            return timestamp
        except ValueError:
            return now

    def _extract_username(self, message: str) -> str | None:
        for pattern in USERNAME_PATTERNS:
            match = pattern.search(message)
            if match:
                return match.group(1)
        return None

    def _extract_src_ip(self, message: str) -> str | None:
        src_match = SRC_IP_PATTERN.search(message)

        from_match = FROM_IP_PATTERN.search(message)
        if src_match:
            return src_match.group(1)
        if from_match:
            return from_match.group(1)

        all_ips = IP_PATTERN.findall(message)
        if all_ips:
            return all_ips[0]
        return None

    def _extract_port(self, message: str) -> int | None:
        for pattern in PORT_PATTERNS:
            match = pattern.search(message)
            if match:
                port = int(match.group(1))
                if 0 <= port <= 65535:
                    return port
        return None

    def _extract_bytes(self, message: str) -> int:
        for pattern in BYTE_PATTERNS:
            match = pattern.search(message)
            if match:
                return int(match.group(1))

        unit_match = UNIT_BYTES_PATTERN.search(message)
        if not unit_match:
            return 0

        value = float(unit_match.group(1))
        unit = unit_match.group(2).upper()
        multipliers = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
        }
        return int(value * multipliers[unit])

    def _classify_event_type(self, message: str, bytes_count: int) -> str:
        message_lower = message.lower()

        if any(token in message_lower for token in FAILED_LOGIN_TOKENS):
            return "failed_login"
        if any(token in message_lower for token in SUCCESS_LOGIN_TOKENS):
            return "successful_login"
        if bytes_count > 0:
            return "data_transfer"
        if any(token in message_lower for token in SUSPICIOUS_TOKENS):
            return "suspicious"
        return "generic"