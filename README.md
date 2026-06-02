# Anomaly Detection System

Real-time Linux log monitoring tool for anomaly detection.

## What This Project Does

The tool tails live additions to system logs, parses each new line, classifies security-relevant events, detects rule-based anomalies, and writes session reports.

Default monitored files:

- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/kern.log`

## Detection Rules

The analyzer currently supports these anomaly types:

1. `failed_login_attempts`
2. `unusual_login_times`
3. `repeated_port_connections`
4. `high_network_traffic`
5. `large_data_transfers`
6. `general_suspicious_entries`

Default thresholds (from `config.py`):

- Failed login attempts: `5` in `60s`
- Unusual login times: outside `06:00-22:00`
- High network traffic: `100 MB` in `60s`
- Repeated port connections: `10` in `30s`
- Large data transfers: `500 MB` in `3600s`

## Project Structure

- `main.py`: CLI entrypoint and session orchestration.
- `log_monitor.py`: Watches files and reads appended lines only.
- `log_parser.py`: Extracts timestamp, IPs, ports, bytes, event type.
- `analyzer.py`: Windowed threshold detection and severity assignment.
- `display.py`: Rich terminal UI and summaries.
- `reporter.py`: JSON/CSV report generation.
- `logger.py`: Application logger (`logs/app.log`).
- `config.py`: Defaults, severity map, paths.

## Requirements

- Linux environment (Kali Linux recommended)
- Python 3.10+
- Dependencies listed in `requirements.txt`

## Setup (Kali/Linux)

```bash
cd "~/Desktop/Anomaly Detection System"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If Kali blocks global pip installs, always use the local `.venv` as above.

## Run Modes

### 1) Interactive mode

Run with no arguments:

```bash
python3 main.py
```

It prompts for thresholds, duration, and poll interval.

### 2) CLI mode

Example:

```bash
python3 main.py \
  --duration 180 \
  --threshold failed-logins=3 \
  --threshold port-connections=3 \
  --threshold high-traffic-mb=1 \
  --threshold large-transfer-mb=2 \
  --threshold login-hours=0-23
```

If running with elevated privileges:

```bash
sudo "$(pwd)/.venv/bin/python3" main.py --duration 180
```

## Screenshots


<img width="1673" height="823" alt="image3" src="https://github.com/user-attachments/assets/a190849a-712b-4821-856f-5ada842c9356" />

<img width="686" height="456" alt="image4" src="https://github.com/user-attachments/assets/91ffe038-aeff-49f9-94a4-624552c8ff53" />



## CLI Threshold Keys

Supported keys:

- `failed-logins`
- `failed-window`
- `login-hours` (format: `start-end`, example `6-22`)
- `high-traffic-mb`
- `high-traffic-window`
- `port-connections`
- `port-window`
- `large-transfer-mb`
- `large-transfer-window`

## Output Files

Generated per session:

- `reports/report.json`
- `reports/report.csv`

Application log:

- `logs/app.log`

## Testing Guidance

### Functional validation (controlled)

Use lower thresholds and append representative log events (for example via `logger`) so each rule is triggered predictably. This confirms parser, analyzer, display, and reporting end to end.

### False-positive check (baseline)

Run a quiet session (10 to 15 minutes) with no synthetic/injected events and normal workstation activity. Review total anomalies and adjust thresholds to your environment baseline.

## Important Behavior Notes

- Monitoring is append-only: historical lines already in files are not reprocessed at startup.
- If no matching suspicious activity occurs, no alerts is expected behavior.
- Parsing is pattern-based, so log format quality directly affects detection quality.
