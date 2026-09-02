# SSH Sentinel Live — Mini-SIEM for SSH Logs

SSH Sentinel Live is a small FastAPI application built as an educational
cybersecurity project. It can analyze uploaded OpenSSH logs or continuously
monitor a local log file. Recognized events and time-based brute-force alerts
are stored in a local SQLite database and displayed in a live dashboard.

> This application is an explainable demonstration. It is not a replacement
> for a production SIEM, intrusion-detection system, or other security tooling.

## Features

- drag-and-drop or file selection for UTF-8 `.log` and `.txt` files up to 2 MB
- parsing of failed and successful SSH logins, including invalid usernames
- IPv4, IPv6, Syslog, and ISO timestamp support
- rule-based analysis with a risk score from 0 to 100
- polling-based live ingestion with truncation and rotation handling
- local SQLite persistence for events, alerts, status, and investigation notes
- time-based SSH brute-force detection
- a responsive dashboard with four-second polling
- alert status filtering and note editing
- a unified command for the web application and live ingestion
- automated tests and reproducible synthetic demo data

## Architecture and data flow

The upload analysis and persistent live processing share the existing parser
but remain separate workflows.

Upload analysis:

```text
Browser / JSON client
  → FastAPI routes
  → analysis service
  → parser
  → upload detector
  → scorer
  → HTML or JSON result
```

Live operation:

```text
Log file
  → File tailer
  → existing parser
  → SQLite events
  → brute-force detection
  → SQLite alerts
  → FastAPI
  → dashboard and alert management
```

Connections to SQLite are opened per operation or transaction. Foreign keys
are enabled for every connection, and SQL queries are parameterized.

## Main components

```text
ssh-sentinel-live/
├── main.py                     FastAPI app factory and default app
├── routes.py                   HTML routes and JSON API
├── launcher.py                 Local upload/dashboard launcher
├── run_live.py                 Unified web and ingestion entry point
├── live_ingest.py              Standalone ingestion entry point
├── file_tailer.py              Polling file tailer
├── live_ingestion.py           Parser-to-database ingestion service
├── brute_force_detection.py    Time-based live detection rule
├── database.py                 SQLite schema and persistence operations
├── runtime_status.py           Thread-safe integrated runtime status
├── parser.py                   OpenSSH log parser
├── detector.py                 Upload-analysis detection rules
├── scorer.py                   Upload-analysis risk scoring
├── service.py                  Upload-analysis orchestration
├── models/
│   ├── analysis.py             Upload-analysis API models
│   └── dashboard.py            Dashboard API models
├── templates/                  Jinja2 pages
├── static/                     CSS and browser JavaScript
├── examples/                   Example SSH logs
├── scripts/
│   ├── demo_brute_force.sh     Synthetic brute-force demo
│   ├── build_linux.sh          Linux executable build
│   └── build_windows.ps1       Windows executable build
└── tests/                      Automated test suite
```

## Requirements and installation

Python 3.10 or newer is required.

### Linux

```bash
git clone https://github.com/ribpaulo/ssh-sentinel-live.git
cd ssh-sentinel-live
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -3.10 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The execution-policy change applies only to the current PowerShell session.

## Manual upload mode

Start the local application and open the browser automatically:

```bash
python launcher.py
```

Alternatively, use the Uvicorn development server:

```bash
python -m uvicorn main:app --reload
```

The upload page is available at
[http://127.0.0.1:8000](http://127.0.0.1:8000), and the interactive API
documentation is available at
[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

Launcher options:

```bash
python launcher.py --port 8001
python launcher.py --no-browser
python launcher.py --help
```

The launcher binds only to `127.0.0.1`. It reports an occupied port and
suggests an alternative.

## Recommended unified live operation

One command starts the dashboard and live ingestion with the exact same
database instance:

```bash
python run_live.py --log-file /var/log/auth.log
```

The defaults are `127.0.0.1:8000`, a 0.5-second polling interval, ingestion
from the current end of the file, and `data/ssh_sentinel.db`.

```bash
python run_live.py \
  --log-file /tmp/ssh-sentinel-demo.log \
  --database data/ssh_sentinel.db \
  --host 127.0.0.1 \
  --port 8000 \
  --poll-interval 0.5 \
  --brute-force-threshold 5 \
  --brute-force-window 60 \
  --from-start
```

`--poll-interval` and `--brute-force-window` must be positive and finite. The
threshold must be at least 2, and the port must be between 1 and 65535. The log
path must identify an existing, readable regular file.

Press `Ctrl+C` to stop the web server and file tailer. Unified live operation
does not use automatic reload or multiple workers. Do not combine an embedded
watcher with `--reload`, because the development reloader can create multiple
processes and duplicate ingestion.

## Standalone live ingestion

The previous standalone mode remains available when the web server and
ingestion should run as separate processes:

```bash
python live_ingest.py --log-file /var/log/auth.log
```

Additional options:

```bash
python live_ingest.py \
  --log-file examples/auth_short_bad.log \
  --database data/ssh_sentinel.db \
  --poll-interval 0.5 \
  --brute-force-threshold 5 \
  --brute-force-window 60 \
  --from-start
```

By default, existing file contents are skipped. `--from-start` explicitly
imports them. Syslog timestamps without a year are interpreted in the local
system timezone and converted to UTC before storage.

## Live dashboard and alert management

The dashboard is available at
[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard). It displays:

- recently stored SSH events
- persistent brute-force alerts
- events linked to each alert
- integrated monitoring status and the last stored event
- alert status and investigation notes

Visible pages poll approximately every four seconds. Polling pauses while the
page is hidden, avoids overlapping refreshes, and keeps existing data visible
during temporary failures.

Alerts can be filtered by these stable status values:

- `OPEN`: a new or untreated alert
- `ACKNOWLEDGED`: an alert that is being investigated
- `FALSE_POSITIVE`: activity classified as a false positive
- `CLOSED`: a completed investigation

`OPEN` and `ACKNOWLEDGED` alerts remain active for live detection and can be
extended by matching events. `FALSE_POSITIVE` and `CLOSED` alerts are not
extended. Investigation notes are preserved when an acknowledged alert is
extended.

The normal `launcher.py` and `main:app` modes report integrated live ingestion
as inactive. A different database can be selected for those modes with:

```bash
SSH_SENTINEL_DATABASE=/tmp/ssh_sentinel.db python -m uvicorn main:app --reload
```

When ingestion runs separately, pass the same database path explicitly:

```bash
python live_ingest.py --log-file /var/log/auth.log --database /tmp/ssh_sentinel.db
```

## System status API

`GET /api/system/status` returns a small read-only status object with these
stable fields:

- `database_ready`
- `live_ingestion`
- `log_file`
- `started_at`
- `last_event_id`
- `last_event_at`
- `last_error`

The endpoint does not expose the database path, stack traces, or internal
exception messages. `GET /api/health` remains available as a basic health
check.

## Brute-force detection rule

The live rule uses these defaults:

| Setting | Value |
|---|---|
| Rule ID | `SSH_BRUTE_FORCE` |
| Event type | `failed_login` |
| Grouping | `ip_address` |
| Threshold | 5 failed logins |
| Time window | 60 seconds, inclusive boundaries |
| Severity | `HIGH` |
| Score | 70 / 100 |
| New alert status | `OPEN` |

The score represents high-risk repeated authentication failures without
claiming that access was successful. Active overlapping alerts are extended
atomically, and events are linked through `alert_events` without duplicates.

## Reproducible brute-force demo

The demo uses only synthetic log lines. It performs no login attempts, network
actions, or privileged operations.

First terminal:

```bash
touch /tmp/ssh-sentinel-demo.log
python run_live.py --log-file /tmp/ssh-sentinel-demo.log
```

Second terminal:

```bash
scripts/demo_brute_force.sh /tmp/ssh-sentinel-demo.log
```

The script appends six synthetic failed-login lines from the reserved
documentation address `203.0.113.50`. It never overwrites existing content.
The fifth event creates an alert with default settings, and the sixth extends
it. View the result at
[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard).

## Upload-analysis rules and scoring

The manual upload workflow remains independent of persistent live detection.
It evaluates all recognized events within one uploaded file.

| Rule | Trigger | Points |
|---|---|---:|
| Multiple failed logins per IP | at least 5 failed logins | 25 base + 2 per additional failure, capped at 40 |
| High volume per IP | at least 10 login events | 15 base + 1 per additional event, capped at 25 |
| Frequently targeted username | at least 6 login events | 15 base + 2 per additional event, capped at 25 |
| Success after failures | successful login after at least 3 failures from the same IP | 30 per sequence |

| Total score | Risk level |
|---:|---|
| 0–19 | `LOW` (API value: `LOW`) |
| 20–49 | `MEDIUM` (API value: `MEDIUM`) |
| 50–74 | `HIGH` (API value: `HIGH`) |
| 75–100 | `CRITICAL` (API value: `CRITICAL`) |

The thresholds and points are demonstration heuristics, not an official
cybersecurity or SIEM standard.

## Supported log patterns

Examples:

```text
Jul 31 09:12:10 host sshd[1110]: Failed password for invalid user admin from 203.0.113.45 port 41101 ssh2
Jul 31 09:12:20 host sshd[1111]: Accepted publickey for deploy from 2001:db8::10 port 41102 ssh2
Jul 31 09:12:30 host sshd[1112]: Invalid user test from 198.51.100.77 port 50201
2026-07-31T09:12:40+02:00 host sshd[1113]: Failed password for root from 198.51.100.22 port 50202 ssh2
```

Unsupported lines are ignored by live ingestion. In upload analysis, they
still contribute to the total line count.

## Building standalone executables

PyInstaller builds are operating-system specific.

Linux:

```bash
source .venv/bin/activate
python -m pytest -q
./scripts/build_linux.sh
./dist/ssh-sentinel
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
.\dist\ssh-sentinel.exe
```

Build output is written to `build/` and `dist/`, both of which are ignored by
Git. A Linux build does not run on Windows, and a Windows build does not run on
Linux.

## Tests

```bash
python -m pytest -q
```

The suite covers parsing, upload analysis, persistence, file tailing, live
ingestion, brute-force detection, alert management, the dashboard, runtime
status, lifecycle handling, and the synthetic demo script.

## Privacy and local data storage

Recognized raw log lines, events, alert links, and investigation notes are
stored in the local SQLite file. They are not sent to external services.
Operators are responsible for file permissions, retention, and deletion based
on the sensitivity of their logs. Database files are ignored by Git.

## Security boundaries and known limitations

- The dashboard has no authentication or role management and should not be
  exposed directly on a public interface.
- This educational project is not a complete production SIEM replacement. It
  lacks central log transport, high availability, notifications, tenant
  isolation, and tamper-resistant long-term storage.
- The tailer does not persist its offset. After restart it begins at the current
  file end unless `--from-start` is selected.
- SQLite is suitable for this local demonstration, not high concurrent write
  rates or distributed instances.
- Syslog timestamps without a year or timezone use the local system timezone
  and a year-boundary heuristic.
- A background failure is reported in the console and dashboard, but automatic
  tailer restart is outside the project scope.

Parser, detector, scorer, persistence, and web layers remain deliberately
separate so each can be tested and extended independently.
