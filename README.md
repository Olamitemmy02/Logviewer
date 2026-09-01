# LogViewer

**LogViewer** is a Python-based security log analysis and monitoring tool designed to inspect, search, filter, analyze, and monitor log data from a Linux system.

Instead of relying on bundled demonstration logs, LogViewer is designed to work with **real log sources available on the host system**, including traditional `/var/log` files, systemd journal data, and security-tool logs such as Snort.

---

## Features

### System Log Discovery

Automatically discovers accessible log files available on the current Linux system.

Examples include:

* `/var/log/auth.log`
* `/var/log/syslog`
* `/var/log/kern.log`
* `/var/log/ufw.log`
* `/var/log/cron.log`
* `/var/log/apt/`
* `/var/log/apache2/`
* `/var/log/nginx/`
* `/var/log/caddy/`
* `/var/log/postgresql/`
* `/var/log/snort/`

The exact sources depend on the services installed and configured on the host.

### Log Viewing

View the contents of an accessible system log directly from the LogViewer interface.

Features include:

* Log source selection
* Recent-event viewing
* Large-log handling
* Permission-aware access
* Support for custom log sources

### Search

Search log events using keywords and other supported criteria.

Example use cases:

* Find authentication failures
* Locate specific processes
* Search for IP addresses
* Find firewall events
* Investigate errors
* Locate specific timestamps or messages

### Filtering

Filter events to reduce large log datasets to relevant security information.

Filtering can be used for:

* Severity
* Event type
* Source
* Process
* Time
* Keywords

### Statistics

Generate statistics from the currently selected log data.

Examples include:

* Total events
* Errors
* Warnings
* Event distribution
* Source distribution
* Security-related activity

Statistics are generated from the data being analyzed rather than predefined demonstration values.

### Live Monitoring

Monitor log files as new events are written.

This allows LogViewer to observe activity in real time and display newly generated events without repeatedly reopening the log file.

### Snort Integration

LogViewer includes a dedicated Snort analysis module for working with Snort alert data.

The Snort subsystem includes:

```text
snort/
├── constants.py
├── reader.py
├── parser.py
├── analyzer.py
└── dashboard.py
```

It is designed to allow Snort alerts to be analyzed alongside other system log sources.

### Exporting

Analyzed information can be exported for later review, reporting, or incident documentation.

The project includes an `exports/` directory for generated reports.

---

## Architecture

LogViewer follows a modular architecture:

```text
                     LOGVIEWER
                         |
                  System Discovery
                         |
          +--------------+--------------+
          |              |              |
      Log Files       Journald        Snort
          |              |              |
          +--------------+--------------+
                         |
                    Log Sources
                         |
                       Parser
                         |
                     LogEvent
                         |
          +--------------+--------------+
          |              |              |
        Viewer        Search         Filters
          |              |              |
          +--------------+--------------+
                         |
                     Statistics
                         |
                    Detection
                         |
                      Alerts
                         |
             +-----------+-----------+
             |                       |
        Live Monitor             Export
```

---

## Project Structure

```text
LogViewer/
│
├── logviewer/
│   ├── __init__.py
│   ├── main.py
│   ├── banner.py
│   ├── menu.py
│   ├── cli.py
│   │
│   ├── config.json
│   ├── config.py
│   ├── settings.py
│   │
│   ├── logger.py
│   ├── viewer.py
│   ├── search.py
│   ├── filters.py
│   ├── monitor.py
│   ├── statistics.py
│   ├── exporter.py
│   │
│   ├── discovery.py
│   ├── events.py
│   ├── system.py
│   ├── system_dashboard.py
│   ├── utils.py
│   │
│   ├── sources/
│   │   ├── __init__.py
│   │   └── file_source.py
│   │
│   └── snort/
│       ├── __init__.py
│       ├── constants.py
│       ├── reader.py
│       ├── parser.py
│       ├── analyzer.py
│       └── dashboard.py
│
├── logs/
├── exports/
├── tests/
├── README.md
└── requirements.txt
```

---

## Requirements

* Linux operating system
* Python 3.10+
* Access to the log sources you want to analyze

Optional components such as Snort, Apache, Nginx, Caddy, UFW, Maltrail, or PostgreSQL can be integrated when they are installed on the system.

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd LogViewer
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Running LogViewer

From the project root:

```bash
python3 -m logviewer.main
```

The application should discover available system log sources rather than depending on bundled example logs.

---

## System Log Discovery

LogViewer can identify accessible logs under locations such as:

```text
/var/log/
```

and relevant service-specific directories.

A system may expose different logs depending on its configuration.

For example:

```text
[01] /var/log/auth.log
[02] /var/log/syslog
[03] /var/log/kern.log
[04] /var/log/ufw.log
[05] /var/log/snort/alert_csv.txt
```

Only sources available and accessible on the host are presented.

---

## Permissions

Some Linux security logs are restricted to privileged users.

If a log cannot be accessed, LogViewer should report the problem without terminating the entire application.

For example:

```text
[!] Permission denied

Source:
    /var/log/auth.log

The selected log cannot currently be read.
```

Run LogViewer with the appropriate permissions when authorized and required by the system configuration.

---

## Security and Privacy

Log files can contain sensitive information, including:

* Usernames
* IP addresses
* Hostnames
* Authentication events
* Application information
* Network activity

Do not publish real system logs to a public repository.

The project's local log directory should remain separate from production source code.

Recommended `.gitignore` entries:

```gitignore
__pycache__/
*.pyc
.venv/
venv/
.env

logs/*
!logs/.gitkeep

exports/*
!exports/.gitkeep
```

---

## Testing

Automated tests are kept separate from the production application.

```text
tests/
```

Test data should be synthetic, isolated, or generated temporarily for testing.

Production LogViewer does **not** depend on test logs or demonstration data.

---

## Development Roadmap

### Completed / In Progress

* [x] Modular CLI architecture
* [x] System information detection
* [x] System log discovery
* [x] Real log-file access
* [x] Standardized `LogEvent` structure
* [x] File log source abstraction
* [x] Snort analysis foundation
* [ ] Unified log parsing
* [ ] Journald source
* [ ] Advanced event detection
* [ ] Improved alert engine
* [ ] Real-time monitoring improvements
* [ ] Advanced reporting
* [ ] Expanded automated test coverage

---

## Design Principles

LogViewer is being developed around several principles:

1. **Real data over demonstration data**
2. **Modular architecture**
3. **System-aware operation**
4. **Least-assumption design**
5. **Clear separation between production code and tests**
6. **Security-focused analysis**
7. **Readable and maintainable Python code**

---

## Disclaimer

LogViewer is intended for authorized security monitoring, system administration, troubleshooting, and defensive security analysis.

Only analyze systems and log data that you are authorized to access.

---

## License

Add the project's chosen license here.

For example:

```text
MIT License
```

if the project is released under the MIT License.
