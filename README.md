LogViewer

LogViewer is a Python-based security log analysis and monitoring tool designed to inspect, search, filter, analyze, and monitor real log data from Linux systems.

Instead of relying on bundled demonstration logs, LogViewer works with real log sources available on the host system, including traditional "/var/log" files, systemd journal data, and security-tool logs such as Snort.

The long-term goal is to evolve LogViewer from a log viewer into an evidence-driven threat investigation platform that helps analysts understand not only what happened, but how events are connected and why they matter.

---

Features

System Log Discovery

Automatically discovers accessible log files available on the current Linux system.

Examples include:

* "/var/log/auth.log"
* "/var/log/syslog"
* "/var/log/kern.log"
* "/var/log/ufw.log"
* "/var/log/cron.log"
* "/var/log/apt/"
* "/var/log/apache2/"
* "/var/log/nginx/"
* "/var/log/caddy/"
* "/var/log/postgresql/"
* "/var/log/snort/"

The exact sources depend on the services installed and configured on the host.

Log Viewing

View the contents of accessible system logs directly through the LogViewer interface.

Features include:

* Log source selection
* Recent-event viewing
* Large-log handling
* Permission-aware access
* Support for custom log sources

Search

Search log events using keywords and supported criteria.

Example use cases:

* Find authentication failures
* Locate specific processes
* Search for IP addresses
* Find firewall events
* Investigate errors
* Locate specific timestamps or messages

Filtering

Filter events to reduce large datasets to relevant security information.

Filtering can be used for:

* Severity
* Event type
* Source
* Process
* Time
* Keywords

Statistics

Generate statistics from the currently selected log data.

Examples include:

* Total events
* Errors
* Warnings
* Event distribution
* Source distribution
* Security-related activity

Statistics are generated from the data being analyzed rather than predefined demonstration values.

Live Monitoring

Monitor log files as new events are written.

This allows LogViewer to observe activity in real time and display newly generated events without repeatedly reopening the log file.

Snort Integration

LogViewer includes a dedicated Snort analysis subsystem for working with Snort alert data.

snort/
├── constants.py
├── reader.py
├── parser.py
├── analyzer.py
└── dashboard.py

The Snort subsystem is designed to analyze network-security alerts alongside other system log sources.

IOC & Security Analysis

LogViewer is being extended toward structured security analysis, including identification of security-relevant artifacts such as:

* IP addresses
* Domains
* URLs
* Processes
* Commands
* Security events
* Alert information

These capabilities form the foundation for future event correlation and threat investigation.

Exporting

Analyzed information can be exported for later review, reporting, or incident documentation.

The project includes an "exports/" directory for generated reports.

---

Architecture

LogViewer follows a modular architecture:

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

---

Project Structure

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

---

Requirements

* Linux operating system
* Python 3.10+
* Access to the log sources you want to analyze

Optional components such as Snort, Apache, Nginx, Caddy, UFW, Maltrail, or PostgreSQL can be integrated when they are installed on the system.

---

Installation

Clone the repository:

git clone <repository-url>
cd LogViewer

Install the Python dependencies:

pip install -r requirements.txt

---

Running LogViewer

From the project root:

python3 -m logviewer.main

LogViewer should discover available system log sources rather than depending on bundled example logs.

---

System Log Discovery

LogViewer can identify accessible logs under locations such as:

/var/log/

and relevant service-specific directories.

A system may expose different logs depending on its configuration.

For example:

[01] /var/log/auth.log
[02] /var/log/syslog
[03] /var/log/kern.log
[04] /var/log/ufw.log
[05] /var/log/snort/alert_csv.txt

Only sources available and accessible on the host are presented.

---

Permissions

Some Linux security logs are restricted to privileged users.

If a log cannot be accessed, LogViewer should report the problem without terminating the entire application.

For example:

[!] Permission denied

Source:
    /var/log/auth.log

The selected log cannot currently be read.

Run LogViewer with the appropriate permissions when authorized and required by the system configuration.

---

Security and Privacy

Log files can contain sensitive information, including:

* Usernames
* IP addresses
* Hostnames
* Authentication events
* Application information
* Network activity

Do not publish real system logs to a public repository.

The project's local log directory should remain separate from production source code.

Recommended ".gitignore" entries:

__pycache__/
*.pyc
.venv/
venv/
.env

logs/*
!logs/.gitkeep

exports/*
!exports/.gitkeep

---

Testing

Automated tests are kept separate from the production application.

tests/

Test data should be synthetic, isolated, or generated temporarily for testing.

Production LogViewer does not depend on test logs or demonstration data.

---

Development Roadmap

Completed / In Progress

* [x] Modular CLI architecture
* [x] System information detection
* [x] System log discovery
* [x] Real log-file access
* [x] Standardized "LogEvent" structure
* [x] File log source abstraction
* [x] Snort analysis foundation
* [ ] Unified log parsing
* [ ] Journald source
* [ ] Advanced event detection
* [ ] Improved alert engine
* [ ] Real-time monitoring improvements
* [ ] Advanced reporting
* [ ] Expanded automated test coverage

Future Threat Investigation

The next stage of LogViewer will focus on turning individual events and alerts into meaningful security investigations.

Planned capabilities include:

* [ ] IOC extraction and normalization
* [ ] IOC-to-event correlation
* [ ] Command execution analysis
* [ ] Process-tree analysis
* [ ] Attack-chain reconstruction
* [ ] MITRE ATT&CK mapping
* [ ] Threat scoring and confidence assessment
* [ ] Evidence-backed findings
* [ ] False-positive analysis
* [ ] Investigation timelines
* [ ] IOC relationship visualization
* [ ] Threat-hunting assistance
* [ ] Detection-rule generation
* [ ] Automated incident summaries

The objective is to answer:

«What happened, what evidence supports it, how are the events connected, and what should the analyst investigate next?»

---

LogViewer Pro

The advanced threat-investigation capabilities are planned as part of the future LogViewer Pro offering.

The Core version will remain focused on essential log analysis and monitoring, while Pro will provide deeper investigation and analysis capabilities.

Core

«See what's happening.»

Pro

«Understand what happened and investigate it.»

Planned Pro capabilities include:

* Advanced event correlation
* Attack-chain reconstruction
* Process and command analysis
* Threat intelligence enrichment
* MITRE ATT&CK analysis
* Evidence-based incident assessment
* Threat scoring
* Investigation graphs
* Threat-hunting assistance
* Detection engineering
* Advanced incident reporting

LogViewer Pro is a future direction and should not be considered part of the currently completed feature set.

---

Design Principles

LogViewer is being developed around several principles:

1. Real data over demonstration data
2. Evidence over assumptions
3. Modular architecture
4. System-aware operation
5. Least-assumption design
6. Clear separation between production code and tests
7. Security-focused analysis
8. Readable and maintainable Python code

---

Project Vision

LogViewer aims to bridge the gap between raw security logs and understandable threat investigations.

Rather than simply displaying an alert, the long-term goal is to help analysts connect:

Events
  ↓
Indicators
  ↓
Processes
  ↓
Commands
  ↓
Network Activity
  ↓
Techniques
  ↓
Attack Chain
  ↓
Evidence-Based Investigation

The project is actively evolving, and feedback from cybersecurity practitioners, students, researchers, and open-source contributors is welcome.

---

Disclaimer

LogViewer is intended for authorized security monitoring, system administration, troubleshooting, and defensive security analysis.

Only analyze systems and log data that you are authorized to access.

---

License

LogViewer is distributed under the LogViewer Personal, Educational & Commercial Royalty License.

- Personal use: permitted
- Educational use: permitted
- Academic projects: permitted
- Non-commercial research: permitted
- Security laboratories and training: permitted
- Commercial use: permitted subject to the license terms
- Commercial royalty: 15% of applicable Gross Revenue

See the ""LICENSE"" (LICENSE) file for the complete license terms.