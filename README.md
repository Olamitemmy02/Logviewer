# LogViewer

A Python-based cybersecurity log viewing and analysis tool designed for monitoring, searching, filtering, analyzing, and exporting log data through a command-line interface.

## Overview

LogViewer is a modular Python application for working with security and system log files.

The project provides tools for viewing logs, searching for specific events, filtering log data, monitoring activity, generating statistics, and exporting information for further analysis.

LogViewer is being developed as a cybersecurity and defensive security project with an emphasis on practical log analysis and monitoring.

## Features

- View security and system logs
- Search log entries
- Filter log data
- Monitor log activity
- Analyze log statistics
- Export log reports
- Interactive command-line interface
- Interactive menu system
- Configurable application settings
- JSON-based configuration
- Modular Python architecture
- Security and system log support
- Firewall log support
- Network log support
- Report generation

## Core Modules

| Module | Purpose |
|---|---|
| `main.py` | Main application entry point |
| `cli.py` | Command-line interface functionality |
| `menu.py` | Interactive menu system |
| `banner.py` | Terminal banner and application presentation |
| `viewer.py` | Log viewing functionality |
| `logger.py` | Logging functionality |
| `monitor.py` | Log monitoring functionality |
| `search.py` | Searching and locating log entries |
| `filters.py` | Filtering log information |
| `statistics.py` | Log statistics and analysis |
| `exporter.py` | Exporting log information and reports |
| `settings.py` | Application settings management |
| `config.py` | Configuration handling |
| `utils.py` | Shared utility functions |
| `config.json` | Application configuration |

## Project Structure

```text
LogViewer/
│
├── logviewer/
│   ├── __init__.py
│   ├── main.py
│   ├── cli.py
│   ├── menu.py
│   ├── banner.py
│   ├── viewer.py
│   ├── logger.py
│   ├── monitor.py
│   ├── search.py
│   ├── filters.py
│   ├── statistics.py
│   ├── exporter.py
│   ├── settings.py
│   ├── config.py
│   ├── utils.py
│   ├── config.json
│   │
│   └── logs/
│       ├── security.log
│       ├── network.log
│       ├── system.log
│       └── firewall.log
│
├── requirements.txt
├── pyproject.toml
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- pip
- Git

### Supported Platforms

The project is primarily developed and tested on Linux/Kali Linux.

It can be adapted for other operating systems depending on the log sources and system-specific functionality being used.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Olamitemmy02/Logviewer.git
```

### 2. Enter the Project Directory

```bash
cd LogViewer
```

### 3. Create a Virtual Environment

```bash
python3 -m venv .venv
```

### 4. Activate the Virtual Environment

On Linux/Kali Linux:

```bash
source .venv/bin/activate
```

On Windows:

```powershell
.venv\Scripts\activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running LogViewer

After installation, run the application with:

```bash
python3 -m logviewer.main
```

If the package has been installed as a command-line application, you can also use:

```bash
logviewer
```

## Log Sources

The project currently contains example log files for different categories of events:

```text
logviewer/logs/security.log
logviewer/logs/network.log
logviewer/logs/system.log
logviewer/logs/firewall.log
```

These logs can be used for development, testing, searching, filtering, monitoring, and analysis.

When using the project with real environments, ensure that sensitive information is handled appropriately.

## Configuration

Application configuration is handled through:

```text
logviewer/config.json
```

Configuration functionality is provided by:

```text
logviewer/config.py
logviewer/settings.py
```

Configuration options may be expanded as the project develops.

## Usage

The application provides functionality for:

1. Viewing available log data
2. Searching for specific log entries
3. Filtering log events
4. Monitoring log activity
5. Reviewing statistical information
6. Exporting reports
7. Managing application settings

The exact menu and command options may change as development continues.

## Development

LogViewer uses a modular architecture where different functions are separated into individual Python modules.

This makes it easier to:

- Maintain the codebase
- Add new features
- Test individual components
- Improve existing functionality
- Extend log-processing capabilities

### Development Goals

Future development may include:

- Additional log formats
- Improved log parsing
- More advanced search capabilities
- More advanced filtering
- Enhanced statistics
- Improved report generation
- Additional monitoring functionality
- Automated testing
- Improved error handling
- Expanded configuration options
- Additional security-focused analysis features

## Security

LogViewer is intended for defensive security, cybersecurity education, log analysis, monitoring, and security research.

Do not commit sensitive information to this repository.

Never upload:

- Passwords
- API keys
- Authentication tokens
- Private keys
- Credentials
- Sensitive personal information
- Confidential production logs
- Unredacted security logs

Use sanitized, synthetic, or test data when sharing logs publicly.

## Contributing

Contributions and improvements are welcome.

To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Test your changes.
5. Commit your changes.
6. Push the branch to GitHub.
7. Open a pull request.

Example:

```bash
git checkout -b feature/new-feature
```

```bash
git add .
git commit -m "Add new feature"
git push origin feature/new-feature
```

## Author

**Olamitemmy02**

GitHub:

https://github.com/Olamitemmy02

## License

This project does not currently specify an open-source license.

A license will be added in a future release.

## Project Status

**Development / Alpha**

LogViewer is currently under active development.

Features, architecture, command-line interfaces, and configuration options may change as the project evolves.

## Disclaimer

LogViewer is designed for defensive security, cybersecurity education, authorized testing, and legitimate log-analysis purposes.

Only use the application on systems and log data that you are authorized to access and analyze.

## Acknowledgements

Built with Python and developed as a cybersecurity log-analysis project.

---

**LogViewer — Cybersecurity Log Viewing and Analysis**
