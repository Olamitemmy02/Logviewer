# LogViewer Installation Guide

## Overview

LogViewer is a Python-based Linux log investigation platform.

The commercial release provides:

- Core: free base functionality
- Pro: Core plus licensed investigation capabilities

## Requirements

Recommended requirements:

- Linux
- Python 3.10 or newer
- Python pip
- Permission to read required log sources
- Permission to write to configured export locations

Check Python:

    python --version

Check pip:

    python -m pip --version

## Core Installation

Install the Core release archive:

    python -m pip install LogViewer-Core-1.0.0.tar.gz

Start LogViewer:

    logviewer

Core functionality does not require a Pro license.

## Pro Installation

Install the Pro release archive:

    python -m pip install LogViewer-Pro-1.0.0.tar.gz

Start LogViewer:

    logviewer

The Pro application can be installed without a license, but Pro-only functionality remains locked until a valid license is activated.

## Customer Installation Scripts

Validated customer installation workflows are provided at:

    install/install_core.py
    install/install_pro.py

The installation workflows validate the selected release archive before installation.

## Supported Log Sources

Depending on the Linux host, LogViewer can work with real sources including:

    /var/log/auth.log
    /var/log/syslog
    /var/log/kern.log
    /var/log/ufw.log
    /var/log/cron.log
    /var/log/apt/
    /var/log/apache2/
    /var/log/nginx/
    /var/log/caddy/
    /var/log/postgresql/
    /var/log/snort/
    systemd journal

The exact available sources depend on the Linux host.

## Permissions

LogViewer can only analyze sources accessible to the account running the application.

If a log source cannot be read, check its permissions and the permissions of the parent directory.

Do not unnecessarily weaken system permissions.

## Updating

Before updating:

1. Export reports that must be retained.
2. Preserve valid customer license information.
3. Install the new release.
4. Start LogViewer.
5. Verify Core functionality.
6. Verify Pro license status when applicable.
7. Confirm expected Pro features are available.

## Uninstallation

Remove the Python package with:

    python -m pip uninstall logviewer

Review customer-generated exports and configuration separately before deleting them.

## Detailed Documentation

Core:

    docs/CORE.md

Pro:

    docs/PRO.md

License activation:

    docs/LICENSE_ACTIVATION.md

Troubleshooting:

    docs/TROUBLESHOOTING.md

Support:

    docs/SUPPORT.md
