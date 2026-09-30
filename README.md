# LogViewer 2.0

**Version:** 2.0

LogViewer is an evidence-driven Linux log investigation platform designed to help security analysts, system administrators, cybersecurity learners, researchers, and organizations investigate real Linux system and security log data.

LogViewer provides a free Core edition and an advanced commercially licensed Pro edition.

---

# LogViewer Core

LogViewer Core provides the main log investigation capabilities required to collect, inspect, search, filter, analyze, and report on Linux log data.

## Core Features

- Linux log source discovery
- Log viewing
- Log searching
- Log filtering
- Live log monitoring
- Log statistics
- Security event analysis
- Security correlation
- Basic IOC extraction
- Snort alert summary
- Report export
- Application configuration
- License management

## Supported Log Sources

LogViewer is designed to work with real Linux log sources, including:

- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/kern.log`
- `/var/log/ufw.log`
- `/var/log/cron.log`
- `/var/log/apt/`
- Apache logs
- Nginx logs
- Caddy logs
- PostgreSQL logs
- Snort alerts
- systemd journal data

The exact sources available depend on the Linux system and installed services.

---

# LogViewer Pro

LogViewer Pro adds advanced investigation and security-analysis capabilities to LogViewer.

Pro is designed for users who need structured investigations rather than simple log viewing.

## Pro Features

### Investigation

Creates a structured investigation containing related events, evidence, IOCs, correlations, analysis results, and findings.

### Threat Scoring

Calculates an analytical threat score and threat level from available investigation evidence.

The score is an analytical aid and does not automatically prove that activity is malicious.

### MITRE ATT&CK Mapping

Maps relevant investigation activity to applicable MITRE ATT&CK techniques.

A mapping does not by itself prove that a technique was successfully executed.

### False-Positive Analysis

Provides analytical context for activity that may have legitimate or non-malicious explanations.

### Process Tree Analysis

Builds parent-child process relationships from available process and parent-process information.

### Attack-Chain Reconstruction

Organizes related investigation activity into an ordered representation of an attack chain when sufficient evidence exists.

### Investigation Timeline

Provides chronological organization of investigation activity, including events, correlations, mappings, process relationships, and attack-chain information where available.

### Investigation Findings

Produces structured findings containing information such as:

- Finding title
- Summary
- Severity
- Confidence
- Rationale
- Supporting events
- Evidence references
- IOC values
- MITRE techniques
- Correlation information
- False-positive context

### Investigation Reporting

Produces structured investigation reports in:

- Markdown
- JSON

### Evidence Packages

Packages investigation reports and structured investigation information together with integrity metadata.

### Evidence Verification

Verifies:

- Required package files
- Package paths
- Recorded file sizes
- SHA-256 integrity hashes
- Manifest consistency

---

# Pro Investigation Workflow

The Pro Investigation Workspace provides a structured workflow for examining an investigation.

Available workspace sections include:

1. Overview
2. Findings
3. Timeline
4. Attack Chain
5. Process Tree
6. MITRE
7. Threat Assessment
8. False-Positive Analysis
9. Evidence
10. IOCs
11. Correlations
12. Report

The reporting workflow supports:

- Markdown reports
- JSON reports
- Combined report generation
- Evidence package creation
- Evidence package verification
- Report history

---

# Pro Pricing

## Complete Pro License

**₦60,000**

The complete Pro license provides access to the full LogViewer Pro feature set.

### License Duration

**1 year**

### Annual Renewal

**₦45,000 per year**

Customers who want to continue using Pro after the initial license period can renew for ₦45,000 per year.

## Individual Pro Feature Pricing

| Feature | Price |
|---|---:|
| Investigation | ₦15,000 |
| Threat Scoring | ₦8,000 |
| MITRE ATT&CK Mapping | ₦10,000 |
| False-Positive Analysis | ₦8,000 |
| Process Tree Analysis | ₦10,000 |
| Attack-Chain Reconstruction | ₦12,000 |
| Investigation Timeline | ₦8,000 |
| Investigation Findings | ₦10,000 |
| Investigation Reporting | ₦10,000 |
| Evidence Packages and Verification | ₦12,000 |

**Individual feature values total: ₦103,000**

The complete Pro license is offered at **₦60,000 for one year** and includes the complete Pro feature set.

# Pro Purchase and Contact

LogViewer Pro is a paid commercial product.

### Current Pro Price

**₦60,000 for 1 year**

### Renewal

**₦45,000 per year**

### Official Contact

**Phone:** `07037444639`

**WhatsApp:** `08076431994`

**Email:** `olamiogungbamila@gmail.com`

Customers can use these official contact channels for:

- Current payment instructions
- Payment confirmation
- Pro license issuance
- License activation assistance
- Installation assistance
- Commercial licensing questions
- Technical support
- Product questions

## Purchase Process

1. Contact the Copyright Holder through the official commercial contact channels.
2. Request the current payment instructions.
3. Complete payment using the provided instructions.
4. Send the payment confirmation or transaction reference where appropriate.
5. Provide the information required for license delivery.
6. Receive the applicable LogViewer Pro license.
7. Activate the license using the documented activation procedure.

Payment account details are intentionally not permanently published in the public source repository. Customers should obtain current payment instructions directly through the official commercial contact channels.

For detailed Pro pricing and purchase information, see:

`docs/PRO_PRICING_AND_PURCHASE.md`

For the complete Pro purchase and customer agreement, see:

`docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md`

---

# Pro Customer Purchase and Support Terms

LogViewer Pro is a paid, commercially licensed product.

## Purchase and Delivery

- The applicable Pro purchase price must be paid and confirmed before a Pro license is issued or Pro access is delivered, unless a separate written agreement states otherwise.
- Each customer may receive a unique Pro License containing the applicable license ID, features, issue date, expiration date, and entitlement information.
- A Pro License does not transfer ownership of LogViewer, its source code, copyright, or other intellectual property.

## Customer Support

Customers who experience a problem with LogViewer Pro should contact the Copyright Holder through the official support channels:

- **Email:** `olamiogungbamila@gmail.com`
- **Phone / WhatsApp:** `08076431994`

Customers should provide their license ID, LogViewer version, affected feature, description of the problem, relevant error information, and other non-sensitive diagnostic information where reasonably possible.

## License Protection

Customers may not intentionally:

- Share Pro license credentials with unauthorized users
- Resell or transfer a license without authorization
- Publish activation credentials
- Circumvent Pro licensing or entitlement controls
- Redistribute paid Pro functionality without authorization

## Refunds and Disputes

Refund requests, cancellations, and remedies are handled according to the applicable purchase terms and mandatory legal rights.

Customers should contact the Copyright Holder promptly if payment, activation, or a material technical problem affects their purchase.

For significant commercial transactions, a separate written commercial agreement may specify additional pricing, support, licensing, royalty, governing-law, and dispute-resolution terms.

## Full Pro Purchase Agreement

This section is only a summary of the Pro commercial terms.

For the complete terms, conditions, customer obligations, payment requirements, support procedures, refund provisions, license restrictions, termination provisions, commercial royalty obligations, transaction records, and dispute information, customers should read:

`docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md`

The full Pro Purchase Agreement contains the detailed terms that apply to the purchase and use of LogViewer Pro.

**Important:** The README provides a customer-friendly summary. The applicable license and purchase agreement contain the controlling legal terms.

---

# Licensing

LogViewer is distributed under the license contained in `LICENSE`.

LogViewer Core may be used subject to the terms of that license.

LogViewer Pro functionality requires an applicable valid Pro License or other written commercial authorization from the Copyright Holder.

A Pro License may include:

- A defined license period
- A defined feature scope
- Activation and entitlement controls
- License expiration
- License identification
- License verification
- Other terms stated in the applicable commercial documentation or written agreement

For current Pro pricing and purchase procedures, see:

`docs/PRO_PRICING_AND_PURCHASE.md`

For complete Pro commercial purchase terms, customers should read:

`docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md`

The Pro Purchase Agreement provides detailed terms covering:

- Payment before Pro license delivery
- Pro license issuance and entitlement
- Customer acceptance
- Technical support and problem reporting
- Refunds and cancellations
- Unauthorized license sharing and redistribution
- License termination
- Commercial royalty obligations
- Transaction and payment records
- Dispute handling

Unless a separate written agreement states otherwise, the applicable Pro purchase price must be paid and confirmed before a Pro License is issued or Pro access is delivered.

The Pro Purchase Agreement supplements the main LogViewer license for Pro commercial transactions.

---

# License Activation

Pro licenses are digitally signed entitlements.

License activation verifies the issued license and determines which Pro features are available.

A license may contain information such as:

- License ID
- Customer
- Edition
- Issue date
- Expiration date
- Enabled features
- Signature information

Customers must not modify license files.

Changing license contents can cause license verification to fail.

For activation instructions, see:

`docs/LICENSE_ACTIVATION.md`

---

# Documentation

| Document | Purpose |
|---|---|
| `README.md` | Project overview and primary documentation |
| `INSTALL.md` | Installation instructions |
| `LICENSE` | Software license |
| `docs/PRO.md` | LogViewer Pro documentation |
| `docs/PRO_PRICING_AND_PURCHASE.md` | Pro pricing and purchase information |
| `docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md` | Complete Pro commercial purchase agreement |
| `docs/LICENSE_ACTIVATION.md` | License activation documentation |
| `docs/TROUBLESHOOTING.md` | Troubleshooting information |
| `docs/SUPPORT.md` | Support procedures |
| `CHANGELOG.md` | Release history |

---

# Installation

## Requirements

LogViewer is intended for Linux systems.

Python dependencies are listed in:

`requirements.txt`

Project packaging and dependency metadata are maintained in:

`pyproject.toml`

## Installation

Clone the repository:

```bash
git clone https://github.com/Olamitemmy02/Logviewer.git
cd Logviewer
```

Create a virtual environment:

```bash
python3 -m venv log_env
source log_env/bin/activate
```

Install the project:

```bash
python3 -m pip install -e .
```

Run LogViewer:

```bash
logviewer
```

---

# Configuration

LogViewer uses configuration information for settings such as:

- Log directory
- Export directory
- Theme
- Logging level

The default project configuration is stored in:

`config.json`

Generated runtime data should not be committed to the repository.

---

# Security and Privacy

LogViewer is designed to analyze security and system log information locally.

Users should consider the sensitivity of the logs being analyzed.

Log files may contain:

- Usernames
- IP addresses
- Hostnames
- Authentication information
- Process information
- Network information
- Security events
- Other potentially sensitive system information

Do not publish sensitive logs to public repositories.

Do not include:

- Passwords
- Private keys
- Credentials
- API secrets
- License-generator credentials
- Recovery codes
- Confidential customer information

in public reports, screenshots, demonstrations, or repository commits.

The LogViewer Pro license signing private key must remain under the control of the Copyright Holder and must never be distributed to customers.

---

# Repository Hygiene

Generated and machine-specific files should remain outside the public source repository.

The repository excludes items such as:

- Python cache files
- Virtual environments
- Build directories
- Packaging metadata
- Runtime logs
- Generated investigation data
- Generated exports
- Local configuration secrets
- Private signing keys
- License-generator credentials
- Test caches

Public verification keys may be included where required for license verification.

---

# Testing

The project contains automated tests covering Core functionality and Pro functionality.

Run the test suite with:

```bash
python -m pytest
```

Additional validation and release checks are maintained under the project's testing and release tooling.

Before a commercial release, the project should be validated for:

- Core functionality
- Pro feature access
- License verification
- Feature gating
- Investigation workflows
- Report generation
- Evidence package generation
- Evidence verification
- Installation
- Dependency integrity
- Repository hygiene

---

# Architecture

LogViewer is organized into modular components.

```text
logviewer/
├── analysis/
├── config/
├── events.py
├── licensing/
├── menu.py
├── parsers/
├── pro/
├── reports/
├── sources/
└── ...
```

The Pro architecture separates advanced investigation functionality from the Core platform through feature gating and licensing controls.

Major Pro components include:

```text
logviewer/pro/
├── investigation/
├── mitre/
├── reporting/
└── ...
```

The investigation subsystem provides structured models, storage, analysis, timelines, findings, reporting, and evidence handling.

---

# Security Analysis

LogViewer supports evidence-driven analysis rather than treating individual log entries as automatic proof of malicious activity.

Analytical results should be interpreted using the underlying evidence.

Important distinctions include:

- Observed event
- Correlated activity
- IOC
- MITRE technique mapping
- Threat score
- Finding
- Analyst interpretation

A generated score, finding, or mapping should be reviewed together with the underlying log evidence.

---

# Release Information

The project maintains Core and Pro commercial release artifacts separately from development files.

The signed commercial release artifacts currently documented by the release process are:

```text
LogViewer-Core-1.0.0.tar.gz
LogViewer-Pro-1.0.0.tar.gz
```

The documented 1.0.0 commercial artifacts have their own release checksums and validation records.

The README product documentation identifies the current product line as **LogViewer 2.0**. A future 2.0 commercial artifact release requires its own intentional versioning, build, validation, checksum, and release sign-off process.

---

# Development Status

LogViewer has completed the core investigation, Pro investigation, licensing, reporting, evidence, testing, and commercial release integration work required for the current product line.

The project continues to evolve through:

- Security improvements
- Investigation improvements
- Parser improvements
- Detection improvements
- Documentation improvements
- Pro feature development
- Customer-facing improvements
- Release engineering

---

# Design Principles

LogViewer follows several design principles.

## Evidence Driven

Security conclusions should be supported by available evidence.

## Modular

Core capabilities and Pro investigation capabilities are separated into maintainable components.

## Auditable

Investigation results should remain traceable to the underlying events and evidence.

## Practical

The platform is designed around real Linux logs and practical investigation workflows.

## Extensible

New parsers, analysis methods, detections, and investigation capabilities can be added without redesigning the entire platform.

## Security Conscious

Sensitive information, credentials, private keys, and customer information should be protected throughout the development and operational lifecycle.

---

# Project Vision

The long-term goal of LogViewer is to provide a practical Linux security investigation platform that combines:

- Real log analysis
- Security event correlation
- IOC extraction
- Structured investigations
- Threat analysis
- MITRE ATT&CK mapping
- Evidence-based findings
- Investigation reporting
- Evidence integrity verification
- Commercially controlled advanced capabilities

The project is intended to grow into a broader evidence-driven security investigation platform while remaining practical for Linux environments.

---

# Support

For LogViewer support and commercial enquiries:

**Email:** `olamiogungbamila@gmail.com`

**Phone:** `07037444639`

**WhatsApp:** `08076431994`

For technical support procedures, see:

`docs/SUPPORT.md`

For Pro purchasing information, see:

`docs/PRO_PRICING_AND_PURCHASE.md`

For the complete Pro commercial agreement, see:

`docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md`

---

# Disclaimer

LogViewer provides analytical tools for examining system and security log data.

Security findings, threat scores, IOC extraction, correlations, MITRE mappings, false-positive analysis, and other analytical results should be reviewed by a qualified analyst.

The presence of an event or analytical finding does not automatically establish malicious intent or compromise.

Users are responsible for validating investigation conclusions against the available evidence and their operational environment.

---

# License

Copyright © 2026 Olami Ogungbamila.

LogViewer is provided under the terms contained in the `LICENSE` file.

For Pro commercial transactions, the applicable Pro Purchase Agreement and other written commercial terms may also apply.

See:

`LICENSE`

`docs/PRO_TERMS_AND_PURCHASE_AGREEMENT.md`

---

# Project Structure

```text
LogViewer/
├── config.json
├── docs/
├── exports/
├── logviewer/
├── tests/
├── tools/
├── .gitignore
├── CHANGELOG.md
├── INSTALL.md
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements.txt
```

Generated runtime data, local virtual environments, private signing keys, credentials, and other machine-specific files should remain outside the public repository.
