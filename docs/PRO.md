# LogViewer Pro

## Overview

LogViewer Pro extends the Core platform with structured security investigation capabilities.

Pro is distributed as a licensed product. Access to Pro functionality is controlled by the application's signed license entitlement system.

The Pro feature set is designed for evidence-driven investigation rather than treating individual log events as automatic proof of malicious activity.

## Pro Features

### Investigation

Feature ID:

    `investigation`

Provides the main investigation workflow for collecting and organizing security events, evidence, IOCs, correlations, MITRE mappings, analysis results, and investigation metadata.

### Threat Scoring

Feature ID:

    `threat_scoring`

Provides threat scoring and threat-level assessment based on available investigation evidence.

Scores are analytical indicators and should be interpreted together with the underlying evidence.

### MITRE ATT&CK Mapping

Feature ID:

    `mitre`

Maps relevant investigation activity to MITRE ATT&CK techniques and related tactical information.

A MITRE mapping does not by itself prove that a technique was successfully executed.

### False-Positive Analysis

Feature ID:

    `false_positive_analysis`

Provides contextual analysis of activity that may have legitimate or non-malicious explanations.

The analysis is intended to help investigators evaluate evidence rather than automatically declare an event malicious or benign.

### Process Tree Analysis

Feature ID:

    `process_tree`

Builds process relationships from available process and parent-process information.

Process-tree results depend on the information present in the collected events.

### Attack-Chain Reconstruction

Feature ID:

    `attack_chain`

Reconstructs related investigation activity into an ordered attack-chain representation when sufficient evidence is available.

Attack-chain reconstruction is an analytical representation and should be reviewed against the underlying events.

### Investigation Timeline

Feature ID:

    `timeline`

Builds a chronological representation of investigation events, correlations, MITRE mappings, process relationships, attack-chain steps, and identified gaps.

Timeline results depend on timestamps and available investigation data.

### Investigation Findings

Feature ID:

    `findings`

Produces structured investigation findings from available events, correlations, MITRE mappings, and supporting evidence.

Findings include supporting context and confidence information.

## Investigation Workflow

A Pro investigation can contain:

- Security events
- Evidence records
- Extracted IOCs
- Event correlations
- MITRE ATT&CK mappings
- Threat scores
- False-positive analysis
- Process-tree relationships
- Attack-chain steps
- Timeline entries
- Investigation findings

The investigation workspace provides access to these areas from a single investigation.

## Investigation Reporting

Pro supports investigation reporting through:

- Markdown reports
- JSON reports
- Combined report exports
- Investigation report history

Markdown reports are intended for human-readable investigation documentation.

JSON reports provide structured investigation data for programmatic processing and archival.

## Evidence Packages

Pro can build investigation evidence packages containing the investigation report and supporting structured data.

A standard evidence package contains:

    report.md
    report.json
    manifest.json

The manifest records package metadata and file integrity information.

## Evidence Verification

Evidence verification checks the contents of an evidence package against the package manifest.

Verification includes:

- Required file presence
- Safe package paths
- Recorded file sizes
- SHA-256 integrity hashes
- Manifest consistency

A successfully verified package means the package contents match the integrity information recorded in its manifest. It does not independently establish that the investigation conclusions are correct.

## Evidence and Analytical Limitations

LogViewer Pro works from the information available in collected logs and events.

Missing logs, incomplete timestamps, parser limitations, clock differences, duplicated events, and ambiguous activity can affect investigation results.

Threat scores, MITRE mappings, attack-chain results, timelines, findings, and false-positive analysis should therefore be reviewed together with the original evidence.

## License Entitlement

Pro functionality requires the appropriate signed license entitlement.

The Pro feature IDs are:

    `investigation`
    `threat_scoring`
    `mitre`
    `false_positive_analysis`
    `process_tree`
    `attack_chain`
    `timeline`
    `findings`

For complete licensing information, check:

    docs/LICENSE_ACTIVATION.md

For troubleshooting, check:

    docs/TROUBLESHOOTING.md
