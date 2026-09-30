# LogViewer Changelog

## LogViewer 1.0.0 — Commercial Release

LogViewer 1.0.0 is the commercial release of the evidence-driven Linux log investigation platform.

The release provides two distributions:

- LogViewer Core
- LogViewer Pro

### Core

Core provides:

- Log viewing
- Log searching
- Log filtering
- Live monitoring
- Statistics
- Report export
- Log source discovery
- Snort alert summaries
- IOC extraction
- Security correlation
- Security analysis
- Application settings
- License management

### Pro

Pro adds eight licensed security investigation features:

- `investigation`
- `threat_scoring`
- `mitre`
- `false_positive_analysis`
- `process_tree`
- `attack_chain`
- `timeline`
- `findings`

Pro also provides investigation reporting, Markdown and JSON reports, evidence packages, and evidence-package verification using SHA-256 integrity checks.

### Licensing

Pro functionality is controlled through signed license entitlement.

License verification uses Ed25519 public-key cryptography.

Customer licenses are issued separately from the application distribution.

Private signing material is never distributed as customer installation material.

### Release Artifacts

Core:

`release/dist/LogViewer-Core-1.0.0.tar.gz`

Pro:

`release/dist/LogViewer-Pro-1.0.0.tar.gz`

### Signed-Off SHA-256 Checksums

Core:

a54059f027419c40d10908f5e7fada596757e2a40810a7646903292254e2d98d

Pro:

b4e4024284d74909a827241efda648ddf1b04f76196cb111f12f88d0c959651c
