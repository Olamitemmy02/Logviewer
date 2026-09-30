# LogViewer Troubleshooting

## LogViewer Does Not Start

Check installation:

    python -m pip show logviewer

Check Python:

    python --version

Try starting LogViewer:

    logviewer

If an import or package error occurs, verify that the intended Python environment is active.

## Permission Denied

A **Permission Denied** error normally means the account running LogViewer cannot access the requested file or directory.

Check a log file:

    ls -l /var/log/auth.log

Check its parent directory:

    ls -ld /var/log

Do not unnecessarily weaken system permissions.

## Missing Log Source

Not every Linux host contains every supported log source.

Check whether the expected source exists.

For example:

    ls -l /var/log/auth.log
    ls -l /var/log/syslog
    ls -l /var/log/kern.log

Availability depends on:

- Linux distribution
- Installed services
- Logging configuration
- Service activity
- Permissions

## Missing Snort Alerts

Check whether Snort is installed:

    snort --version

Check the configured Snort logging location.

Snort versions and configurations can produce different alert formats and locations.

## Pro Features Are Locked

If Pro features are locked:

1. Open License Management.
2. Check license status.
3. Confirm that the license is valid.
4. Check expiration.
5. Confirm the required feature entitlement.
6. Reactivate with a valid license if necessary.

The eight Pro feature IDs are:

    investigation
    threat_scoring
    mitre
    false_positive_analysis
    process_tree
    attack_chain
    timeline
    findings

## License Activation Fails

Check:

- The complete license token was supplied.
- The token was not modified.
- The license belongs to the expected product.
- The license has not expired.
- The system clock is correct.
- The required feature entitlement exists.

Do not modify the cryptographic contents of a license token.

## Reports Are Missing

Check the configured export directory.

Verify that the application account can write to that location.

For Pro investigation reports, confirm that the investigation exists and that the report operation completed successfully.

Supported report formats include:

- Markdown
- JSON

## Evidence Package Verification Fails

A failed evidence verification can indicate:

- Missing required file
- Modified file
- Changed file size
- Changed SHA-256 hash
- Invalid manifest
- Unsafe package path
- Damaged archive

Do not treat a failed verification as an intact evidence package.

## Python Problems

Check Python:

    python --version

Check pip:

    python -m pip --version

Check LogViewer:

    python -m pip show logviewer

If using a virtual environment, activate it before running LogViewer.

## Release Archive Verification

Signed-off Core SHA-256:

    a54059f027419c40d10908f5e7fada596757e2a40810a7646903292254e2d98d

Signed-off Pro SHA-256:

    b4e4024284d74909a827241efda648ddf1b04f76196cb111f12f88d0c959651c

Verify Core:

    sha256sum LogViewer-Core-1.0.0.tar.gz

Verify Pro:

    sha256sum LogViewer-Pro-1.0.0.tar.gz

A checksum mismatch means the archive should not be treated as the signed-off release artifact.

## Detailed Documentation

Core:

    docs/CORE.md

Pro:

    docs/PRO.md

License:

    docs/LICENSE_ACTIVATION.md

Support:

    docs/SUPPORT.md

Check `docs/SUPPORT.md` if troubleshooting does not resolve the problem.
