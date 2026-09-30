# LogViewer License Activation

## Overview

LogViewer Core does not require a Pro license.

LogViewer Pro features require a valid signed license containing the appropriate feature entitlements.

The license lifecycle includes issuance, delivery, activation, verification, status inspection, expiration handling, and deactivation.

## Pro Feature Entitlements

The following feature IDs are used for Pro entitlement checks:

    `investigation`

    `threat_scoring`

    `mitre`

    `false_positive_analysis`

    `process_tree`

    `attack_chain`

    `timeline`

    `findings`

A customer license must contain the appropriate feature entitlement before the corresponding Pro functionality can be used.

## License Activation

Activation installs a signed customer license into the application's configured license location.

The application verifies the license before accepting it.

An invalid license must not be treated as an active Pro entitlement.

Activation does not modify the application's private signing material.

## License Status

The license status operation can report:

- Whether a valid license is installed
- License ID
- Customer or license metadata available to the application
- Expiration information
- Enabled feature entitlements
- License path
- Verification reason when a license is invalid or unavailable

Use the application's License Management menu to inspect the current status.

## Feature Entitlement

Feature access is checked individually.

A valid license may contain a subset of Pro features. A feature is available only when the license contains the corresponding feature entitlement.

The application's feature gate controls access to:

    `investigation`

    `threat_scoring`

    `mitre`

    `false_positive_analysis`

    `process_tree`

    `attack_chain`

    `timeline`

    `findings`

## Expiration

License expiration is enforced during license verification.

An expired license must not provide valid Pro entitlement.

Customers should obtain a valid replacement license before the current license expires when continued Pro access is required.

## Deactivation

Deactivation removes the installed customer license from the application's configured license location.

After deactivation, Pro feature checks should no longer grant access based on the removed license.

Deactivation does not remove the LogViewer Core installation.

## License Security

Customer licenses are signed so that the application can verify their authenticity and integrity.

The private signing key is issuer-side material and must never be distributed with customer releases, customer licenses, or customer installation packages.

Customers should protect their issued license files and avoid modifying them.

## License Lifecycle Summary

The normal customer lifecycle is:

1. Receive an issued license.
2. Activate the license in LogViewer.
3. Check license status.
4. Use the features included in the license entitlement.
5. Monitor expiration information.
6. Replace an expired or expiring license when necessary.
7. Deactivate the license when Pro access is no longer required.

## More Information

Troubleshooting:

    docs/TROUBLESHOOTING.md

Support:

    docs/SUPPORT.md
