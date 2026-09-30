from __future__ import annotations

import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# ----------------------------------------------------------------------
# Always test the current source tree, not an older installed package.
# ----------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT))


from logviewer.events import Event
from logviewer.licensing.feature_gate import (
    FeatureAccessError,
    FeatureGate,
)
from logviewer.licensing.license_manager import LicenseManager
from logviewer.pro.investigation.service import InvestigationService
from logviewer.pro.investigation.store import InvestigationStore
from logviewer.pro.reporting.evidence_package import (
    InvestigationEvidencePackageBuilder,
)
from logviewer.pro.reporting.evidence_package_verifier import (
    InvestigationEvidencePackageVerifier,
)
from logviewer.pro.reporting.exporter import (
    InvestigationReportExporter,
)
from logviewer.pro.reporting.investigation_report import (
    InvestigationReportGenerator,
)


PRO_FEATURES = [
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive_analysis",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
]


def _create_signed_license(
    tmp_path: Path,
) -> Path:
    """
    Generate a real signed full-Pro license using the production
    license issuer.

    The private signing key is read only. This test never modifies
    or replaces the user's real signing key.
    """

    private_key = (
        Path.home()
        / ".config"
        / "logviewer"
        / "logviewer_private_key.pem"
    )

    if not private_key.exists():
        pytest.fail(
            f"Required local signing key was not found: {private_key}"
        )

    issued_directory = tmp_path / "issued"
    issued_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        issued_directory
        / "pro_release_flow.license"
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=30)
    ).date().isoformat()

    command = [
        sys.executable,
        str(PROJECT_ROOT / "tools" / "license_issuer.py"),
        "--customer",
        "16F-C-FULL-FLOW",
        "--edition",
        "PRO",
    ]

    for feature in PRO_FEATURES:
        command.extend(
            [
                "--feature",
                feature,
            ]
        )

    command.extend(
        [
            "--expires",
            expires_at,
            "--license-id",
            "LV-16F-C-FULL-FLOW",
            "--private-key",
            str(private_key),
            "--output",
            str(output_path),
        ]
    )

    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, (
        "License issuer failed.\n\n"
        f"STDOUT:\n{completed.stdout}\n\n"
        f"STDERR:\n{completed.stderr}"
    )

    assert output_path.exists()
    assert output_path.stat().st_size > 0

    return output_path


def _build_events() -> list[Event]:
    """
    Real normalized LogViewer Event objects.

    The repeated SSH activity gives the Pro pipeline meaningful
    authentication, network, process, and IOC context.
    """

    return [
        Event(
            timestamp="2026-09-23T10:00:00",
            source="auth.log",
            severity="HIGH",
            message=(
                "Failed SSH authentication from 192.0.2.50 "
                "for user admin"
            ),
            event_type="authentication_failure",
            host="test-host",
            user="admin",
            protocol="ssh",
            src_ip="192.0.2.50",
            src_port=54321,
            dst_ip="10.0.2.9",
            dst_port=22,
            process="sshd",
            pid=1200,
            parent_pid=1,
            command="/usr/sbin/sshd",
            action="failed",
        ),
        Event(
            timestamp="2026-09-23T10:00:05",
            source="auth.log",
            severity="HIGH",
            message=(
                "Failed SSH authentication from 192.0.2.50 "
                "for user admin"
            ),
            event_type="authentication_failure",
            host="test-host",
            user="admin",
            protocol="ssh",
            src_ip="192.0.2.50",
            src_port=54322,
            dst_ip="10.0.2.9",
            dst_port=22,
            process="sshd",
            pid=1201,
            parent_pid=1,
            command="/usr/sbin/sshd",
            action="failed",
        ),
        Event(
            timestamp="2026-09-23T10:00:12",
            source="auth.log",
            severity="MEDIUM",
            message=(
                "Repeated SSH authentication attempt "
                "from 192.0.2.50"
            ),
            event_type="authentication_failure",
            host="test-host",
            user="admin",
            protocol="ssh",
            src_ip="192.0.2.50",
            src_port=54323,
            dst_ip="10.0.2.9",
            dst_port=22,
            process="sshd",
            pid=1202,
            parent_pid=1,
            command="/usr/sbin/sshd",
            action="failed",
        ),
    ]


def test_full_pro_investigation_release_flow(
    tmp_path: Path,
) -> None:
    """
    Step 16F-C.

    Complete licensed Pro release flow:

        signed license
            ->
        LicenseManager
            ->
        FeatureGate
            ->
        InvestigationService
            ->
        Pro analysis
            ->
        persistence
            ->
        findings/timeline/attack-chain
            ->
        report generation
            ->
        Markdown/JSON export
            ->
        evidence package
            ->
        SHA-256 verification
            ->
        license removal
            ->
        Pro access revoked
    """

    license_path = (
        tmp_path / "license.key"
    )

    investigation_directory = (
        tmp_path / "investigations"
    )

    export_directory = (
        tmp_path / "exports"
    )

    investigation_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    export_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ==============================================================
    # 1. Generate a real signed full-Pro license.
    # ==============================================================

    issued_license = _create_signed_license(
        tmp_path
    )

    token = issued_license.read_text(
        encoding="utf-8"
    ).strip()

    assert token

    # ==============================================================
    # 2. Install the license into an isolated temporary location.
    # ==============================================================

    manager = LicenseManager(
        license_path=license_path
    )

    verification = manager.install(
        token
    )

    assert verification.valid is True
    assert verification.license is not None

    assert (
        verification.license.license_id
        == "LV-16F-C-FULL-FLOW"
    )

    assert (
        verification.license.edition
        == "PRO"
    )

    # ==============================================================
    # 3. Verify all eight Pro features through the real FeatureGate.
    # ==============================================================

    gate = FeatureGate(
        license_manager=manager
    )

    for feature in PRO_FEATURES:
        assert gate.check(feature) is True

    # ==============================================================
    # 4. Build the investigation service with isolated persistence.
    # ==============================================================

    store = InvestigationStore(
        root=investigation_directory
    )

    service = InvestigationService(
        feature_gate=gate,
        store=store,
    )

    events = _build_events()

    investigation = service.create(
        investigation_id="16F-C-FULL-FLOW",
        events=events,
        title=(
            "16F-C Full Pro Investigation "
            "Release Flow"
        ),
    )

    assert (
        investigation.investigation_id
        == "16F-C-FULL-FLOW"
    )

    assert (
        investigation.title
        == (
            "16F-C Full Pro Investigation "
            "Release Flow"
        )
    )

    # ==============================================================
    # 5. Core investigation data.
    # ==============================================================

    assert len(
        investigation.events
    ) == 3

    assert len(
        investigation.evidence
    ) == 3

    assert investigation.iocs
    assert investigation.mitre_mappings

    # ==============================================================
    # 6. Pro analysis artifacts.
    # ==============================================================

    assert (
        investigation.threat_score
        is not None
    )

    assert investigation.threat_level

    assert (
        investigation.false_positive_analysis
    )

    assert investigation.process_tree
    assert investigation.attack_chain
    assert investigation.timeline
    assert investigation.findings

    assert (
        investigation.attack_chain["summary"]
    )

    assert (
        investigation.timeline["summary"]
    )

    assert (
        investigation.attack_chain[
            "summary"
        ]["step_count"]
        >= 0
    )

    assert (
        investigation.timeline[
            "summary"
        ]["entry_count"]
        >= 0
    )

    # ==============================================================
    # 7. Validate structured findings.
    # ==============================================================

    for finding in investigation.findings:
        assert finding["finding_id"].startswith(
            "F-"
        )

        assert finding["title"]
        assert finding["summary"]

        assert finding["severity"] in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        assert (
            0.0
            <= finding["confidence"]
            <= 1.0
        )

        assert "rationale" in finding
        assert "event_ids" in finding
        assert "evidence_ids" in finding
        assert "ioc_values" in finding
        assert "mitre_techniques" in finding
        assert "correlation_ids" in finding
        assert "false_positive_context" in finding
        assert "metadata" in finding

    # ==============================================================
    # 8. Verify persistence through the service boundary.
    # ==============================================================

    stored_files = list(
        investigation_directory.glob(
            "*.json"
        )
    )

    assert stored_files

    loaded = service.get(
        "16F-C-FULL-FLOW"
    )

    assert loaded is not None

    assert (
        loaded.investigation_id
        == investigation.investigation_id
    )

    assert (
        loaded.title
        == investigation.title
    )

    assert (
        loaded.findings
        == investigation.findings
    )

    assert (
        loaded.mitre_mappings
        == investigation.mitre_mappings
    )

    # ==============================================================
    # 9. Generate the analyst report.
    # ==============================================================

    generator = (
        InvestigationReportGenerator()
    )

    report_data = generator.build_data(
        investigation
    )

    assert (
        report_data["investigation"][
            "investigation_id"
        ]
        == "16F-C-FULL-FLOW"
    )

    markdown_report = (
        generator.render_markdown(
            investigation
        )
    )

    assert (
        "# Investigation Report:"
        in markdown_report
    )

    assert (
        "## 3. Findings"
        in markdown_report
    )

    assert (
        "## 7. MITRE ATT&CK Mappings"
        in markdown_report
    )

    assert (
        "## 9. Attack Chain"
        in markdown_report
    )

    assert (
        "## 10. Timeline"
        in markdown_report
    )

    assert (
        "## 12. Analyst-Ready Conclusion"
        in markdown_report
    )

    # ==============================================================
    # 10. Export Markdown and JSON.
    # ==============================================================

    exporter = (
        InvestigationReportExporter(
            export_directory=export_directory
        )
    )

    exported = exporter.export_all(
        investigation
    )

    markdown_path = (
        export_directory
        / "investigation_16F-C-FULL-FLOW.md"
    )

    json_path = (
        export_directory
        / "investigation_16F-C-FULL-FLOW.json"
    )

    assert markdown_path.exists()
    assert json_path.exists()

    assert markdown_path in exported.values()
    assert json_path in exported.values()

    assert markdown_path.read_text(
        encoding="utf-8"
    )

    assert json_path.read_text(
        encoding="utf-8"
    )

    # ==============================================================
    # 11. Build the evidence package.
    # ==============================================================

    package_builder = (
        InvestigationEvidencePackageBuilder(
            export_directory=export_directory
        )
    )

    package_path = (
        package_builder.build(
            investigation
        )
    )

    assert package_path.exists()
    assert package_path.suffix == ".zip"

    # ==============================================================
    # 12. Verify the package with the production verifier.
    # ==============================================================

    verifier = (
        InvestigationEvidencePackageVerifier()
    )

    verification_result = (
        verifier.verify(package_path)
    )

    assert (
        verification_result["verified"]
        is True
    )

    assert (
        verification_result["status"]
        == "verified"
    )

    assert (
        verification_result["errors"]
        == []
    )

    assert (
        verification_result["algorithm"]
        == "SHA-256"
    )

    assert (
        verification_result[
            "investigation"
        ]["id"]
        == "16F-C-FULL-FLOW"
    )

    assert (
        verification_result[
            "investigation"
        ]["title"]
        == (
            "16F-C Full Pro Investigation "
            "Release Flow"
        )
    )

    assert len(
        verification_result["files"]
    ) == 2

    assert all(
        item["verified"]
        for item in verification_result[
            "files"
        ]
    )

    assert all(
        item["expected_sha256"]
        == item["actual_sha256"]
        for item in verification_result[
            "files"
        ]
    )

    # ==============================================================
    # 13. Confirm the evidence ZIP contains the expected artifacts.
    # ==============================================================

    with zipfile.ZipFile(
        package_path,
        "r",
    ) as archive:
        names = set(
            archive.namelist()
        )

    package_root = (
        "investigation_16F-C-FULL-FLOW/"
    )

    assert (
        package_root + "report.md"
        in names
    )

    assert (
        package_root + "report.json"
        in names
    )

    assert (
        package_root + "manifest.json"
        in names
    )

    # ==============================================================
    # 14. Remove the temporary license and confirm Pro is blocked.
    # ==============================================================

    assert manager.remove() is True
    assert manager.is_activated() is False

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False

    with pytest.raises(
        FeatureAccessError
    ):
        gate.require(
            "investigation"
        )

    # ==============================================================
    # 15. Confirm this test never created a default license.
    # ==============================================================

    assert license_path.exists() is False


if __name__ == "__main__":
    raise SystemExit(
        pytest.main(
            [
                __file__,
                "-q",
            ]
        )
    )
