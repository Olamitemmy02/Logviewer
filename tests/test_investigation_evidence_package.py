from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from logviewer.pro.investigation.model import Investigation
from logviewer.pro.reporting import (
    InvestigationEvidencePackageBuilder,
)


def build_investigation(
    investigation_id: str = "INV-15D-001",
) -> Investigation:
    investigation = Investigation(
        investigation_id=investigation_id,
        title="Evidence Package Test Investigation",
        status="open",
        severity="high",
        confidence=0.91,
    )

    investigation.events = [
        {
            "event_id": "event-001",
            "message": "Authentication event",
        }
    ]

    investigation.evidence = [
        {
            "evidence_id": "evidence-001",
            "source": "/var/log/auth.log",
        }
    ]

    investigation.iocs = [
        {
            "type": "ip",
            "value": "10.0.2.50",
        }
    ]

    investigation.correlations = [
        {
            "correlation_id": "corr-001",
            "event_ids": ["event-001"],
        }
    ]

    investigation.mitre_mappings = [
        {
            "technique": "T1078",
            "name": "Valid Accounts",
        }
    ]

    investigation.findings = [
        {
            "finding_id": "finding-001",
            "title": "Authentication Activity",
            "severity": "medium",
            "confidence": 0.8,
            "summary": "Authentication activity requires review.",
        }
    ]

    investigation.process_tree = {
        "node_count": 1,
        "relationship_count": 0,
        "nodes": [
            {
                "node_id": "process-001",
                "name": "sshd",
            }
        ],
        "relationships": [],
    }

    investigation.attack_chain = {
        "summary": {
            "step_count": 1,
            "link_count": 0,
            "technique_count": 1,
            "tactic_count": 1,
            "process_relationship_count": 0,
        },
        "steps": [
            {
                "step_id": "step-001",
                "technique": "T1078",
            }
        ],
        "links": [],
    }

    investigation.timeline = {
        "summary": {
            "entry_count": 1,
            "event_count": 1,
            "correlation_count": 0,
            "mitre_count": 1,
            "process_relationship_count": 0,
            "attack_chain_step_count": 1,
            "gap_count": 0,
            "confidence": 0.9,
        },
        "entries": [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "event-001",
            }
        ],
        "gaps": [],
    }

    investigation.false_positive_analysis = {
        "possible": True,
        "confidence": 0.2,
        "reason": "Expected administrative activity is possible.",
    }

    investigation.threat_score = 42
    investigation.threat_level = "medium"
    investigation.threat_score_details = {
        "base": 42,
    }

    investigation.metadata = {
        "test": True,
        "source": "unit-test",
    }

    return investigation


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_build_creates_evidence_package(tmp_path: Path) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    assert package_path.exists()
    assert package_path.name == (
        "investigation_INV-15D-001_evidence.zip"
    )

    with zipfile.ZipFile(package_path) as archive:
        names = sorted(archive.namelist())

        assert names == [
            "investigation_INV-15D-001/manifest.json",
            "investigation_INV-15D-001/report.json",
            "investigation_INV-15D-001/report.md",
        ]


def test_manifest_contains_integrity_hashes(tmp_path: Path) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    with zipfile.ZipFile(package_path) as archive:
        manifest = json.loads(
            archive.read(
                "investigation_INV-15D-001/manifest.json"
            ).decode("utf-8")
        )

        report_md = archive.read(
            "investigation_INV-15D-001/report.md"
        )
        report_json = archive.read(
            "investigation_INV-15D-001/report.json"
        )

    assert manifest["package_version"] == "1.0"
    assert manifest["investigation"]["investigation_id"] == (
        "INV-15D-001"
    )

    assert manifest["integrity"]["algorithm"] == "SHA-256"

    files = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    md_entry = files[
        "investigation_INV-15D-001/report.md"
    ]
    json_entry = files[
        "investigation_INV-15D-001/report.json"
    ]

    assert md_entry["sha256"] == sha256_bytes(report_md)
    assert json_entry["sha256"] == sha256_bytes(report_json)
    assert md_entry["size"] == len(report_md)
    assert json_entry["size"] == len(report_json)


def test_report_json_contains_existing_report_data(
    tmp_path: Path,
) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    with zipfile.ZipFile(package_path) as archive:
        report = json.loads(
            archive.read(
                "investigation_INV-15D-001/report.json"
            ).decode("utf-8")
        )

    assert report["report_version"] == "1.0"
    assert report["investigation"]["investigation_id"] == (
        "INV-15D-001"
    )
    assert report["investigation"]["title"] == (
        "Evidence Package Test Investigation"
    )
    assert len(report["events"]) == 1
    assert len(report["evidence"]) == 1
    assert len(report["findings"]) == 1


def test_markdown_report_is_present_and_readable(
    tmp_path: Path,
) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    with zipfile.ZipFile(package_path) as archive:
        markdown = archive.read(
            "investigation_INV-15D-001/report.md"
        ).decode("utf-8")

    assert "# Investigation Report:" in markdown
    assert "Evidence Package Test Investigation" in markdown
    assert "## 3. Findings" in markdown
    assert "## 12. Analyst-Ready Conclusion" in markdown


def test_build_manifest_without_creating_package(
    tmp_path: Path,
) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    manifest = builder.build_manifest(investigation)

    assert manifest["package_version"] == "1.0"
    assert manifest["investigation"]["investigation_id"] == (
        "INV-15D-001"
    )
    assert len(manifest["files"]) == 2
    assert all(
        len(entry["sha256"]) == 64
        for entry in manifest["files"]
    )

    assert not list(tmp_path.glob("*.zip"))


def test_investigation_id_is_safely_sanitized(
    tmp_path: Path,
) -> None:
    investigation = build_investigation(
        investigation_id="../../INV 15D/unsafe"
    )

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    assert package_path.name == (
        "investigation_INV_15D_unsafe_evidence.zip"
    )

    with zipfile.ZipFile(package_path) as archive:
        names = archive.namelist()

    assert all(
        not name.startswith("/")
        for name in names
    )
    assert all(
        ".." not in Path(name).parts
        for name in names
    )


def test_existing_package_is_replaced(
    tmp_path: Path,
) -> None:
    investigation = build_investigation()

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    first = builder.build(investigation)
    first_bytes = first.read_bytes()

    second = builder.build(investigation)
    second_bytes = second.read_bytes()

    assert first == second
    assert second.exists()
    assert first_bytes
    assert second_bytes


def test_reporting_imports() -> None:
    from logviewer.pro.reporting import (
        InvestigationEvidencePackageBuilder,
        InvestigationReportExporter,
        InvestigationReportGenerator,
    )

    assert InvestigationEvidencePackageBuilder is not None
    assert InvestigationReportExporter is not None
    assert InvestigationReportGenerator is not None
