from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from logviewer.pro.reporting import (
    InvestigationEvidencePackageBuilder,
    InvestigationEvidencePackageVerifier,
)


def _build_investigation() -> SimpleNamespace:
    investigation = SimpleNamespace(
        investigation_id="TEST-15F",
        title="Evidence Verification Test",
        status="open",
        severity="high",
        confidence=0.9,
        created_at="2026-09-22T10:00:00",
        updated_at="2026-09-22T10:00:00",
        threat_score=10,
        threat_level="low",
        threat_score_details={},
        false_positive_analysis={},
        events=[],
        evidence=[],
        iocs=[],
        correlations=[],
        mitre_mappings=[],
        findings=[],
        process_tree={
            "summary": {
                "node_count": 0,
                "relationship_count": 0,
            },
            "nodes": [],
            "relationships": [],
        },
        attack_chain={
            "summary": {
                "step_count": 0,
                "link_count": 0,
                "technique_count": 0,
                "tactic_count": 0,
                "process_relationship_count": 0,
            },
            "steps": [],
            "links": [],
        },
        timeline={
            "summary": {
                "entry_count": 0,
                "event_count": 0,
                "correlation_count": 0,
                "mitre_count": 0,
                "process_relationship_count": 0,
                "attack_chain_step_count": 0,
                "gap_count": 0,
                "confidence": 0,
            },
            "entries": [],
            "gaps": [],
        },
        metadata={},
    )

    investigation.summary = lambda: {
        "event_count": 0,
        "evidence_count": 0,
        "ioc_count": 0,
        "correlation_count": 0,
        "mitre_mapping_count": 0,
        "finding_count": 0,
        "process_node_count": 0,
        "process_relationship_count": 0,
        "attack_chain_step_count": 0,
        "timeline_entry_count": 0,
    }

    return investigation


def _build_package(tmp_path: Path) -> Path:
    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path,
    )
    return builder.build(_build_investigation())


def test_valid_package_verifies(tmp_path: Path) -> None:
    package = _build_package(tmp_path)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(package)

    assert result["verified"] is True
    assert result["status"] == "verified"
    assert result["errors"] == []
    assert result["investigation"]["id"] == "TEST-15F"
    assert result["investigation"]["title"] == "Evidence Verification Test"

    assert len(result["files"]) == 2
    assert all(item["verified"] for item in result["files"])


def test_modified_report_fails_verification(tmp_path: Path) -> None:
    package = _build_package(tmp_path)

    tampered_package = tmp_path / "tampered.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            tampered_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                data = source.read(item.filename)

                if item.filename.endswith("/report.md"):
                    data += b"\nTAMPERED"

                destination.writestr(item, data)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(tampered_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "SHA-256 mismatch" in error
        for error in result["errors"]
    )


def test_missing_report_fails_verification(tmp_path: Path) -> None:
    package = _build_package(tmp_path)

    broken_package = tmp_path / "missing_report.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            broken_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                if item.filename.endswith("/report.json"):
                    continue

                destination.writestr(
                    item,
                    source.read(item.filename),
                )

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(broken_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "missing" in error.lower()
        for error in result["errors"]
    )


def test_missing_manifest_fails_verification(tmp_path: Path) -> None:
    package = _build_package(tmp_path)

    broken_package = tmp_path / "missing_manifest.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            broken_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                if item.filename.endswith("/manifest.json"):
                    continue

                destination.writestr(
                    item,
                    source.read(item.filename),
                )

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(broken_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "manifest.json" in error
        for error in result["errors"]
    )


def test_invalid_package_path_returns_error(tmp_path: Path) -> None:
    verifier = InvestigationEvidencePackageVerifier()

    result = verifier.verify(
        tmp_path / "does_not_exist.zip"
    )

    assert result["verified"] is False
    assert result["status"] == "error"
    assert result["errors"]


def test_invalid_zip_returns_error(tmp_path: Path) -> None:
    invalid_zip = tmp_path / "invalid.zip"
    invalid_zip.write_bytes(b"not a zip file")

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(invalid_zip)

    assert result["verified"] is False
    assert result["status"] == "error"
    assert result["errors"]


def test_invalid_manifest_algorithm_fails(tmp_path: Path) -> None:
    package = _build_package(tmp_path)
    broken_package = tmp_path / "invalid_algorithm.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            broken_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                data = source.read(item.filename)

                if item.filename.endswith("/manifest.json"):
                    manifest = json.loads(data.decode("utf-8"))
                    manifest["integrity"]["algorithm"] = "MD5"
                    data = json.dumps(
                        manifest,
                        indent=2,
                    ).encode("utf-8")

                destination.writestr(item, data)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(broken_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "Unsupported integrity algorithm" in error
        for error in result["errors"]
    )


def test_unsafe_manifest_path_fails(tmp_path: Path) -> None:
    package = _build_package(tmp_path)
    broken_package = tmp_path / "unsafe_path.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            broken_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                data = source.read(item.filename)

                if item.filename.endswith("/manifest.json"):
                    manifest = json.loads(data.decode("utf-8"))
                    manifest["files"][0]["path"] = "../report.md"
                    data = json.dumps(
                        manifest,
                        indent=2,
                    ).encode("utf-8")

                destination.writestr(item, data)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(broken_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "Unsafe archive path" in error
        for error in result["errors"]
    )


def test_invalid_hash_fails(tmp_path: Path) -> None:
    package = _build_package(tmp_path)
    broken_package = tmp_path / "invalid_hash.zip"

    with zipfile.ZipFile(package, "r") as source:
        with zipfile.ZipFile(
            broken_package,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                data = source.read(item.filename)

                if item.filename.endswith("/manifest.json"):
                    manifest = json.loads(data.decode("utf-8"))
                    manifest["files"][0]["sha256"] = "invalid"
                    data = json.dumps(
                        manifest,
                        indent=2,
                    ).encode("utf-8")

                destination.writestr(item, data)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(broken_package)

    assert result["verified"] is False
    assert result["status"] == "failed"
    assert any(
        "Invalid SHA-256 hash" in error
        for error in result["errors"]
    )
