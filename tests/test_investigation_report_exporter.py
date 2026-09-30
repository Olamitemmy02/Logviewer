from pathlib import Path

import pytest

from logviewer.pro.investigation.model import Investigation
from logviewer.pro.reporting import InvestigationReportExporter


def build_investigation() -> Investigation:
    investigation = Investigation(
        investigation_id="INV-EXPORT-001",
        title="Report Export Test",
        status="open",
        severity="medium",
        confidence=0.85,
    )

    investigation.add_event(
        {
            "event_id": "EVT-001",
            "source": "auth.log",
            "message": "Test authentication event",
        }
    )

    investigation.add_evidence(
        {
            "evidence_id": "EVD-001",
            "type": "log_event",
            "event_id": "EVT-001",
        }
    )

    investigation.iocs = [
        {
            "type": "ip",
            "value": "192.0.2.10",
        }
    ]

    investigation.correlations = [
        {
            "correlation_id": "COR-001",
            "event_ids": ["EVT-001"],
        }
    ]

    investigation.mitre_mappings = [
        {
            "technique_id": "T1110",
            "technique": "Brute Force",
        }
    ]

    investigation.findings = [
        {
            "finding_id": "FND-001",
            "title": "Test Finding",
            "summary": "Test finding for report export.",
            "severity": "medium",
            "confidence": 0.85,
            "rationale": "Testing the export path.",
            "source": "test",
            "event_ids": ["EVT-001"],
            "evidence_ids": ["EVD-001"],
            "ioc_values": ["192.0.2.10"],
            "mitre_techniques": ["T1110"],
            "correlation_ids": ["COR-001"],
        }
    ]

    investigation.set_threat_score(
        42,
        "medium",
        {
            "test_score": 42,
        },
    )

    investigation.set_false_positive_analysis(
        {
            "potential": False,
            "confidence": 0.9,
        }
    )

    investigation.set_process_tree(
        {
            "node_count": 1,
            "relationship_count": 0,
            "nodes": [
                {
                    "process_id": "1",
                    "name": "sshd",
                }
            ],
            "relationships": [],
        }
    )

    investigation.set_attack_chain(
        {
            "summary": {
                "step_count": 1,
                "link_count": 0,
                "technique_count": 1,
                "tactic_count": 1,
                "process_relationship_count": 0,
            },
            "steps": [
                {
                    "step": 1,
                    "technique_id": "T1110",
                }
            ],
        }
    )

    investigation.set_timeline(
        {
            "summary": {
                "entry_count": 1,
                "event_count": 1,
                "correlation_count": 1,
                "mitre_count": 1,
                "process_relationship_count": 0,
                "attack_chain_step_count": 1,
                "gap_count": 0,
                "confidence": 0.85,
            },
            "entries": [
                {
                    "timestamp": "2026-09-26T18:00:00",
                    "type": "event",
                    "event_id": "EVT-001",
                }
            ],
        }
    )

    return investigation


def test_exporter_creates_default_directory(tmp_path: Path):
    investigation = build_investigation()
    export_directory = tmp_path / "exports"

    exporter = InvestigationReportExporter(
        export_directory=export_directory,
    )

    markdown_path = exporter.export_markdown(investigation)

    assert export_directory.exists()
    assert markdown_path.exists()
    assert markdown_path.parent == export_directory
    assert markdown_path.name == "investigation_INV-EXPORT-001.md"


def test_exporter_creates_json_report(tmp_path: Path):
    investigation = build_investigation()
    export_directory = tmp_path / "exports"

    exporter = InvestigationReportExporter(
        export_directory=export_directory,
    )

    json_path = exporter.export_json(investigation)

    assert json_path.exists()
    assert json_path.name == "investigation_INV-EXPORT-001.json"

    content = json_path.read_text(encoding="utf-8")

    assert '"INV-EXPORT-001"' in content
    assert '"threat_assessment"' in content
    assert '"findings"' in content


def test_export_all_creates_both_formats(tmp_path: Path):
    investigation = build_investigation()
    export_directory = tmp_path / "exports"

    exporter = InvestigationReportExporter(
        export_directory=export_directory,
    )

    exported = exporter.export_all(investigation)

    assert set(exported.keys()) == {
        "markdown",
        "json",
    }

    assert exported["markdown"].exists()
    assert exported["json"].exists()

    markdown = exported["markdown"].read_text(
        encoding="utf-8"
    )

    assert "# Investigation Report:" in markdown
    assert "Test Finding" in markdown


def test_exporter_sanitizes_investigation_id(tmp_path: Path):
    investigation = build_investigation()
    investigation.investigation_id = "INV/../REPORT:001"

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    path = exporter.export_markdown(investigation)

    assert path.parent == tmp_path / "exports"
    assert "/" not in path.name
    assert "\\" not in path.name
    assert path.exists()


def test_exporter_import():
    from logviewer.pro.reporting import (
        InvestigationReportExporter,
        InvestigationReportGenerator,
    )

    assert InvestigationReportExporter is not None
    assert InvestigationReportGenerator is not None


def test_list_exports_returns_only_current_investigation_reports(
    tmp_path: Path,
):
    investigation = build_investigation()
    other = Investigation(
        investigation_id="INV-OTHER-001",
        title="Other Investigation",
    )

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    exporter.export_all(investigation)
    exporter.export_markdown(other)

    reports = exporter.list_exports(investigation)

    assert len(reports) == 2
    assert all(
        path.name.startswith("investigation_INV-EXPORT-001.")
        for path in reports
    )


def test_read_markdown_export(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    path = exporter.export_markdown(investigation)
    content = exporter.read_markdown(path)

    assert "# Investigation Report:" in content
    assert "Test Finding" in content


def test_read_markdown_rejects_json(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    path = exporter.export_json(investigation)

    with pytest.raises(ValueError):
        exporter.read_markdown(path)


def test_delete_export(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    path = exporter.export_markdown(investigation)

    assert path.exists()
    assert exporter.delete_export(path) is True
    assert not path.exists()
    assert exporter.delete_export(path) is False


def test_delete_export_rejects_outside_path(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    outside = tmp_path / "outside.md"
    outside.write_text(
        "must not be deleted",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        exporter.delete_export(outside)

    assert outside.exists()


def test_report_exists(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    assert exporter.report_exists(
        investigation,
        "md",
    ) is False

    exporter.export_markdown(investigation)

    assert exporter.report_exists(
        investigation,
        "md",
    ) is True


def test_unsupported_extension_is_rejected(tmp_path: Path):
    investigation = build_investigation()

    exporter = InvestigationReportExporter(
        export_directory=tmp_path / "exports",
    )

    with pytest.raises(ValueError):
        exporter._build_path(
            investigation,
            "txt",
        )
