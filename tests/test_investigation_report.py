from pathlib import Path

from logviewer.pro.investigation.model import Investigation
from logviewer.pro.reporting import InvestigationReportGenerator


def build_investigation() -> Investigation:
    investigation = Investigation(
        investigation_id="INV-REPORT-001",
        title="SSH Authentication Investigation",
        status="open",
        severity="high",
        confidence=0.91,
    )

    investigation.add_event(
        {
            "event_id": "EVT-001",
            "source": "auth.log",
            "message": "Failed SSH authentication",
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
            "value": "10.10.10.50",
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
            "title": "Repeated Authentication Failures",
            "summary": "Multiple authentication failures were observed.",
            "severity": "high",
            "confidence": 0.88,
            "rationale": "Repeated related authentication events.",
            "source": "event_analysis",
            "event_ids": ["EVT-001"],
            "evidence_ids": ["EVD-001"],
            "ioc_values": ["10.10.10.50"],
            "mitre_techniques": ["T1110"],
            "correlation_ids": ["COR-001"],
        }
    ]

    investigation.set_threat_score(
        78,
        "high",
        {
            "finding_score": 35,
            "correlation_score": 20,
            "mitre_score": 15,
            "context_score": 8,
        },
    )

    investigation.set_false_positive_analysis(
        {
            "potential": True,
            "confidence": 0.32,
            "reasons": [
                "Authentication failures may have legitimate causes."
            ],
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
                "confidence": 0.91,
            },
            "entries": [
                {
                    "timestamp": "2026-09-22T10:00:00",
                    "type": "event",
                    "event_id": "EVT-001",
                }
            ],
        }
    )

    investigation.metadata = {
        "analyst": "test",
        "environment": "test",
    }

    return investigation


def test_report_build_data_contains_pro_sections():
    investigation = build_investigation()
    generator = InvestigationReportGenerator()

    data = generator.build_data(investigation)

    assert data["investigation"]["investigation_id"] == "INV-REPORT-001"
    assert data["threat_assessment"]["score"] == 78
    assert len(data["findings"]) == 1
    assert len(data["evidence"]) == 1
    assert len(data["iocs"]) == 1
    assert len(data["correlations"]) == 1
    assert len(data["mitre_mappings"]) == 1
    assert data["process_tree"]["node_count"] == 1
    assert data["attack_chain"]["summary"]["step_count"] == 1
    assert data["timeline"]["summary"]["entry_count"] == 1
    assert data["false_positive_analysis"]["potential"] is True


def test_markdown_report_contains_all_major_sections():
    investigation = build_investigation()
    generator = InvestigationReportGenerator()

    report = generator.render_markdown(investigation)

    required_sections = [
        "# Investigation Report:",
        "## 1. Investigation Overview",
        "## 2. Threat Assessment",
        "## 3. Findings",
        "## 4. Evidence",
        "## 5. Indicators of Compromise",
        "## 6. Correlations",
        "## 7. MITRE ATT&CK Mappings",
        "## 8. Process Tree",
        "## 9. Attack Chain",
        "## 10. Timeline",
        "## 11. False-Positive Analysis",
        "## 12. Analyst-Ready Conclusion",
        "## 13. Investigation Metadata",
    ]

    for section in required_sections:
        assert section in report

    assert "Repeated Authentication Failures" in report
    assert "10.10.10.50" in report
    assert "T1110" in report
    assert "78" in report
    assert "high" in report


def test_conclusion_is_cautious_and_analyst_ready():
    investigation = build_investigation()
    generator = InvestigationReportGenerator()

    report = generator.render_markdown(investigation)

    assert "does not independently establish malicious intent" in report
    assert "successful compromise" in report


def test_markdown_and_json_exports(tmp_path: Path):
    investigation = build_investigation()
    generator = InvestigationReportGenerator()

    markdown_path = tmp_path / "investigation.md"
    json_path = tmp_path / "investigation.json"

    returned_markdown = generator.write_markdown(
        investigation,
        markdown_path,
    )
    returned_json = generator.write_json(
        investigation,
        json_path,
    )

    assert returned_markdown == markdown_path
    assert returned_json == json_path
    assert markdown_path.exists()
    assert json_path.exists()

    markdown = markdown_path.read_text(encoding="utf-8")
    json_data = json_path.read_text(encoding="utf-8")

    assert "Investigation Report" in markdown
    assert '"INV-REPORT-001"' in json_data
    assert '"threat_assessment"' in json_data
    assert '"findings"' in json_data


def test_plain_text_report_is_generated():
    investigation = build_investigation()
    generator = InvestigationReportGenerator()

    report = generator.render_text(investigation)

    assert "Investigation Report:" in report
    assert "Threat Assessment" in report
    assert "Repeated Authentication Failures" in report
    assert "**" not in report
