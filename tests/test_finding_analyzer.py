import unittest

from logviewer.pro.findings import FindingAnalyzer
from logviewer.pro.investigation.model import Investigation


class FindingAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = FindingAnalyzer()
        self.investigation = Investigation(
            investigation_id="FINDING-TEST-001",
            title="Finding analyzer test",
        )

    def test_event_creates_evidence_linked_finding(self):
        self.investigation.add_event({
            "event_id": "evt-001",
            "source": "auth.log",
            "timestamp": "2026-09-23T10:00:00Z",
            "severity": "HIGH",
            "message": "Repeated authentication failures",
            "source_ip": "192.0.2.10",
        })
        self.investigation.add_evidence({
            "evidence_id": "ev-001",
            "event_index": 0,
        })

        findings = self.analyzer.analyze(self.investigation)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["event_ids"], ["evt-001"])
        self.assertEqual(findings[0]["evidence_ids"], ["ev-001"])
        self.assertIn("192.0.2.10", findings[0]["ioc_values"])
        self.assertTrue(findings[0]["finding_id"].startswith("F-"))

    def test_correlation_creates_structured_finding(self):
        self.investigation.correlations = [{
            "correlation_id": "corr-001",
            "title": "Related authentication activity",
            "description": "Several events share a source address.",
            "severity": "MEDIUM",
            "confidence": 0.8,
            "event_ids": ["evt-1", "evt-2"],
            "evidence_ids": ["ev-1"],
            "technique_ids": ["T1110"],
        }]

        findings = self.analyzer.analyze(self.investigation)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["correlation_ids"],
            ["corr-001"],
        )
        self.assertEqual(
            findings[0]["mitre_techniques"],
            ["T1110"],
        )
        self.assertEqual(findings[0]["confidence"], 0.8)

    def test_mitre_mapping_is_not_claimed_as_proof(self):
        self.investigation.mitre_mappings = [{
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "confidence": 75,
            "event_ids": ["evt-9"],
        }]

        findings = self.analyzer.analyze(self.investigation)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], 0.75)
        self.assertIn("not proof", findings[0]["rationale"])

    def test_duplicate_findings_are_removed(self):
        event = {
            "event_id": "evt-001",
            "source": "syslog",
            "severity": "LOW",
            "message": "Observed event",
        }
        self.investigation.events = [event, event]

        findings = self.analyzer.analyze(self.investigation)

        self.assertEqual(len(findings), 1)

    def test_findings_sort_by_severity_then_confidence(self):
        self.investigation.events = [
            {
                "event_id": "evt-low",
                "source": "syslog",
                "severity": "LOW",
                "confidence": 0.9,
                "message": "Low severity event",
            },
            {
                "event_id": "evt-high",
                "source": "auth.log",
                "severity": "HIGH",
                "confidence": 0.4,
                "message": "High severity event",
            },
        ]

        findings = self.analyzer.analyze(self.investigation)

        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[1]["severity"], "LOW")

    def test_analyze_and_store_updates_investigation(self):
        self.investigation.events = [{
            "event_id": "evt-001",
            "source": "syslog",
            "message": "Test event",
        }]

        stored = self.analyzer.analyze_and_store(
            self.investigation
        )

        self.assertEqual(len(stored), 1)
        self.assertEqual(len(self.investigation.findings), 1)

    def test_missing_event_message_is_skipped(self):
        self.investigation.events = [{
            "event_id": "evt-001",
            "source": "syslog",
        }]

        self.assertEqual(
            self.analyzer.analyze(self.investigation),
            [],
        )


if __name__ == "__main__":
    unittest.main()
