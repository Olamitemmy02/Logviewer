from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from logviewer.pro.investigation.engine import InvestigationEngine
from logviewer.pro.investigation.store import InvestigationStore


class FeatureGateStub:
    ENABLED = {
        "investigation",
        "mitre",
        "threat_scoring",
        "false_positive_analysis",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }

    def check(self, feature: str) -> bool:
        return feature in self.ENABLED


@dataclass
class FakeEvent:
    event_id: str
    timestamp: str
    severity: str
    source: str
    message: str
    source_ip: str

    def as_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "source_ip": self.source_ip,
        }


class FakeMitreMapper:
    def map_events(self, events):
        return [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.9,
                "event_ids": [events[0].event_id],
            }
        ] if events else []


class FakeThreatScorer:
    def score(self, investigation):
        return {
            "score": 75,
            "level": "HIGH",
        }


class FakeFalsePositiveAnalyzer:
    def analyze_and_store(self, investigation):
        investigation.set_false_positive_analysis(
            {
                "is_false_positive": False,
            }
        )


class FakeProcessTreeAnalyzer:
    def analyze_and_store(self, investigation):
        investigation.set_process_tree(
            {
                "node_count": 1,
                "relationship_count": 0,
                "root": "sshd",
            }
        )


class FakeAttackChainReconstructor:
    def reconstruct_and_store(self, investigation):
        investigation.set_attack_chain(
            {
                "steps": [
                    {
                        "step": 1,
                        "description": "Initial access activity",
                    }
                ],
                "summary": {
                    "step_count": 1,
                    "link_count": 0,
                    "technique_count": 0,
                    "tactic_count": 0,
                    "process_relationship_count": 0,
                },
            }
        )


class FakeTimelineReconstructor:
    def reconstruct_and_store(self, investigation):
        investigation.set_timeline(
            {
                "entries": [
                    {
                        "timestamp": investigation.events[0].as_dict()[
                            "timestamp"
                        ],
                        "type": "event",
                        "event_id": investigation.events[0].event_id,
                    }
                ],
                "summary": {
                    "entry_count": 1,
                    "event_count": 1,
                    "correlation_count": 0,
                    "mitre_count": 0,
                    "process_relationship_count": 0,
                    "attack_chain_step_count": 0,
                    "gap_count": 0,
                    "confidence": 1.0,
                },
            }
        )


class FakeCorrelationEngine:
    def correlate(self, events):
        if not events:
            return []

        return [
            {
                "correlation_id": "CORR-001",
                "title": "Related SSH activity",
                "summary": "Related authentication events were grouped.",
                "severity": "HIGH",
                "confidence": 0.85,
                "event_ids": [event.event_id for event in events],
                "evidence_ids": [],
                "ioc_values": [events[0].source_ip],
            }
        ]


def build_engine(store):
    gate = FeatureGateStub()

    engine = InvestigationEngine(
        feature_gate=gate,
        store=store,
        correlation_engine=FakeCorrelationEngine(),
    )

    engine.mitre_mapper = FakeMitreMapper()
    engine.threat_scorer = FakeThreatScorer()
    engine.false_positive_analyzer = FakeFalsePositiveAnalyzer()
    engine.process_tree_analyzer = FakeProcessTreeAnalyzer()
    engine.attack_chain_reconstructor = FakeAttackChainReconstructor()
    engine.timeline_reconstructor = FakeTimelineReconstructor()

    return engine


def test_findings_are_generated_by_full_investigation_pipeline():
    with TemporaryDirectory() as directory:
        store = InvestigationStore(Path(directory))
        engine = build_engine(store)

        events = [
            FakeEvent(
                event_id="EVT-001",
                timestamp="2026-09-22T10:00:00",
                severity="HIGH",
                source="sshd",
                message="Failed SSH authentication from 192.0.2.10",
                source_ip="192.0.2.10",
            ),
            FakeEvent(
                event_id="EVT-002",
                timestamp="2026-09-22T10:00:05",
                severity="MEDIUM",
                source="sshd",
                message="Repeated SSH authentication attempt",
                source_ip="192.0.2.10",
            ),
        ]

        investigation = engine.create_investigation(
            investigation_id="INV-FINDINGS-001",
            events=events,
            title="Findings Pipeline Test",
        )

        assert len(investigation.events) == 2
        assert len(investigation.evidence) == 2
        assert len(investigation.correlations) == 1
        assert len(investigation.mitre_mappings) == 1

        assert investigation.threat_score == 75
        assert investigation.threat_level == "HIGH"

        assert investigation.false_positive_analysis
        assert investigation.process_tree
        assert investigation.attack_chain
        assert investigation.timeline

        assert investigation.findings
        assert len(investigation.findings) >= 3

        finding_titles = {
            finding["title"]
            for finding in investigation.findings
        }

        assert "Related SSH activity" in finding_titles

        assert any(
            finding["source"] == "mitre"
            for finding in investigation.findings
        )

        assert any(
            finding["source"] == "sshd"
            for finding in investigation.findings
        )

        for finding in investigation.findings:
            assert finding["finding_id"].startswith("F-")
            assert finding["title"]
            assert finding["summary"]

            assert finding["severity"] in {
                "INFO",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }

            assert 0.0 <= finding["confidence"] <= 1.0

            assert "rationale" in finding
            assert "event_ids" in finding
            assert "evidence_ids" in finding
            assert "ioc_values" in finding
            assert "mitre_techniques" in finding
            assert "correlation_ids" in finding
            assert "false_positive_context" in finding
            assert "metadata" in finding


def test_findings_survive_investigation_store_persistence():
    with TemporaryDirectory() as directory:
        store = InvestigationStore(Path(directory))
        engine = build_engine(store)

        event = FakeEvent(
            event_id="EVT-STORE-001",
            timestamp="2026-09-22T11:00:00",
            severity="HIGH",
            source="sshd",
            message="SSH authentication failure from 198.51.100.20",
            source_ip="198.51.100.20",
        )

        investigation = engine.create_investigation(
            investigation_id="INV-FINDINGS-STORE",
            events=[event],
            title="Findings Persistence Test",
        )

        assert investigation.findings

        finding_ids_before = [
            finding["finding_id"]
            for finding in investigation.findings
        ]

        loaded = store.load("INV-FINDINGS-STORE")

        assert loaded is not None
        assert loaded.findings

        finding_ids_after = [
            finding["finding_id"]
            for finding in loaded.findings
        ]

        assert finding_ids_after == finding_ids_before
        assert loaded.findings == investigation.findings


def test_findings_stage_respects_feature_gate():
    with TemporaryDirectory() as directory:
        store = InvestigationStore(Path(directory))
        gate = FeatureGateStub()

        gate.ENABLED = {
            "investigation",
            "mitre",
            "threat_scoring",
            "false_positive_analysis",
            "process_tree",
            "attack_chain",
            "timeline",
        }

        engine = InvestigationEngine(
            feature_gate=gate,
            store=store,
            correlation_engine=FakeCorrelationEngine(),
        )

        engine.mitre_mapper = FakeMitreMapper()
        engine.threat_scorer = FakeThreatScorer()
        engine.false_positive_analyzer = FakeFalsePositiveAnalyzer()
        engine.process_tree_analyzer = FakeProcessTreeAnalyzer()
        engine.attack_chain_reconstructor = FakeAttackChainReconstructor()
        engine.timeline_reconstructor = FakeTimelineReconstructor()

        event = FakeEvent(
            event_id="EVT-GATE-001",
            timestamp="2026-09-22T12:00:00",
            severity="MEDIUM",
            source="auth",
            message="Authentication event",
            source_ip="203.0.113.5",
        )

        investigation = engine.create_investigation(
            investigation_id="INV-FINDINGS-GATE",
            events=[event],
        )

        assert investigation.findings == []


if __name__ == "__main__":
    import pytest

    raise SystemExit(
        pytest.main([__file__, "-q"])
    )
