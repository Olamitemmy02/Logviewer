from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Investigation:
    investigation_id: str
    title: str = "Untitled Investigation"
    status: str = "open"
    severity: str = "INFO"
    confidence: float = 0.0

    threat_score: int = 0
    threat_level: str = "INFO"
    threat_score_details: Dict[str, Any] = field(default_factory=dict)

    false_positive_analysis: Dict[str, Any] = field(default_factory=dict)
    process_tree: Dict[str, Any] = field(default_factory=dict)
    attack_chain: Dict[str, Any] = field(default_factory=dict)
    timeline: Dict[str, Any] = field(default_factory=dict)

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    updated_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    events: List[Any] = field(default_factory=list)
    evidence: List[Any] = field(default_factory=list)
    iocs: List[Any] = field(default_factory=list)
    correlations: List[Any] = field(default_factory=list)
    mitre_mappings: List[Any] = field(default_factory=list)
    findings: List[Any] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_event(self, event: Any) -> None:
        self.events.append(event)
        self.touch()

    def add_evidence(self, evidence: Any) -> None:
        self.evidence.append(evidence)
        self.touch()

    def add_finding(self, finding: Any) -> None:
        self.findings.append(finding)
        self.touch()

    def set_status(self, status: str) -> None:
        self.status = status
        self.touch()

    def set_severity(self, severity: str) -> None:
        self.severity = severity
        self.touch()

    def set_threat_score(
        self,
        score: int,
        level: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.threat_score = int(score)
        self.threat_level = str(level)

        if details is not None:
            self.threat_score_details = dict(details)

        self.touch()

    def set_mitre_mappings(
        self,
        mappings: List[Any],
    ) -> None:
        self.mitre_mappings = list(mappings)
        self.touch()

    def set_false_positive_analysis(
        self,
        analysis: Dict[str, Any],
    ) -> None:
        self.false_positive_analysis = dict(
            analysis
        )
        self.touch()

    def set_process_tree(
        self,
        process_tree: Dict[str, Any],
    ) -> None:
        self.process_tree = dict(
            process_tree
        )
        self.touch()

    def set_attack_chain(
        self,
        attack_chain: Dict[str, Any],
    ) -> None:
        self.attack_chain = dict(
            attack_chain
        )
        self.touch()

    def set_timeline(
        self,
        timeline: Dict[str, Any],
    ) -> None:
        self.timeline = dict(
            timeline
        )
        self.touch()

    def touch(self) -> None:
        self.updated_at = datetime.now(
            timezone.utc
        ).isoformat()

    def summary(self) -> Dict[str, Any]:
        false_positive_analysis = (
            self.false_positive_analysis
            if self.false_positive_analysis
            else {}
        )

        process_tree = (
            self.process_tree
            if self.process_tree
            else {}
        )

        attack_chain = (
            self.attack_chain
            if self.attack_chain
            else {}
        )

        timeline = (
            self.timeline
            if self.timeline
            else {}
        )

        attack_chain_summary = (
            attack_chain.get(
                "summary",
                {},
            )
            if attack_chain
            else {}
        )

        timeline_summary = (
            timeline.get(
                "summary",
                {},
            )
            if timeline
            else {}
        )

        return {
            "investigation_id": self.investigation_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,

            "threat_score": self.threat_score,
            "threat_level": self.threat_level,

            "event_count": len(self.events),
            "evidence_count": len(self.evidence),
            "ioc_count": len(self.iocs),
            "correlation_count": len(
                self.correlations
            ),
            "mitre_mapping_count": len(
                self.mitre_mappings
            ),
            "finding_count": len(self.findings),

            "false_positive_analysis": (
                bool(false_positive_analysis)
            ),

            "process_tree_nodes": (
                process_tree.get(
                    "node_count",
                    0,
                )
            ),

            "process_tree_relationships": (
                process_tree.get(
                    "relationship_count",
                    0,
                )
            ),

            "attack_chain_steps": (
                attack_chain_summary.get(
                    "step_count",
                    0,
                )
            ),

            "attack_chain_links": (
                attack_chain_summary.get(
                    "link_count",
                    0,
                )
            ),

            "attack_chain_techniques": (
                attack_chain_summary.get(
                    "technique_count",
                    0,
                )
            ),

            "attack_chain_tactics": (
                attack_chain_summary.get(
                    "tactic_count",
                    0,
                )
            ),

            "attack_chain_process_relationships": (
                attack_chain_summary.get(
                    "process_relationship_count",
                    0,
                )
            ),

            "timeline_entries": (
                timeline_summary.get(
                    "entry_count",
                    0,
                )
            ),

            "timeline_events": (
                timeline_summary.get(
                    "event_count",
                    0,
                )
            ),

            "timeline_correlations": (
                timeline_summary.get(
                    "correlation_count",
                    0,
                )
            ),

            "timeline_mitre_mappings": (
                timeline_summary.get(
                    "mitre_count",
                    0,
                )
            ),

            "timeline_process_relationships": (
                timeline_summary.get(
                    "process_relationship_count",
                    0,
                )
            ),

            "timeline_attack_chain_steps": (
                timeline_summary.get(
                    "attack_chain_step_count",
                    0,
                )
            ),

            "timeline_gap_count": (
                timeline_summary.get(
                    "gap_count",
                    0,
                )
            ),

            "timeline_confidence": (
                timeline_summary.get(
                    "confidence",
                    0.0,
                )
            ),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,

            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "threat_score_details":
                self.threat_score_details,

            "false_positive_analysis":
                self.false_positive_analysis,

            "process_tree":
                self.process_tree,

            "attack_chain":
                self.attack_chain,

            "timeline":
                self.timeline,

            "created_at":
                self.created_at,

            "updated_at":
                self.updated_at,

            "events": [
                (
                    event.as_dict()
                    if hasattr(event, "as_dict")
                    else event
                )
                for event in self.events
            ],

            "evidence": [
                (
                    item.as_dict()
                    if hasattr(item, "as_dict")
                    else item
                )
                for item in self.evidence
            ],

            "iocs": [
                (
                    item.as_dict()
                    if hasattr(item, "as_dict")
                    else item
                )
                for item in self.iocs
            ],

            "correlations": [
                (
                    item.as_dict()
                    if hasattr(item, "as_dict")
                    else item
                )
                for item in self.correlations
            ],

            "mitre_mappings": [
                (
                    item.as_dict()
                    if hasattr(item, "as_dict")
                    else item
                )
                for item in self.mitre_mappings
            ],

            "findings": [
                (
                    item.as_dict()
                    if hasattr(item, "as_dict")
                    else item
                )
                for item in self.findings
            ],

            "metadata":
                self.metadata,

            "summary":
                self.summary(),
        }


if __name__ == "__main__":
    investigation = Investigation(
        investigation_id="TEST-001",
        title="Timeline Integration Test",
    )

    investigation.set_timeline(
        {
            "investigation_id": "TEST-001",
            "entries": [
                {
                    "entry_id": "event:evt-001",
                    "timestamp":
                        "2026-01-01T10:00:00Z",
                    "entry_type": "event",
                },
                {
                    "entry_id": "mitre:1",
                    "timestamp":
                        "2026-01-01T10:01:00Z",
                    "entry_type": "mitre",
                    "technique_id": "T1059",
                },
            ],
            "summary": {
                "entry_count": 2,
                "event_count": 1,
                "correlation_count": 0,
                "mitre_count": 1,
                "process_relationship_count": 0,
                "attack_chain_step_count": 0,
                "gap_count": 0,
                "confidence": 0.9,
            },
        }
    )

    summary = investigation.summary()
    serialized = investigation.as_dict()

    assert investigation.timeline
    assert summary["timeline_entries"] == 2
    assert summary["timeline_events"] == 1
    assert summary["timeline_mitre_mappings"] == 1
    assert summary["timeline_confidence"] == 0.9
    assert serialized["timeline"] == investigation.timeline
    assert serialized["summary"]["timeline_entries"] == 2

    print(
        "Investigation model timeline integration "
        "self-test: PASSED"
    )
    print(
        f"Timeline entries: "
        f"{summary['timeline_entries']}"
    )
    print(
        f"Timeline events: "
        f"{summary['timeline_events']}"
    )
    print(
        f"Timeline MITRE mappings: "
        f"{summary['timeline_mitre_mappings']}"
    )
