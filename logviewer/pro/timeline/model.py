from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


TIMELINE_FEATURE = "timeline"


@dataclass
class TimelineEntry:
    """
    A normalized chronological entry derived from existing investigation data.

    Timeline entries never replace or mutate the underlying evidence. They
    provide a unified analytical view over events, correlations, MITRE
    mappings, process relationships, and attack-chain steps.
    """

    entry_id: str
    timestamp: str
    entry_type: str
    title: str
    description: str = ""

    source: str = ""
    severity: str = "INFO"
    confidence: float = 0.0

    event_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""

    process: str = ""
    pid: Any = None
    parent_pid: Any = None

    related_entry_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "entry_type": self.entry_type,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "severity": self.severity,
            "confidence": self.confidence,
            "event_id": self.event_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "process": self.process,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "related_entry_ids": list(self.related_entry_ids),
            "evidence_ids": list(self.evidence_ids),
            "metadata": dict(self.metadata),
        }


@dataclass
class SecurityTimeline:
    """
    Unified chronological representation of an investigation.

    The timeline is analytical output. It does not create new security events.
    """

    investigation_id: str

    entries: List[TimelineEntry] = field(default_factory=list)

    start_time: str = ""
    end_time: str = ""

    event_count: int = 0
    correlation_count: int = 0
    mitre_count: int = 0
    process_relationship_count: int = 0
    attack_chain_step_count: int = 0

    confidence: float = 0.0

    gaps: List[Dict[str, Any]] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_entry(self, entry: TimelineEntry) -> None:
        self.entries.append(entry)

    def sort_entries(self) -> None:
        self.entries.sort(
            key=lambda entry: (
                entry.timestamp or "",
                entry.entry_id,
            )
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "entry_count": len(self.entries),
            "event_count": self.event_count,
            "correlation_count": self.correlation_count,
            "mitre_count": self.mitre_count,
            "process_relationship_count": self.process_relationship_count,
            "attack_chain_step_count": self.attack_chain_step_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "gap_count": len(self.gaps),
            "confidence": self.confidence,
        }

    def as_dict(self) -> Dict[str, Any]:
        self.sort_entries()

        return {
            "investigation_id": self.investigation_id,
            "entries": [entry.as_dict() for entry in self.entries],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "event_count": self.event_count,
            "correlation_count": self.correlation_count,
            "mitre_count": self.mitre_count,
            "process_relationship_count": self.process_relationship_count,
            "attack_chain_step_count": self.attack_chain_step_count,
            "confidence": self.confidence,
            "gaps": list(self.gaps),
            "metadata": dict(self.metadata),
            "summary": self.summary(),
        }


if __name__ == "__main__":
    timeline = SecurityTimeline(
        investigation_id="TEST-001",
        start_time="2026-01-01T10:00:00",
        end_time="2026-01-01T10:05:00",
        event_count=2,
        correlation_count=1,
        mitre_count=1,
        process_relationship_count=1,
        attack_chain_step_count=2,
        confidence=0.85,
    )

    timeline.add_entry(
        TimelineEntry(
            entry_id="event-001",
            timestamp="2026-01-01T10:00:00",
            entry_type="event",
            title="Authentication event",
            description="Test authentication event.",
            source="auth.log",
            severity="INFO",
            confidence=1.0,
            event_id="event-001",
        )
    )

    timeline.add_entry(
        TimelineEntry(
            entry_id="mitre-001",
            timestamp="2026-01-01T10:01:00",
            entry_type="mitre",
            title="Command and Scripting Interpreter",
            description="Candidate MITRE mapping derived from investigation evidence.",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            confidence=0.80,
            related_entry_ids=["event-001"],
        )
    )

    result = timeline.as_dict()

    assert result["investigation_id"] == "TEST-001"
    assert result["summary"]["entry_count"] == 2
    assert result["summary"]["event_count"] == 2
    assert result["entries"][0]["entry_id"] == "event-001"
    assert result["entries"][1]["technique_id"] == "T1059"

    print("Security Timeline model self-test: PASSED")
    print(f"Entries: {result['summary']['entry_count']}")
    print(f"Events: {result['summary']['event_count']}")
    print(f"MITRE mappings: {result['summary']['mitre_count']}")
