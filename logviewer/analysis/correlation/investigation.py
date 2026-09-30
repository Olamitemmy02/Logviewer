from dataclasses import dataclass, field
from typing import Dict, List, Set

from .engine import CorrelationFinding
from .timeline import (
    InvestigationTimeline,
    InvestigationTimelineBuilder,
)


@dataclass
class InvestigationContext:
    """
    Maintains analyst-selected correlation findings
    for the current LogViewer investigation session.

    This object stores investigation state only.

    It does not:
        - assign threat scores
        - declare findings malicious
        - perform MITRE ATT&CK mapping
        - reconstruct attack chains
        - make attribution claims

    The investigation timeline is derived from the selected
    correlation findings and is not stored as a separate copy
    of the underlying event dataset.
    """

    name: str = "Untitled Investigation"

    findings: List[CorrelationFinding] = field(
        default_factory=list
    )

    notes: List[str] = field(
        default_factory=list
    )

    def add_finding(
        self,
        finding: CorrelationFinding,
    ) -> bool:
        """
        Add a finding if it is not already present.
        """

        if self.contains(finding):
            return False

        self.findings.append(
            finding
        )

        return True

    def remove_finding(
        self,
        finding: CorrelationFinding,
    ) -> bool:
        """
        Remove a matching finding.
        """

        for index, existing in enumerate(
            self.findings
        ):
            if self._same_finding(
                existing,
                finding,
            ):
                del self.findings[index]

                return True

        return False

    def contains(
        self,
        finding: CorrelationFinding,
    ) -> bool:
        """
        Determine whether a finding is already selected.
        """

        return any(
            self._same_finding(
                existing,
                finding,
            )
            for existing in self.findings
        )

    def clear(self) -> None:
        """
        Clear all selected findings and notes.
        """

        self.findings.clear()
        self.notes.clear()

    def add_note(
        self,
        note: str,
    ) -> bool:
        """
        Add an analyst note.
        """

        note = str(note).strip()

        if not note:
            return False

        self.notes.append(
            note
        )

        return True

    def remove_note(
        self,
        index: int,
    ) -> bool:
        """
        Remove a note by index.
        """

        if not (
            0 <= index < len(self.notes)
        ):
            return False

        del self.notes[index]

        return True

    @property
    def finding_count(self) -> int:
        return len(
            self.findings
        )

    @property
    def evidence_count(self) -> int:
        return sum(
            finding.evidence_count
            for finding in self.findings
        )

    @property
    def ioc_count(self) -> int:
        return len(
            {
                (
                    finding.ioc_type.lower(),
                    finding.value,
                )
                for finding in self.findings
            }
        )

    @property
    def source_count(self) -> int:
        sources: Set[str] = set()

        for finding in self.findings:
            sources.update(
                source
                for source in finding.sources
                if source
            )

        return len(sources)

    @property
    def event_count(self) -> int:
        return sum(
            finding.event_count
            for finding in self.findings
        )

    @property
    def relationship_edge_count(self) -> int:
        """
        Return the number of explicit evidence relationships
        represented by the selected findings.
        """

        return sum(
            len(
                getattr(
                    finding,
                    "relationship_edges",
                    [],
                )
            )
            for finding in self.findings
        )

    @property
    def timeline(self) -> InvestigationTimeline:
        """
        Build the current investigation timeline.

        The timeline is derived from the selected findings every time
        it is requested. This avoids maintaining a second mutable copy
        of the investigation evidence.
        """

        return (
            InvestigationTimelineBuilder().build(
                self.findings
            )
        )

    def validate(self):
        """
        Validate the structural integrity of this investigation.

        Validation is read-only and does not modify the investigation.
        """

        from .investigation_validator import (
            InvestigationValidator,
        )

        return InvestigationValidator().validate(
            self
        )

    def relationship_counts(
        self,
    ) -> Dict[str, int]:
        counts: Dict[str, int] = {}

        for finding in self.findings:
            relationship = finding.relationship

            counts[relationship] = (
                counts.get(
                    relationship,
                    0,
                )
                + 1
            )

        return counts

    def source_names(
        self,
    ) -> List[str]:
        sources = set()

        for finding in self.findings:
            sources.update(
                finding.sources
            )

        return sorted(
            source
            for source in sources
            if source
        )

    def iocs(
        self,
    ) -> List[str]:
        values = {
            finding.value
            for finding in self.findings
            if finding.value
        }

        return sorted(
            values
        )

    def summary(
        self,
    ) -> Dict[str, object]:
        return {
            "name": self.name,
            "findings": self.finding_count,
            "evidence": self.evidence_count,
            "events": self.event_count,
            "iocs": self.ioc_count,
            "sources": self.source_count,
            "relationships": (
                self.relationship_counts()
            ),
            "relationship_edges": (
                self.relationship_edge_count
            ),
            "timeline_entries": len(
                self.timeline
            ),
            "notes": len(self.notes),
        }

    @staticmethod
    def _same_finding(
        first: CorrelationFinding,
        second: CorrelationFinding,
    ) -> bool:
        return (
            first.ioc_type
            == second.ioc_type
            and first.value
            == second.value
            and first.relationship
            == second.relationship
            and first.first_seen
            == second.first_seen
            and first.last_seen
            == second.last_seen
        )
