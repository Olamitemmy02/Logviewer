"""
Investigation timeline construction.

The timeline layer converts evidence-backed correlation findings into
an ordered analyst-facing sequence.

This module does not determine maliciousness, attribution, attack
intent, or attack-chain membership. It only represents observable
events and their documented relationships.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .engine import CorrelationFinding, EvidenceRelationship
from ..evidence.model import Evidence
from ..normalization import parse_event_timestamp


@dataclass
class TimelineEntry:
    """
    One chronological observation in an investigation timeline.
    """

    timestamp: Optional[str]

    event_id: Optional[str]

    ioc_type: str

    ioc_value: str

    source: Optional[str] = None

    event_type: Optional[str] = None

    description: str = ""

    relationship_types: List[str] = field(
        default_factory=list
    )

    related_event_ids: List[str] = field(
        default_factory=list
    )

    previous_event_id: Optional[str] = None

    gap_from_previous_seconds: Optional[
        float
    ] = None

    evidence_index: int = 0

    def as_dict(self) -> dict:
        """
        Serialize the timeline entry.
        """

        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "relationship_types": list(
                self.relationship_types
            ),
            "related_event_ids": list(
                self.related_event_ids
            ),
            "previous_event_id": (
                self.previous_event_id
            ),
            "gap_from_previous_seconds": (
                self.gap_from_previous_seconds
            ),
            "evidence_index": self.evidence_index,
        }


class InvestigationTimeline:
    """
    Ordered timeline of evidence-backed observations.

    Timeline ordering is based on parseable timestamps. Evidence
    without a parseable timestamp is retained and placed after
    timestamped evidence.

    The timeline is descriptive only.
    """

    def __init__(
        self,
        entries: Optional[
            Iterable[TimelineEntry]
        ] = None,
    ):
        self.entries: List[
            TimelineEntry
        ] = list(
            entries or []
        )

    def add(
        self,
        entry: TimelineEntry,
    ) -> None:
        """
        Add an entry to the timeline.
        """

        self.entries.append(
            entry
        )

    def sort(self) -> None:
        """
        Sort entries chronologically.
        """

        def sort_key(
            entry: TimelineEntry,
        ):
            timestamp = parse_event_timestamp(
                entry.timestamp
            )

            if timestamp is None:
                return (
                    1,
                    entry.timestamp or "",
                    entry.evidence_index,
                )

            return (
                0,
                timestamp,
                entry.evidence_index,
            )

        self.entries.sort(
            key=sort_key
        )

    def as_dict(self) -> dict:
        """
        Serialize the complete timeline.
        """

        return {
            "entries": [
                entry.as_dict()
                for entry in self.entries
            ],
            "entry_count": len(
                self.entries
            ),
        }

    def __len__(self) -> int:
        return len(
            self.entries
        )

    def __iter__(self):
        return iter(
            self.entries
        )


class InvestigationTimelineBuilder:
    """
    Build investigation timelines from correlation findings.
    """

    def build(
        self,
        findings: Iterable[
            CorrelationFinding
        ],
    ) -> InvestigationTimeline:
        """
        Build one chronological timeline from correlation findings.
        """

        timeline = InvestigationTimeline()

        findings = list(
            findings
        )

        for finding in findings:
            self._add_finding(
                timeline,
                finding,
            )

        timeline.sort()

        self._calculate_temporal_gaps(
            timeline
        )

        return timeline

    def _add_finding(
        self,
        timeline: InvestigationTimeline,
        finding: CorrelationFinding,
    ) -> None:
        """
        Convert one correlation finding into timeline entries.
        """

        relationship_map = (
            self._relationship_map(
                finding.relationship_edges
            )
        )

        for index, evidence in enumerate(
            finding.evidence
        ):
            event_id = evidence.event_id

            relationship_types = (
                relationship_map.get(
                    event_id,
                    [],
                )
            )

            related_event_ids = (
                self._related_event_ids(
                    finding.relationship_edges,
                    event_id,
                )
            )

            event_type = (
                evidence.metadata.get(
                    "event_type"
                )
            )

            description = (
                evidence.description
                or (
                    f"{finding.ioc_type.upper()} "
                    f"{finding.value} observed."
                )
            )

            timeline.add(
                TimelineEntry(
                    timestamp=(
                        evidence.timestamp
                    ),
                    event_id=event_id,
                    ioc_type=(
                        finding.ioc_type
                    ),
                    ioc_value=(
                        finding.value
                    ),
                    source=(
                        evidence.source
                    ),
                    event_type=event_type,
                    description=description,
                    relationship_types=(
                        relationship_types
                    ),
                    related_event_ids=(
                        related_event_ids
                    ),
                    evidence_index=index,
                )
            )

    @staticmethod
    def _relationship_map(
        relationships: Iterable[
            EvidenceRelationship
        ],
    ) -> dict:
        """
        Build an event-ID to relationship-type mapping.
        """

        result = {}

        for relationship in relationships:
            relationship_type = (
                relationship.relationship_type
            )

            source_event_id = (
                relationship.source_event_id
            )

            target_event_id = (
                relationship.target_event_id
            )

            if source_event_id:
                result.setdefault(
                    source_event_id,
                    set(),
                ).add(
                    relationship_type
                )

            if target_event_id:
                result.setdefault(
                    target_event_id,
                    set(),
                ).add(
                    relationship_type
                )

        return {
            event_id: sorted(
                relationship_types
            )
            for event_id,
                relationship_types
            in result.items()
        }

    @staticmethod
    def _related_event_ids(
        relationships: Iterable[
            EvidenceRelationship
        ],
        event_id: Optional[str],
    ) -> List[str]:
        """
        Return the event IDs directly related to an event.
        """

        if not event_id:
            return []

        related = set()

        for relationship in relationships:
            if (
                relationship.source_event_id
                == event_id
            ):
                if (
                    relationship.target_event_id
                ):
                    related.add(
                        relationship.target_event_id
                    )

            elif (
                relationship.target_event_id
                == event_id
            ):
                if (
                    relationship.source_event_id
                ):
                    related.add(
                        relationship.source_event_id
                    )

        return sorted(
            related
        )

    @staticmethod
    def _calculate_temporal_gaps(
        timeline: InvestigationTimeline,
    ) -> None:
        """
        Calculate the gap between consecutive timestamped entries.
        """

        previous_timestamp = None
        previous_event_id = None

        for entry in timeline.entries:
            current_timestamp = (
                parse_event_timestamp(
                    entry.timestamp
                )
            )

            if (
                current_timestamp is None
                or previous_timestamp is None
            ):
                entry.previous_event_id = (
                    previous_event_id
                )

                previous_event_id = (
                    entry.event_id
                )

                if current_timestamp is not None:
                    previous_timestamp = (
                        current_timestamp
                    )

                continue

            entry.previous_event_id = (
                previous_event_id
            )

            entry.gap_from_previous_seconds = (
                current_timestamp
                - previous_timestamp
            ).total_seconds()

            previous_timestamp = (
                current_timestamp
            )

            previous_event_id = (
                entry.event_id
            )
