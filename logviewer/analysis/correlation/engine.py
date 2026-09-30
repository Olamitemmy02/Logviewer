from bisect import bisect_left
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from logviewer.events import Event

from ..evidence.model import Evidence
from ..normalization import (
    correlation_keys,
    event_context,
    event_id,
    event_text,
    parse_event_timestamp,
)
from ..ioc.analyzer import extract_event_iocs


class EvidenceRelationship(dict):
    """
    Represents a relationship between two evidence observations.

    The object behaves both as:
        - an attribute-based relationship model for the timeline layer
        - a dictionary for existing exporters, validators, and callers
    """

    def __init__(
        self,
        source_event_id: Optional[str],
        target_event_id: Optional[str],
        relationship_type: str,
        time_delta_seconds: Optional[float] = None,
        source_a: Optional[str] = None,
        source_b: Optional[str] = None,
    ) -> None:
        self.source_event_id = source_event_id
        self.target_event_id = target_event_id
        self.relationship_type = relationship_type
        self.time_delta_seconds = time_delta_seconds
        self.source_a = source_a
        self.source_b = source_b

        super().__init__(
            from_event_id=source_event_id,
            to_event_id=target_event_id,
            type=relationship_type,
            time_delta_seconds=time_delta_seconds,
            source_a=source_a,
            source_b=source_b,
        )

    @property
    def source(self) -> Optional[str]:
        """
        Backward-compatible source alias.

        Older investigation exporters expect relationship.source.
        The canonical relationship model stores the two endpoint
        event IDs separately and preserves source_a/source_b for
        their corresponding log sources.
        """

        return self.source_a

    @property
    def target(self) -> Optional[str]:
        """
        Backward-compatible target alias.
        """

        return self.source_b

    @property
    def time_gap_seconds(self) -> Optional[float]:
        """Backward-compatible alias for the relationship time gap."""
        return self.time_delta_seconds

    @property
    def description(self) -> str:
        """Human-readable description used by investigation exporters."""
        parts = [
            self.relationship_type,
            self.source_a or "-",
            self.source_b or "-",
        ]
        if self.time_delta_seconds is not None:
            parts.append(f"{self.time_delta_seconds:.3f}s")
        return " | ".join(parts)

    @property
    def from_event_id(self) -> Optional[str]:
        """
        Compatibility alias for the originating event ID.
        """

        return self.source_event_id

    @property
    def to_event_id(self) -> Optional[str]:
        """
        Compatibility alias for the destination event ID.
        """

        return self.target_event_id

    @property
    def type(self) -> str:
        """
        Compatibility alias for the relationship type.
        """

        return self.relationship_type

    def as_dict(self) -> Dict[str, Any]:
        """
        Return the relationship as a plain serializable dictionary.
        """

        return dict(self)


@dataclass
class CorrelationFinding:
    """
    Represents an evidence-backed correlation finding.

    A finding groups observations of the same IOC and describes
    how those observations relate across events and sources.
    """

    ioc_type: str
    ioc_value: str
    event_count: int
    sources: List[str] = field(default_factory=list)
    event_types: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    time_span_seconds: Optional[float] = None
    relationship: str = "observed"
    description: str = ""
    related_event_ids: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    relationship_edges: List[EvidenceRelationship] = field(
        default_factory=list
    )
    closest_cross_source_gap_seconds: Optional[float] = None

    @property
    def value(self) -> str:
        """
        Backward-compatible alias for the canonical IOC value.

        Older correlation display, investigation, timeline, filter,
        and export components use finding.value. The canonical field
        remains ioc_value.
        """

        return self.ioc_value

    @property
    def source_count(self) -> int:
        """
        Backward-compatible count of distinct evidence sources.
        """

        return len(self.sources)

    @property
    def evidence_count(self) -> int:
        """
        Backward-compatible count of supporting evidence records.
        """

        return len(self.evidence)

    def as_dict(self) -> Dict[str, Any]:
        """
        Serialize the finding into a JSON-compatible dictionary.

        The canonical model fields are preserved while compatibility
        fields used by older dashboard, investigation, and export
        components are exposed explicitly.
        """

        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "value": self.value,
            "event_count": self.event_count,
            "evidence_count": self.evidence_count,
            "source_count": self.source_count,
            "sources": list(self.sources),
            "event_types": list(self.event_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "time_span_seconds": self.time_span_seconds,
            "relationship": self.relationship,
            "description": self.description,
            "related_event_ids": list(self.related_event_ids),
            "evidence": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.evidence
            ],
            "relationship_edges": [
                edge.as_dict()
                if hasattr(edge, "as_dict")
                else dict(edge)
                for edge in self.relationship_edges
            ],
            "closest_cross_source_gap_seconds": (
                self.closest_cross_source_gap_seconds
            ),
        }

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
    ) -> "CorrelationFinding":
        """
        Reconstruct a CorrelationFinding from persisted data.

        This is the inverse of as_dict() and is required when loading
        saved investigations from the investigation store.
        """

        if not isinstance(data, dict):
            raise TypeError(
                "CorrelationFinding data must be a dictionary."
            )

        evidence_items: List[Evidence] = []

        for item in data.get("evidence", []) or []:
            if isinstance(item, Evidence):
                evidence_items.append(item)
                continue

            if not isinstance(item, dict):
                continue

            evidence_items.append(
                Evidence(
                    evidence_type=item.get(
                        "evidence_type",
                        "",
                    ),
                    value=item.get(
                        "value",
                        "",
                    ),
                    source=item.get("source"),
                    timestamp=item.get("timestamp"),
                    confidence=float(
                        item.get(
                            "confidence",
                            1.0,
                        )
                    ),
                    description=item.get(
                        "description"
                    ),
                    event_id=item.get(
                        "event_id"
                    ),
                    metadata=dict(
                        item.get(
                            "metadata",
                            {}
                        ) or {}
                    ),
                )
            )

        relationship_edges: List[
            EvidenceRelationship
        ] = []

        for item in data.get(
            "relationship_edges",
            [],
        ) or []:
            if isinstance(
                item,
                EvidenceRelationship,
            ):
                relationship_edges.append(item)
                continue

            if not isinstance(item, dict):
                continue

            relationship_edges.append(
                EvidenceRelationship(
                    source_event_id=item.get(
                        "from_event_id",
                        item.get(
                            "source_event_id"
                        ),
                    ),
                    target_event_id=item.get(
                        "to_event_id",
                        item.get(
                            "target_event_id"
                        ),
                    ),
                    relationship_type=item.get(
                        "type",
                        item.get(
                            "relationship_type",
                            "observed",
                        ),
                    ),
                    time_delta_seconds=item.get(
                        "time_delta_seconds"
                    ),
                    source_a=item.get(
                        "source_a"
                    ),
                    source_b=item.get(
                        "source_b"
                    ),
                )
            )

        return cls(
            ioc_type=data.get(
                "ioc_type",
                "",
            ),
            ioc_value=data.get(
                "ioc_value",
                data.get(
                    "value",
                    "",
                ),
            ),
            event_count=int(
                data.get(
                    "event_count",
                    data.get(
                        "evidence_count",
                        len(evidence_items),
                    ),
                )
            ),
            sources=list(
                data.get(
                    "sources",
                    [],
                ) or []
            ),
            event_types=list(
                data.get(
                    "event_types",
                    [],
                ) or []
            ),
            first_seen=data.get(
                "first_seen"
            ),
            last_seen=data.get(
                "last_seen"
            ),
            time_span_seconds=data.get(
                "time_span_seconds"
            ),
            relationship=data.get(
                "relationship",
                "observed",
            ),
            description=data.get(
                "description",
                "",
            ),
            related_event_ids=list(
                data.get(
                    "related_event_ids",
                    [],
                ) or []
            ),
            evidence=evidence_items,
            relationship_edges=relationship_edges,
            closest_cross_source_gap_seconds=data.get(
                "closest_cross_source_gap_seconds"
            ),
        )


class CorrelationEngine:
    """
    Correlate IOC observations across normalized LogViewer events.

    The engine is intentionally evidence-driven:

        Event -> IOC observation -> Evidence -> CorrelationFinding

    Performance-sensitive operations are cached per event so repeated
    normalization and IOC extraction work is avoided.
    """

    DEFAULT_WINDOW_SECONDS = 300
    ALL_PAIRS_THRESHOLD = 200
    MAX_RELATIONSHIP_EDGES = 2000

    RELATIONSHIP_PRIORITY = {
        "cross_source_temporal": 4,
        "cross_source": 3,
        "repeated": 2,
        "observed": 1,
    }

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.window_seconds = window_seconds
        self._event_cache: Dict[str, Dict[str, object]] = {}

    def correlate(
        self,
        events: Iterable[Event],
    ) -> List[CorrelationFinding]:
        """
        Correlate IOC observations across events.

        Performance characteristics:
            - Event normalization is cached once per event.
            - IOC extraction is performed once per event.
            - Timestamp parsing is cached once per event.
            - Evidence is grouped by IOC before correlation.
            - Large evidence groups use bounded relationship
              construction rather than quadratic all-pairs scanning.
        """

        events = list(events)

        grouped: Dict[
            Tuple[str, str],
            List[Evidence],
        ] = {}

        try:
            for event in events:
                cache = self._prepare_event_cache(event)

                event_iocs = cache["iocs"]

                for ioc_type, values in event_iocs.items():
                    for value in values:
                        evidence = self._build_cached_evidence(
                            event=event,
                            ioc_type=ioc_type,
                            value=value,
                            cache=cache,
                        )

                        key = (ioc_type, value)

                        grouped.setdefault(
                            key,
                            [],
                        ).append(evidence)

            findings: List[CorrelationFinding] = []

            for (
                ioc_type,
                value,
            ), evidence in grouped.items():
                finding = self.correlate_evidence(
                    ioc_type=ioc_type,
                    value=value,
                    evidence=evidence,
                )

                if finding is not None:
                    findings.append(finding)

            findings.sort(
                key=lambda finding: (
                    -self.RELATIONSHIP_PRIORITY.get(
                        finding.relationship,
                        0,
                    ),
                    -finding.event_count,
                    finding.first_seen or "",
                    finding.ioc_type,
                    finding.ioc_value,
                )
            )

            return findings

        finally:
            self._event_cache.clear()

    def correlate_events(
        self,
        events: Iterable[Event],
    ) -> List[CorrelationFinding]:
        """
        Compatibility alias for correlate().
        """

        return self.correlate(events)

    def _prepare_event_cache(
        self,
        event: Event,
    ) -> Dict[str, object]:
        """
        Normalize everything needed for an event once.
        """

        identifier = event_id(event)

        cached = self._event_cache.get(identifier)

        if cached is not None:
            return cached

        normalized_context = event_context(event)

        normalized_event_text = event_text(event)

        cached = {
            "event_id": identifier,
            "context": normalized_context,
            "event_text": normalized_event_text,
            "correlation_keys": correlation_keys(event),
            "timestamp": parse_event_timestamp(
                event.timestamp
            ),
            "iocs": extract_event_iocs(
                event,
                text=normalized_event_text,
            ),
        }

        self._event_cache[identifier] = cached

        return cached

    @staticmethod
    def _build_cached_evidence(
        event: Event,
        ioc_type: str,
        value: str,
        cache: Dict[str, object],
    ) -> Evidence:
        """
        Build Evidence from already-normalized event data.
        """

        normalized_context = cache["context"]

        metadata = dict(normalized_context)

        metadata["message"] = event.message or ""

        metadata["event_text"] = cache["event_text"]

        metadata["correlation_keys"] = cache[
            "correlation_keys"
        ]

        metadata["normalized_timestamp"] = (
            normalized_context.get("timestamp")
        )

        metadata["original_timestamp"] = event.timestamp

        metadata["original_source"] = event.source

        return Evidence(
            evidence_type=ioc_type,
            value=value,
            source=event.source,
            timestamp=event.timestamp,
            confidence=1.0,
            description=(
                f"{ioc_type.upper()} observed in "
                f"{event.source}."
            ),
            event_id=cache["event_id"],
            metadata=metadata,
        )

    def extract_evidence(
        self,
        event: Event,
        ioc_type: str,
        value: str,
    ) -> Evidence:
        """
        Convert an IOC observation from an Event into Evidence.

        This remains a public method for compatibility.
        """

        cache = self._prepare_event_cache(event)

        return self._build_cached_evidence(
            event=event,
            ioc_type=ioc_type,
            value=value,
            cache=cache,
        )

    def correlate_evidence(
        self,
        ioc_type: str,
        value: str,
        evidence: Iterable[Evidence],
    ) -> Optional[CorrelationFinding]:
        """
        Build a finding from supporting evidence.
        """

        evidence_list = list(evidence)

        if not evidence_list:
            return None

        timestamped: List[
            Tuple[datetime, Evidence]
        ] = []

        for item in evidence_list:
            parsed_timestamp = self._parse_timestamp(
                item.timestamp
            )

            if parsed_timestamp is not None:
                timestamped.append(
                    (
                        parsed_timestamp,
                        item,
                    )
                )

        timestamped.sort(
            key=lambda pair: pair[0]
        )

        sources = sorted(
            {
                item.source
                for item in evidence_list
                if item.source
            }
        )

        event_types = sorted(
            {
                item.metadata.get("event_type") or ""
                for item in evidence_list
                if item.metadata.get("event_type")
            }
        )

        related_event_ids = list(
            dict.fromkeys(
                item.event_id
                for item in evidence_list
                if item.event_id
            )
        )

        if timestamped:
            first_seen = timestamped[0][0]
            last_seen = timestamped[-1][0]

            time_span_seconds = max(
                0.0,
                (
                    last_seen - first_seen
                ).total_seconds(),
            )
        else:
            first_seen = None
            last_seen = None
            time_span_seconds = None

        closest_cross_source_gap = (
            self._closest_cross_source_gap(
                timestamped
            )
        )

        relationship_edges = (
            self._build_relationship_edges(
                timestamped
            )
        )

        relationship = self._classify_relationship(
            evidence_count=len(evidence_list),
            source_count=len(sources),
            time_span_seconds=time_span_seconds,
            closest_cross_source_gap=(
                closest_cross_source_gap
            ),
        )

        description = self._build_description(
            ioc_type=ioc_type,
            value=value,
            evidence_count=len(evidence_list),
            source_count=len(sources),
            relationship=relationship,
            time_span_seconds=time_span_seconds,
        )

        return CorrelationFinding(
            ioc_type=ioc_type,
            ioc_value=value,
            event_count=len(evidence_list),
            sources=sources,
            event_types=event_types,
            first_seen=(
                first_seen.isoformat()
                if first_seen is not None
                else None
            ),
            last_seen=(
                last_seen.isoformat()
                if last_seen is not None
                else None
            ),
            time_span_seconds=time_span_seconds,
            relationship=relationship,
            description=description,
            related_event_ids=related_event_ids,
            evidence=evidence_list,
            relationship_edges=relationship_edges,
            closest_cross_source_gap_seconds=(
                closest_cross_source_gap
            ),
        )

    def _build_relationship_edges(
        self,
        timestamped: List[
            Tuple[
                datetime,
                Evidence,
            ]
        ],
    ) -> List[EvidenceRelationship]:
        """
        Build bounded relationship edges between evidence observations.
        """

        if len(timestamped) < 2:
            return []

        if len(timestamped) <= self.ALL_PAIRS_THRESHOLD:
            return self._build_all_pair_edges(
                timestamped
            )

        return self._build_bounded_relationship_edges(
            timestamped
        )

    def _build_all_pair_edges(
        self,
        timestamped: List[
            Tuple[
                datetime,
                Evidence,
            ]
        ],
    ) -> List[EvidenceRelationship]:
        """
        Build relationship edges using all observation pairs.
        """

        edges: List[EvidenceRelationship] = []

        for index, (
            timestamp_a,
            evidence_a,
        ) in enumerate(timestamped):
            for (
                timestamp_b,
                evidence_b,
            ) in timestamped[index + 1:]:
                gap = (
                    timestamp_b - timestamp_a
                ).total_seconds()

                if gap > self.window_seconds:
                    break

                if (
                    evidence_a.event_id
                    == evidence_b.event_id
                ):
                    continue

                edge_type = (
                    "cross_source_temporal"
                    if evidence_a.source
                    != evidence_b.source
                    else "repeated"
                )

                edges.append(
                    EvidenceRelationship(
                        source_event_id=evidence_a.event_id,
                        target_event_id=evidence_b.event_id,
                        relationship_type=edge_type,
                        time_delta_seconds=gap,
                        source_a=evidence_a.source,
                        source_b=evidence_b.source,
                    )
                )

                if (
                    len(edges)
                    >= self.MAX_RELATIONSHIP_EDGES
                ):
                    return edges

        return edges

    def _build_bounded_relationship_edges(
        self,
        timestamped: List[
            Tuple[
                datetime,
                Evidence,
            ]
        ],
    ) -> List[EvidenceRelationship]:
        """
        Build bounded relationship edges for large evidence groups.

        Each observation is connected to:
            - the nearest temporal observation on the right
            - the nearest temporal observation on the left
            - the nearest cross-source observation on each side

        The nearest cross-source observations are located using
        precomputed neighboring-source indexes rather than repeatedly
        scanning through the evidence list.
        """

        edges: List[EvidenceRelationship] = []

        seen = set()

        count = len(timestamped)

        timestamps = [
            timestamp
            for timestamp, _ in timestamped
        ]

        left_cross_source: List[Optional[int]] = [
            None
        ] * count

        last_index_by_source: Dict[
            Optional[str],
            int,
        ] = {}

        most_recent_index: Optional[int] = None
        second_recent_index: Optional[int] = None

        for index, (
            _timestamp,
            evidence,
        ) in enumerate(timestamped):
            source = evidence.source

            if (
                most_recent_index is not None
                and timestamped[
                    most_recent_index
                ][1].source != source
            ):
                left_cross_source[index] = (
                    most_recent_index
                )
            elif (
                second_recent_index is not None
                and timestamped[
                    second_recent_index
                ][1].source != source
            ):
                left_cross_source[index] = (
                    second_recent_index
                )

            previous_source_index = (
                last_index_by_source.get(source)
            )

            if (
                most_recent_index is None
                or index > most_recent_index
            ):
                if (
                    most_recent_index is not None
                    and timestamped[
                        most_recent_index
                    ][1].source != source
                ):
                    second_recent_index = (
                        most_recent_index
                    )

                most_recent_index = index

            elif (
                previous_source_index is not None
                and previous_source_index
                == most_recent_index
            ):
                pass

            last_index_by_source[source] = index

        left_cross_source = [None] * count

        first_index: Optional[int] = None
        second_index: Optional[int] = None

        for index, (
            _timestamp,
            evidence,
        ) in enumerate(timestamped):
            source = evidence.source

            if (
                first_index is not None
                and timestamped[
                    first_index
                ][1].source != source
            ):
                left_cross_source[index] = first_index

            elif (
                second_index is not None
                and timestamped[
                    second_index
                ][1].source != source
            ):
                left_cross_source[index] = second_index

            if (
                first_index is None
                or index > first_index
            ):
                if (
                    first_index is not None
                    and timestamped[
                        first_index
                    ][1].source != source
                ):
                    second_index = first_index

                elif (
                    first_index is not None
                    and timestamped[
                        first_index
                    ][1].source == source
                ):
                    second_index = first_index

                first_index = index

        right_cross_source: List[Optional[int]] = [
            None
        ] * count

        first_index = None
        second_index = None

        for index in range(count - 1, -1, -1):
            source = timestamped[index][1].source

            if (
                first_index is not None
                and timestamped[
                    first_index
                ][1].source != source
            ):
                right_cross_source[index] = first_index

            elif (
                second_index is not None
                and timestamped[
                    second_index
                ][1].source != source
            ):
                right_cross_source[index] = second_index

            if (
                first_index is None
                or index < first_index
            ):
                if (
                    first_index is not None
                    and timestamped[
                        first_index
                    ][1].source != source
                ):
                    second_index = first_index

                elif (
                    first_index is not None
                    and timestamped[
                        first_index
                    ][1].source == source
                ):
                    second_index = first_index

                first_index = index

        for index, (
            timestamp,
            evidence,
        ) in enumerate(timestamped):
            if len(edges) >= self.MAX_RELATIONSHIP_EDGES:
                return edges

            right_index = index + 1

            if right_index < count:
                right_timestamp, right_evidence = (
                    timestamped[right_index]
                )

                gap = (
                    right_timestamp - timestamp
                ).total_seconds()

                if (
                    gap <= self.window_seconds
                    and evidence.event_id
                    != right_evidence.event_id
                ):
                    self._append_relationship_edge(
                        edges=edges,
                        seen=seen,
                        evidence_a=evidence,
                        evidence_b=right_evidence,
                        gap=gap,
                    )

            if len(edges) >= self.MAX_RELATIONSHIP_EDGES:
                return edges

            left_index = index - 1

            if left_index >= 0:
                left_timestamp, left_evidence = (
                    timestamped[left_index]
                )

                gap = (
                    timestamp - left_timestamp
                ).total_seconds()

                if (
                    gap <= self.window_seconds
                    and evidence.event_id
                    != left_evidence.event_id
                ):
                    self._append_relationship_edge(
                        edges=edges,
                        seen=seen,
                        evidence_a=left_evidence,
                        evidence_b=evidence,
                        gap=gap,
                    )

            if len(edges) >= self.MAX_RELATIONSHIP_EDGES:
                return edges

            cross_left = left_cross_source[index]

            if cross_left is not None:
                cross_timestamp, cross_evidence = (
                    timestamped[cross_left]
                )

                gap = abs(
                    (
                        cross_timestamp - timestamp
                    ).total_seconds()
                )

                if (
                    gap <= self.window_seconds
                    and cross_evidence.event_id
                    != evidence.event_id
                ):
                    self._append_relationship_edge(
                        edges=edges,
                        seen=seen,
                        evidence_a=cross_evidence,
                        evidence_b=evidence,
                        gap=gap,
                    )

            if len(edges) >= self.MAX_RELATIONSHIP_EDGES:
                return edges

            cross_right = right_cross_source[index]

            if cross_right is not None:
                cross_timestamp, cross_evidence = (
                    timestamped[cross_right]
                )

                gap = abs(
                    (
                        cross_timestamp - timestamp
                    ).total_seconds()
                )

                if (
                    gap <= self.window_seconds
                    and cross_evidence.event_id
                    != evidence.event_id
                ):
                    self._append_relationship_edge(
                        edges=edges,
                        seen=seen,
                        evidence_a=evidence,
                        evidence_b=cross_evidence,
                        gap=gap,
                    )

        return edges

    def _append_relationship_edge(
        self,
        edges: List[EvidenceRelationship],
        seen: set,
        evidence_a: Evidence,
        evidence_b: Evidence,
        gap: float,
    ) -> None:
        """
        Append a relationship edge unless it has already been observed.
        """

        event_a = evidence_a.event_id
        event_b = evidence_b.event_id

        if not event_a or not event_b:
            return

        key = (
            event_a,
            event_b,
        )

        reverse_key = (
            event_b,
            event_a,
        )

        if (
            key in seen
            or reverse_key in seen
        ):
            return

        edge_type = (
            "cross_source_temporal"
            if evidence_a.source
            != evidence_b.source
            else "repeated"
        )

        edges.append(
            EvidenceRelationship(
                source_event_id=event_a,
                target_event_id=event_b,
                relationship_type=edge_type,
                time_delta_seconds=gap,
                source_a=evidence_a.source,
                source_b=evidence_b.source,
            )
        )

        seen.add(key)

    def _closest_cross_source_gap(
        self,
        timestamped: List[
            Tuple[
                datetime,
                Evidence,
            ]
        ],
    ) -> Optional[float]:
        """
        Find the smallest temporal gap between different sources.

        Because timestamped evidence is sorted chronologically, the
        smallest cross-source temporal gap must occur between adjacent
        observations whose sources differ. If an intermediate event
        exists, it produces an equal-or-smaller gap to at least one
        endpoint.

        Therefore this operation is O(n), rather than O(n²).
        """

        if len(timestamped) < 2:
            return None

        closest: Optional[float] = None

        for index in range(len(timestamped) - 1):
            timestamp_a, evidence_a = timestamped[index]
            timestamp_b, evidence_b = timestamped[index + 1]

            if evidence_a.source == evidence_b.source:
                continue

            gap = (
                timestamp_b - timestamp_a
            ).total_seconds()

            if gap > self.window_seconds:
                continue

            if (
                closest is None
                or gap < closest
            ):
                closest = gap

                if closest == 0:
                    return 0.0

        return closest

    def _classify_relationship(
        self,
        evidence_count: int,
        source_count: int,
        time_span_seconds: Optional[float],
        closest_cross_source_gap: Optional[float],
    ) -> str:
        """
        Classify the strength/type of the observed relationship.
        """

        if evidence_count < 2:
            return "observed"

        if (
            source_count >= 2
            and closest_cross_source_gap is not None
            and closest_cross_source_gap
            <= self.window_seconds
        ):
            return "cross_source_temporal"

        if source_count >= 2:
            return "cross_source"

        if (
            time_span_seconds is not None
            and time_span_seconds
            <= self.window_seconds
        ):
            return "repeated"

        return "observed"

    @staticmethod
    def _build_description(
        ioc_type: str,
        value: str,
        evidence_count: int,
        source_count: int,
        relationship: str,
        time_span_seconds: Optional[float],
    ) -> str:
        """
        Generate an evidence-based human-readable finding description.
        """

        description = (
            f"{ioc_type.upper()} {value} was observed "
            f"{evidence_count} time"
            f"{'' if evidence_count == 1 else 's'} "
            f"across {source_count} source"
            f"{'' if source_count == 1 else 's'}."
        )

        if relationship == "cross_source_temporal":
            description += (
                " Observations occurred across multiple "
                "sources within the correlation window."
            )
        elif relationship == "cross_source":
            description += (
                " Observations were recorded by multiple sources."
            )
        elif relationship == "repeated":
            description += (
                " Repeated observations occurred within "
                "the correlation window."
            )

        if time_span_seconds is not None:
            description += (
                f" Observed span: "
                f"{time_span_seconds:.1f} seconds."
            )

        return description

    @staticmethod
    def _event_id(event: Event) -> str:
        """
        Compatibility wrapper for the normalized event ID helper.
        """

        return event_id(event)

    @staticmethod
    def _parse_timestamp(
        value: object,
    ) -> Optional[datetime]:
        """
        Parse a timestamp into timezone-aware UTC.
        """

        parsed = parse_event_timestamp(value)

        if parsed is None:
            return None

        if parsed.tzinfo is None:
            return parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(timezone.utc)
