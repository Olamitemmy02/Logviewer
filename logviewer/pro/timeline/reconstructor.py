from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from logviewer.pro.timeline.model import (
    TIMELINE_FEATURE,
    SecurityTimeline,
    TimelineEntry,
)


class TimelineReconstructor:
    """
    Build a chronological timeline from existing investigation data.

    Supported inputs:
      - Events
      - Correlations
      - MITRE mappings
      - Process-tree relationships
      - Attack-chain steps and links

    Analytical objects are labeled separately from raw events. This class
    does not create or modify source events.
    """

    def __init__(self, feature_gate: Any = None) -> None:
        self.feature_gate = feature_gate

    def reconstruct(self, investigation: Any) -> SecurityTimeline:
        self._require_feature()

        investigation_id = str(
            self._get(investigation, "investigation_id", "unknown")
        )

        timeline = SecurityTimeline(
            investigation_id=investigation_id
        )

        events = self._as_list(
            self._get(investigation, "events", [])
        )
        correlations = self._as_list(
            self._get(investigation, "correlations", [])
        )
        mitre_mappings = self._as_list(
            self._get(investigation, "mitre_mappings", [])
        )

        process_tree = self._get(investigation, "process_tree", {}) or {}
        attack_chain = self._get(investigation, "attack_chain", {}) or {}

        event_index: Dict[str, TimelineEntry] = {}

        # 1. Original security events
        for index, event in enumerate(events):
            entry = self._event_entry(event, index)

            if entry is None:
                continue

            timeline.add_entry(entry)

            if entry.event_id:
                event_index[entry.event_id] = entry

        timeline.event_count = len(
            [
                entry
                for entry in timeline.entries
                if entry.entry_type == "event"
            ]
        )

        # 2. Correlation findings
        for index, correlation in enumerate(correlations):
            entry = self._correlation_entry(
                correlation,
                index,
                event_index,
            )

            if entry is not None:
                timeline.add_entry(entry)

        timeline.correlation_count = len(
            [
                entry
                for entry in timeline.entries
                if entry.entry_type == "correlation"
            ]
        )

        # 3. MITRE mappings
        for index, mapping in enumerate(mitre_mappings):
            entry = self._mitre_entry(
                mapping,
                index,
                event_index,
            )

            if entry is not None:
                timeline.add_entry(entry)

        timeline.mitre_count = len(
            [
                entry
                for entry in timeline.entries
                if entry.entry_type == "mitre"
            ]
        )

        # 4. Process relationships
        process_relationships = self._extract_process_relationships(
            process_tree
        )

        for index, relationship in enumerate(process_relationships):
            entry = self._process_entry(
                relationship,
                index,
            )

            if entry is not None:
                timeline.add_entry(entry)

        timeline.process_relationship_count = len(
            [
                entry
                for entry in timeline.entries
                if entry.entry_type == "process_relationship"
            ]
        )

        # 5. Attack-chain steps
        chain_steps = self._as_list(
            self._get(attack_chain, "steps", [])
        )

        for index, step in enumerate(chain_steps):
            entry = self._attack_step_entry(
                step,
                index,
            )

            if entry is not None:
                timeline.add_entry(entry)

        timeline.attack_chain_step_count = len(
            [
                entry
                for entry in timeline.entries
                if entry.entry_type == "attack_chain_step"
            ]
        )

        # Preserve source relationships.
        self._link_entries(
            timeline,
            event_index,
        )

        timeline.sort_entries()

        self._set_time_bounds(timeline)

        timeline.confidence = self._overall_confidence(
            timeline
        )

        timeline.metadata.update(
            {
                "source_event_count": timeline.event_count,
                "source_correlation_count": timeline.correlation_count,
                "source_mitre_mapping_count": timeline.mitre_count,
                "source_process_relationship_count":
                    timeline.process_relationship_count,
                "source_attack_chain_step_count":
                    timeline.attack_chain_step_count,
                "analytical_entries_are_not_raw_events": True,
            }
        )

        return timeline

    def reconstruct_and_store(
        self,
        investigation: Any,
    ) -> SecurityTimeline:
        """
        Reconstruct and store serialized timeline data when the investigation
        exposes a timeline attribute, setter, or metadata dictionary.
        """

        timeline = self.reconstruct(investigation)

        serialized = timeline.as_dict()

        if isinstance(investigation, dict):
            investigation["timeline"] = serialized
            return timeline

        setter = getattr(
            investigation,
            "set_timeline",
            None,
        )

        if callable(setter):
            setter(serialized)
            return timeline

        metadata = getattr(
            investigation,
            "metadata",
            None,
        )

        if isinstance(metadata, dict):
            metadata["timeline"] = serialized
            return timeline

        setattr(
            investigation,
            "timeline",
            serialized,
        )

        return timeline

    def _require_feature(self) -> None:
        if self.feature_gate is None:
            return

        checker = getattr(
            self.feature_gate,
            "check",
            None,
        )

        if not callable(checker):
            raise TypeError(
                "feature_gate must provide a check(feature_name) method"
            )

        allowed = checker(TIMELINE_FEATURE)

        if not allowed:
            raise PermissionError(
                "Timeline Reconstruction requires the Pro timeline feature."
            )

    def _event_entry(
        self,
        event: Any,
        index: int,
    ) -> Optional[TimelineEntry]:
        timestamp = self._text(
            self._get(
                event,
                "timestamp",
                "",
            )
        )

        if not timestamp:
            return None

        event_id = self._text(
            self._first(
                event,
                (
                    "event_id",
                    "id",
                    "uuid",
                    "fingerprint",
                ),
                "",
            )
        )

        if not event_id:
            event_id = f"event-{index + 1}"

        source = self._text(
            self._get(
                event,
                "source",
                "",
            )
        )

        severity = self._text(
            self._get(
                event,
                "severity",
                "INFO",
            )
        ).upper()

        message = self._text(
            self._get(
                event,
                "message",
                "",
            )
        )

        event_type = self._text(
            self._get(
                event,
                "event_type",
                "",
            )
        )

        title = (
            event_type
            or source
            or "Security event"
        )

        return TimelineEntry(
            entry_id=f"event:{event_id}",
            timestamp=timestamp,
            entry_type="event",
            title=title,
            description=message,
            source=source,
            severity=severity,
            confidence=1.0,
            event_id=event_id,
            process=self._text(
                self._get(
                    event,
                    "process",
                    "",
                )
            ),
            pid=self._get(
                event,
                "pid",
                None,
            ),
            parent_pid=self._get(
                event,
                "parent_pid",
                None,
            ),
            metadata={
                "parser": self._get(
                    event,
                    "parser",
                    "",
                ),
                "host": self._get(
                    event,
                    "host",
                    "",
                ),
                "user": self._get(
                    event,
                    "user",
                    "",
                ),
                "protocol": self._get(
                    event,
                    "protocol",
                    "",
                ),
                "src_ip": self._get(
                    event,
                    "src_ip",
                    "",
                ),
                "dst_ip": self._get(
                    event,
                    "dst_ip",
                    "",
                ),
                "raw_event_type": event_type,
            },
        )

    def _correlation_entry(
        self,
        correlation: Any,
        index: int,
        event_index: Dict[str, TimelineEntry],
    ) -> Optional[TimelineEntry]:
        timestamp = self._text(
            self._first(
                correlation,
                (
                    "timestamp",
                    "first_seen",
                    "start_time",
                    "created_at",
                ),
                "",
            )
        )

        related_ids = self._extract_ids(
            self._first(
                correlation,
                (
                    "event_ids",
                    "related_event_ids",
                    "matched_events",
                ),
                [],
            )
        )

        if not timestamp:
            timestamp = self._timestamp_from_events(
                related_ids,
                event_index,
            )

        if not timestamp:
            return None

        title = self._text(
            self._first(
                correlation,
                (
                    "title",
                    "name",
                    "rule_name",
                    "type",
                ),
                "Correlation finding",
            )
        )

        description = self._text(
            self._first(
                correlation,
                (
                    "description",
                    "summary",
                    "rationale",
                    "message",
                ),
                "",
            )
        )

        return TimelineEntry(
            entry_id=f"correlation:{index + 1}",
            timestamp=timestamp,
            entry_type="correlation",
            title=title,
            description=description,
            severity=self._text(
                self._get(
                    correlation,
                    "severity",
                    "INFO",
                )
            ).upper(),
            confidence=self._confidence(
                self._get(
                    correlation,
                    "confidence",
                    0.0,
                )
            ),
            related_entry_ids=[
                f"event:{event_id}"
                for event_id in related_ids
            ],
            metadata={
                "source_type": type(correlation).__name__,
                "source_id": self._text(
                    self._first(
                        correlation,
                        (
                            "finding_id",
                            "correlation_id",
                            "id",
                        ),
                        "",
                    )
                ),
            },
        )

    def _mitre_entry(
        self,
        mapping: Any,
        index: int,
        event_index: Dict[str, TimelineEntry],
    ) -> Optional[TimelineEntry]:
        """
        Convert a MITRE mapping into a timeline analytical entry.

        MitreMapper currently stores matched_events as dictionaries containing
        observation metadata such as timestamp/source/matched_patterns. Those
        records are not necessarily event IDs, so timestamp reconstruction must
        support both event-ID references and embedded matched-event metadata.
        """

        matched_events = self._as_list(
            self._get(
                mapping,
                "matched_events",
                [],
            )
        )

        matched_ids = self._extract_ids(
            matched_events
        )

        timestamp = self._text(
            self._first(
                mapping,
                (
                    "timestamp",
                    "first_seen",
                    "created_at",
                    "start_time",
                ),
                "",
            )
        )

        # First fallback: timestamps embedded directly in matched_events.
        if not timestamp:
            timestamp = self._timestamp_from_matched_events(
                matched_events
            )

        # Second fallback: matched event IDs pointing to original events.
        if not timestamp:
            timestamp = self._timestamp_from_events(
                matched_ids,
                event_index,
            )

        if not timestamp:
            return None

        technique_id = self._text(
            self._get(
                mapping,
                "technique_id",
                "",
            )
        )

        technique_name = self._text(
            self._get(
                mapping,
                "technique_name",
                "",
            )
        )

        tactic = self._text(
            self._get(
                mapping,
                "tactic",
                "",
            )
        )

        title = " ".join(
            part
            for part in (
                technique_id,
                technique_name,
            )
            if part
        )

        if not title:
            title = "MITRE technique mapping"

        return TimelineEntry(
            entry_id=f"mitre:{index + 1}",
            timestamp=timestamp,
            entry_type="mitre",
            title=title,
            description=self._text(
                self._get(
                    mapping,
                    "rationale",
                    "",
                )
            ),
            confidence=self._confidence(
                self._get(
                    mapping,
                    "confidence",
                    0.0,
                )
            ),
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            related_entry_ids=[
                f"event:{event_id}"
                for event_id in matched_ids
            ],
            metadata={
                "interpretation_only": True,
                "matched_event_count": len(
                    matched_events
                ),
            },
        )

    def _extract_process_relationships(
        self,
        process_tree: Any,
    ) -> List[Any]:
        if isinstance(process_tree, list):
            return process_tree

        relationships = self._first(
            process_tree,
            (
                "relationships",
                "process_relationships",
                "edges",
                "links",
            ),
            [],
        )

        if relationships:
            return self._as_list(
                relationships
            )

        nodes = self._as_list(
            self._get(
                process_tree,
                "nodes",
                [],
            )
        )

        derived = []

        for node in nodes:
            parent_pid = self._get(
                node,
                "parent_pid",
                None,
            )

            if parent_pid is None:
                continue

            derived.append(
                {
                    "timestamp": self._get(
                        node,
                        "timestamp",
                        "",
                    ),
                    "process": self._get(
                        node,
                        "process",
                        "",
                    ),
                    "pid": self._get(
                        node,
                        "pid",
                        None,
                    ),
                    "parent_pid": parent_pid,
                    "description":
                        "Parent-child process relationship.",
                }
            )

        return derived

    def _process_entry(
        self,
        relationship: Any,
        index: int,
    ) -> Optional[TimelineEntry]:
        timestamp = self._text(
            self._first(
                relationship,
                (
                    "timestamp",
                    "first_seen",
                    "created_at",
                ),
                "",
            )
        )

        if not timestamp:
            timestamp = self._text(
                self._get(
                    relationship,
                    "start_time",
                    "",
                )
            )

        if not timestamp:
            return None

        process = self._text(
            self._first(
                relationship,
                (
                    "process",
                    "child_process",
                    "name",
                    "command",
                ),
                "",
            )
        )

        parent_process = self._text(
            self._first(
                relationship,
                (
                    "parent_process",
                    "parent_name",
                ),
                "",
            )
        )

        pid = self._get(
            relationship,
            "pid",
            self._get(
                relationship,
                "child_pid",
                None,
            ),
        )

        parent_pid = self._get(
            relationship,
            "parent_pid",
            None,
        )

        description = self._text(
            self._get(
                relationship,
                "description",
                "Observed process relationship.",
            )
        )

        return TimelineEntry(
            entry_id=f"process:{index + 1}",
            timestamp=timestamp,
            entry_type="process_relationship",
            title="Process relationship",
            description=description,
            process=process,
            pid=pid,
            parent_pid=parent_pid,
            confidence=self._confidence(
                self._get(
                    relationship,
                    "confidence",
                    0.0,
                )
            ),
            metadata={
                "parent_process": parent_process,
            },
        )

    def _attack_step_entry(
        self,
        step: Any,
        index: int,
    ) -> Optional[TimelineEntry]:
        timestamp = self._text(
            self._first(
                step,
                (
                    "timestamp",
                    "start_time",
                    "first_seen",
                ),
                "",
            )
        )

        if not timestamp:
            timestamp = self._text(
                self._get(
                    step,
                    "end_time",
                    "",
                )
            )

        if not timestamp:
            return None

        technique_id = self._text(
            self._get(
                step,
                "technique_id",
                "",
            )
        )

        technique_name = self._text(
            self._get(
                step,
                "technique_name",
                "",
            )
        )

        tactic = self._text(
            self._get(
                step,
                "tactic",
                "",
            )
        )

        title = self._text(
            self._first(
                step,
                (
                    "title",
                    "name",
                    "stage",
                ),
                "",
            )
        )

        if not title:
            title = " ".join(
                part
                for part in (
                    technique_id,
                    technique_name,
                )
                if part
            )

        if not title:
            title = "Attack-chain step"

        event_ids = self._extract_ids(
            self._first(
                step,
                (
                    "event_ids",
                    "related_event_ids",
                    "matched_events",
                ),
                [],
            )
        )

        return TimelineEntry(
            entry_id=f"attack-chain:{index + 1}",
            timestamp=timestamp,
            entry_type="attack_chain_step",
            title=title,
            description=self._text(
                self._first(
                    step,
                    (
                        "description",
                        "rationale",
                    ),
                    "",
                )
            ),
            severity=self._text(
                self._get(
                    step,
                    "severity",
                    "INFO",
                )
            ).upper(),
            confidence=self._confidence(
                self._get(
                    step,
                    "confidence",
                    0.0,
                )
            ),
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            related_entry_ids=[
                f"event:{event_id}"
                for event_id in event_ids
            ],
            metadata={
                "interpretation_only": True,
                "stage": self._get(
                    step,
                    "stage",
                    "",
                ),
                "step_index": self._get(
                    step,
                    "step_index",
                    index,
                ),
            },
        )

    def _link_entries(
        self,
        timeline: SecurityTimeline,
        event_index: Dict[str, TimelineEntry],
    ) -> None:
        known_ids = {
            entry.entry_id
            for entry in timeline.entries
        }

        for entry in timeline.entries:
            valid_links = []

            for related_id in entry.related_entry_ids:
                if related_id in known_ids:
                    valid_links.append(
                        related_id
                    )

            entry.related_entry_ids = list(
                dict.fromkeys(valid_links)
            )

    def _set_time_bounds(
        self,
        timeline: SecurityTimeline,
    ) -> None:
        timestamps = [
            entry.timestamp
            for entry in timeline.entries
            if self._parse_timestamp(
                entry.timestamp
            ) is not None
        ]

        if not timestamps:
            return

        ordered = sorted(
            timestamps,
            key=self._timestamp_sort_key,
        )

        timeline.start_time = ordered[0]
        timeline.end_time = ordered[-1]

    def _overall_confidence(
        self,
        timeline: SecurityTimeline,
    ) -> float:
        if not timeline.entries:
            return 0.0

        values = [
            self._confidence(
                entry.confidence
            )
            for entry in timeline.entries
        ]

        return round(
            sum(values) / len(values),
            4,
        )

    def _timestamp_from_events(
        self,
        event_ids: Iterable[str],
        event_index: Dict[str, TimelineEntry],
    ) -> str:
        timestamps = []

        for event_id in event_ids:
            entry = event_index.get(
                str(event_id)
            )

            if entry is not None and entry.timestamp:
                timestamps.append(
                    entry.timestamp
                )

        if not timestamps:
            return ""

        return min(
            timestamps,
            key=self._timestamp_sort_key,
        )

    @classmethod
    def _timestamp_from_matched_events(
        cls,
        matched_events: Iterable[Any],
    ) -> str:
        """
        Extract the earliest valid timestamp from MITRE matched-event records.

        Matched-event records may contain:
          - timestamp
          - first_seen
          - start_time
          - created_at

        Invalid or missing timestamps are ignored.
        """

        timestamps = []

        for matched_event in cls._as_list(
            matched_events
        ):
            timestamp = cls._text(
                cls._first(
                    matched_event,
                    (
                        "timestamp",
                        "first_seen",
                        "start_time",
                        "created_at",
                    ),
                    "",
                )
            )

            if timestamp and cls._parse_timestamp(
                timestamp
            ) is not None:
                timestamps.append(timestamp)

        if not timestamps:
            return ""

        return min(
            timestamps,
            key=cls._timestamp_sort_key,
        )

    @staticmethod
    def _get(
        obj: Any,
        key: str,
        default: Any = None,
    ) -> Any:
        if isinstance(obj, dict):
            return obj.get(
                key,
                default,
            )

        return getattr(
            obj,
            key,
            default,
        )

    @classmethod
    def _first(
        cls,
        obj: Any,
        keys: Tuple[str, ...],
        default: Any = None,
    ) -> Any:
        for key in keys:
            value = cls._get(
                obj,
                key,
                None,
            )

            if value is not None and value != "":
                return value

        return default

    @staticmethod
    def _as_list(
        value: Any,
    ) -> List[Any]:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        if isinstance(value, dict):
            return [value]

        if isinstance(value, (str, bytes)):
            return []

        try:
            return list(value)
        except TypeError:
            return [value]

    @classmethod
    def _extract_ids(
        cls,
        values: Any,
    ) -> List[str]:
        result = []

        for value in cls._as_list(values):
            if isinstance(
                value,
                (str, int),
            ):
                result.append(
                    str(value)
                )
                continue

            candidate = cls._first(
                value,
                (
                    "event_id",
                    "id",
                    "uuid",
                    "fingerprint",
                ),
                "",
            )

            if candidate:
                result.append(
                    str(candidate)
                )

        return list(
            dict.fromkeys(result)
        )

    @staticmethod
    def _text(
        value: Any,
    ) -> str:
        if value is None:
            return ""

        return str(value).strip()

    @staticmethod
    def _confidence(
        value: Any,
    ) -> float:
        try:
            number = float(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

        if number > 1.0 and number <= 100.0:
            number /= 100.0

        return max(
            0.0,
            min(
                1.0,
                number,
            )
        )

    @classmethod
    def _parse_timestamp(
        cls,
        value: Any,
    ) -> Optional[datetime]:
        if not value:
            return None

        text = cls._text(value)

        if not text:
            return None

        normalized = text.replace(
            "Z",
            "+00:00",
        )

        try:
            parsed = datetime.fromisoformat(
                normalized
            )
        except ValueError:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    @classmethod
    def _timestamp_sort_key(
        cls,
        value: Any,
    ) -> float:
        parsed = cls._parse_timestamp(
            value
        )

        if parsed is None:
            return float("inf")

        return parsed.timestamp()


if __name__ == "__main__":
    class AllowAllFeatures:
        @staticmethod
        def check(
            feature_name: str,
        ) -> bool:
            return feature_name == TIMELINE_FEATURE

    investigation = {
        "investigation_id": "TL-TEST-001",
        "events": [
            {
                "event_id": "evt-2",
                "timestamp": "2026-01-01T10:02:00Z",
                "source": "auth.log",
                "severity": "WARNING",
                "message": "Authentication event two",
            },
            {
                "event_id": "evt-1",
                "timestamp": "2026-01-01T10:01:00+00:00",
                "source": "syslog",
                "severity": "INFO",
                "message": "Authentication event one",
            },
        ],
        "correlations": [
            {
                "correlation_id": "corr-1",
                "title": "Related authentication activity",
                "event_ids": [
                    "evt-1",
                    "evt-2",
                ],
                "confidence": 0.75,
            }
        ],
        "mitre_mappings": [
            {
                "technique_id": "T1059",
                "technique_name":
                    "Command and Scripting Interpreter",
                "tactic": "Execution",
                "matched_events": ["evt-2"],
                "confidence": 0.8,
                "rationale":
                    "Candidate mapping for testing.",
            }
        ],
        "process_tree": {
            "relationships": [
                {
                    "timestamp":
                        "2026-01-01T10:03:00Z",
                    "process": "python3",
                    "pid": 200,
                    "parent_pid": 100,
                    "description":
                        "Test parent-child relationship.",
                }
            ]
        },
        "attack_chain": {
            "steps": [
                {
                    "timestamp":
                        "2026-01-01T10:04:00Z",
                    "title": "Execution",
                    "technique_id": "T1059",
                    "technique_name":
                        "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "event_ids": ["evt-2"],
                    "confidence": 0.8,
                }
            ]
        },
    }

    reconstructor = TimelineReconstructor(
        feature_gate=AllowAllFeatures()
    )

    timeline = reconstructor.reconstruct(
        investigation
    )

    result = timeline.as_dict()

    assert result["investigation_id"] == "TL-TEST-001"
    assert result["event_count"] == 2
    assert result["correlation_count"] == 1
    assert result["mitre_count"] == 1
    assert result["process_relationship_count"] == 1
    assert result["attack_chain_step_count"] == 1

    event_entries = [
        entry
        for entry in result["entries"]
        if entry["entry_type"] == "event"
    ]

    assert len(event_entries) == 2
    assert event_entries[0]["event_id"] == "evt-1"
    assert event_entries[1]["event_id"] == "evt-2"

    mitre_entries = [
        entry
        for entry in result["entries"]
        if entry["entry_type"] == "mitre"
    ]

    assert len(mitre_entries) == 1
    assert mitre_entries[0]["technique_id"] == "T1059"

    # Regression test for MitreMapper's matched-event dictionary format.
    matched_event_mapping = {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "matched_events": [
            {
                "matched_patterns": [
                    "event_type:authentication"
                ],
                "timestamp":
                    "2026-01-01T10:01:00Z",
                "source": "auth.log",
            },
            {
                "matched_patterns": [
                    "event_type:authentication"
                ],
                "timestamp":
                    "2026-01-01T10:03:00Z",
                "source": "auth.log",
            },
        ],
        "confidence": 0.65,
        "rationale":
            "Candidate mapping from authentication activity.",
    }

    matched_event_timeline = reconstructor.reconstruct(
        {
            "investigation_id": "TL-MITRE-MATCHED-EVENT-TEST",
            "events": [],
            "correlations": [],
            "mitre_mappings": [
                matched_event_mapping
            ],
            "process_tree": {},
            "attack_chain": {},
        }
    ).as_dict()

    matched_event_mitre_entries = [
        entry
        for entry in matched_event_timeline["entries"]
        if entry["entry_type"] == "mitre"
    ]

    assert len(matched_event_mitre_entries) == 1
    assert matched_event_timeline["mitre_count"] == 1
    assert (
        matched_event_mitre_entries[0]["timestamp"]
        == "2026-01-01T10:01:00Z"
    )
    assert (
        matched_event_mitre_entries[0]["technique_id"]
        == "T1110"
    )

    assert result["metadata"][
        "analytical_entries_are_not_raw_events"
    ]

    print(
        "Security Timeline Reconstructor "
        "self-test: PASSED"
    )
    print(
        f"Total timeline entries: "
        f"{result['summary']['entry_count']}"
    )
    print(
        f"Events: {result['event_count']}"
    )
    print(
        f"Correlations: "
        f"{result['correlation_count']}"
    )
    print(
        f"MITRE mappings: "
        f"{result['mitre_count']}"
    )
    print(
        f"Process relationships: "
        f"{result['process_relationship_count']}"
    )
    print(
        f"Attack-chain steps: "
        f"{result['attack_chain_step_count']}"
    )
    print(
        f"Time range: "
        f"{result['start_time']} -> "
        f"{result['end_time']}"
    )
