from dataclasses import dataclass, field
from typing import List, Optional, Set

from .investigation import InvestigationContext
from ..normalization import parse_event_timestamp


@dataclass
class InvestigationValidationResult:
    """
    Read-only validation result for an investigation.

    Validation never modifies the investigation.
    """

    valid: bool = True

    errors: List[str] = field(
        default_factory=list
    )

    warnings: List[str] = field(
        default_factory=list
    )

    findings_checked: int = 0
    evidence_checked: int = 0
    relationship_edges_checked: int = 0
    timeline_entries_checked: int = 0

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    def add_error(
        self,
        message: str,
    ) -> None:
        self.errors.append(
            str(message)
        )
        self.valid = False

    def add_warning(
        self,
        message: str,
    ) -> None:
        self.warnings.append(
            str(message)
        )

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "findings_checked": (
                self.findings_checked
            ),
            "evidence_checked": (
                self.evidence_checked
            ),
            "relationship_edges_checked": (
                self.relationship_edges_checked
            ),
            "timeline_entries_checked": (
                self.timeline_entries_checked
            ),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
        }


class InvestigationValidator:
    """
    Validate the internal integrity of a LogViewer investigation.

    This validator is intentionally read-only.

    It does not:
        - modify findings
        - modify evidence
        - modify relationships
        - modify the timeline
        - repair malformed data
        - assign threat scores
        - declare activity malicious

    It checks structural consistency and reports errors
    and warnings separately.
    """

    def validate(
        self,
        investigation: InvestigationContext,
    ) -> InvestigationValidationResult:
        result = InvestigationValidationResult()

        if not isinstance(
            investigation,
            InvestigationContext,
        ):
            result.add_error(
                "Investigation object has an invalid type."
            )
            return result

        self._validate_investigation(
            investigation,
            result,
        )

        timeline = self._safe_timeline(
            investigation,
            result,
        )

        self._validate_timeline(
            investigation,
            timeline,
            result,
        )

        result.valid = (
            result.error_count == 0
        )

        return result

    def _validate_investigation(
        self,
        investigation: InvestigationContext,
        result: InvestigationValidationResult,
    ) -> None:
        name = investigation.name

        if not isinstance(
            name,
            str,
        ):
            result.add_error(
                "Investigation name must be a string."
            )
        elif not name.strip():
            result.add_warning(
                "Investigation has an empty name."
            )

        if not isinstance(
            investigation.findings,
            list,
        ):
            result.add_error(
                "Investigation findings must be a list."
            )
            return

        if not isinstance(
            investigation.notes,
            list,
        ):
            result.add_error(
                "Investigation notes must be a list."
            )
        else:
            for index, note in enumerate(
                investigation.notes,
                start=1,
            ):
                if not isinstance(
                    note,
                    str,
                ):
                    result.add_error(
                        f"Analyst note {index} is not a string."
                    )
                elif not note.strip():
                    result.add_warning(
                        f"Analyst note {index} is empty."
                    )

        finding_identity: Set[tuple] = set()
        known_event_ids: Set[str] = set()

        for index, finding in enumerate(
            investigation.findings,
            start=1,
        ):
            result.findings_checked += 1

            self._validate_finding(
                finding,
                index,
                finding_identity,
                known_event_ids,
                result,
            )

    def _validate_finding(
        self,
        finding,
        index: int,
        finding_identity: Set[tuple],
        known_event_ids: Set[str],
        result: InvestigationValidationResult,
    ) -> None:
        if finding is None:
            result.add_error(
                f"Finding {index} is null."
            )
            return

        ioc_type = getattr(
            finding,
            "ioc_type",
            None,
        )

        value = getattr(
            finding,
            "value",
            None,
        )

        relationship = getattr(
            finding,
            "relationship",
            None,
        )

        if not isinstance(
            ioc_type,
            str,
        ) or not ioc_type.strip():
            result.add_error(
                f"Finding {index} has no valid IOC type."
            )

        if not isinstance(
            value,
            str,
        ) or not value.strip():
            result.add_error(
                f"Finding {index} has no valid IOC value."
            )

        if not isinstance(
            relationship,
            str,
        ) or not relationship.strip():
            result.add_error(
                f"Finding {index} has no valid relationship type."
            )

        identity = (
            str(ioc_type).lower(),
            str(value),
            str(relationship),
            getattr(
                finding,
                "first_seen",
                None,
            ),
            getattr(
                finding,
                "last_seen",
                None,
            ),
        )

        if identity in finding_identity:
            result.add_error(
                f"Finding {index} is a duplicate of another "
                "selected finding."
            )
        else:
            finding_identity.add(identity)

        self._validate_finding_timestamps(
            finding,
            index,
            result,
        )

        self._validate_evidence(
            finding,
            index,
            known_event_ids,
            result,
        )

        self._validate_relationships(
            finding,
            index,
            known_event_ids,
            result,
        )

    def _validate_finding_timestamps(
        self,
        finding,
        index: int,
        result: InvestigationValidationResult,
    ) -> None:
        for field_name in (
            "first_seen",
            "last_seen",
        ):
            value = getattr(
                finding,
                field_name,
                None,
            )

            if value is None:
                continue

            if not isinstance(
                value,
                str,
            ):
                result.add_error(
                    f"Finding {index} has a non-string "
                    f"{field_name} timestamp."
                )
                continue

            if not value.strip():
                result.add_warning(
                    f"Finding {index} has an empty "
                    f"{field_name} timestamp."
                )
                continue

            if parse_event_timestamp(value) is None:
                result.add_error(
                    f"Finding {index} has an invalid "
                    f"{field_name} timestamp: {value}"
                )

        first_seen = getattr(
            finding,
            "first_seen",
            None,
        )

        last_seen = getattr(
            finding,
            "last_seen",
            None,
        )

        if (
            first_seen
            and last_seen
            and parse_event_timestamp(first_seen)
            and parse_event_timestamp(last_seen)
        ):
            first_dt = parse_event_timestamp(
                first_seen
            )
            last_dt = parse_event_timestamp(
                last_seen
            )

            if first_dt > last_dt:
                result.add_error(
                    f"Finding {index} has first_seen "
                    "later than last_seen."
                )

        span = getattr(
            finding,
            "time_span_seconds",
            None,
        )

        if span is not None:
            if not isinstance(
                span,
                (int, float),
            ):
                result.add_error(
                    f"Finding {index} has an invalid "
                    "time_span_seconds value."
                )
            elif span < 0:
                result.add_error(
                    f"Finding {index} has a negative "
                    "time span."
                )

    def _validate_evidence(
        self,
        finding,
        finding_index: int,
        known_event_ids: Set[str],
        result: InvestigationValidationResult,
    ) -> None:
        evidence_items = getattr(
            finding,
            "evidence",
            None,
        )

        if evidence_items is None:
            result.add_warning(
                f"Finding {finding_index} has no evidence list."
            )
            return

        if not isinstance(
            evidence_items,
            list,
        ):
            result.add_error(
                f"Finding {finding_index} evidence "
                "must be a list."
            )
            return

        for evidence_index, evidence in enumerate(
            evidence_items,
            start=1,
        ):
            result.evidence_checked += 1

            if evidence is None:
                result.add_error(
                    f"Finding {finding_index}, evidence "
                    f"{evidence_index} is null."
                )
                continue

            evidence_type = getattr(
                evidence,
                "evidence_type",
                None,
            )

            value = getattr(
                evidence,
                "value",
                None,
            )

            if not isinstance(
                evidence_type,
                str,
            ) or not evidence_type.strip():
                result.add_error(
                    f"Finding {finding_index}, evidence "
                    f"{evidence_index} has no valid evidence type."
                )

            if not isinstance(
                value,
                str,
            ) or not value.strip():
                result.add_error(
                    f"Finding {finding_index}, evidence "
                    f"{evidence_index} has no valid value."
                )

            timestamp = getattr(
                evidence,
                "timestamp",
                None,
            )

            if timestamp:
                if not isinstance(
                    timestamp,
                    str,
                ):
                    result.add_error(
                        f"Finding {finding_index}, evidence "
                        f"{evidence_index} has a non-string timestamp."
                    )
                elif parse_event_timestamp(
                    timestamp
                ) is None:
                    result.add_error(
                        f"Finding {finding_index}, evidence "
                        f"{evidence_index} has an invalid timestamp: "
                        f"{timestamp}"
                    )

            event_id = getattr(
                evidence,
                "event_id",
                None,
            )

            if event_id:
                known_event_ids.add(
                    str(event_id)
                )
            else:
                result.add_warning(
                    f"Finding {finding_index}, evidence "
                    f"{evidence_index} has no event ID."
                )

            confidence = getattr(
                evidence,
                "confidence",
                None,
            )

            if confidence is not None:
                if not isinstance(
                    confidence,
                    (int, float),
                ):
                    result.add_error(
                        f"Finding {finding_index}, evidence "
                        f"{evidence_index} has invalid confidence."
                    )
                elif not (
                    0.0 <= float(confidence) <= 1.0
                ):
                    result.add_error(
                        f"Finding {finding_index}, evidence "
                        f"{evidence_index} has confidence outside "
                        "the valid range 0.0-1.0."
                    )

    def _validate_relationships(
        self,
        finding,
        finding_index: int,
        known_event_ids: Set[str],
        result: InvestigationValidationResult,
    ) -> None:
        edges = getattr(
            finding,
            "relationship_edges",
            None,
        )

        if edges is None:
            return

        if not isinstance(
            edges,
            list,
        ):
            result.add_error(
                f"Finding {finding_index} relationship_edges "
                "must be a list."
            )
            return

        for edge_index, edge in enumerate(
            edges,
            start=1,
        ):
            result.relationship_edges_checked += 1

            if edge is None:
                result.add_error(
                    f"Finding {finding_index}, relationship "
                    f"edge {edge_index} is null."
                )
                continue

            relationship_type = getattr(
                edge,
                "relationship_type",
                None,
            )

            if not isinstance(
                relationship_type,
                str,
            ) or not relationship_type.strip():
                result.add_error(
                    f"Finding {finding_index}, relationship "
                    f"edge {edge_index} has no relationship type."
                )

            source_event_id = getattr(
                edge,
                "source_event_id",
                None,
            )

            target_event_id = getattr(
                edge,
                "target_event_id",
                None,
            )

            if not source_event_id:
                result.add_warning(
                    f"Finding {finding_index}, relationship "
                    f"edge {edge_index} has no source event ID."
                )

            if not target_event_id:
                result.add_warning(
                    f"Finding {finding_index}, relationship "
                    f"edge {edge_index} has no target event ID."
                )

            if (
                source_event_id
                and target_event_id
                and str(source_event_id)
                == str(target_event_id)
            ):
                result.add_error(
                    f"Finding {finding_index}, relationship "
                    f"edge {edge_index} references the same event "
                    "as both source and target."
                )

            gap = getattr(
                edge,
                "time_gap_seconds",
                None,
            )

            if gap is not None:
                if not isinstance(
                    gap,
                    (int, float),
                ):
                    result.add_error(
                        f"Finding {finding_index}, relationship "
                        f"edge {edge_index} has an invalid time gap."
                    )
                elif gap < 0:
                    result.add_error(
                        f"Finding {finding_index}, relationship "
                        f"edge {edge_index} has a negative time gap."
                    )

    def _safe_timeline(
        self,
        investigation: InvestigationContext,
        result: InvestigationValidationResult,
    ):
        try:
            return investigation.timeline
        except Exception as exc:
            result.add_error(
                "Investigation timeline could not be reconstructed: "
                f"{exc}"
            )
            return []

    def _validate_timeline(
        self,
        investigation: InvestigationContext,
        timeline,
        result: InvestigationValidationResult,
    ) -> None:
        if timeline is None:
            result.add_error(
                "Investigation timeline is null."
            )
            return

        try:
            entries = list(timeline)
        except TypeError:
            result.add_error(
                "Investigation timeline is not iterable."
            )
            return

        known_event_ids = self._known_event_ids(
            investigation
        )

        timeline_event_ids: Set[str] = set()

        previous_timestamp = None

        for index, entry in enumerate(
            entries,
            start=1,
        ):
            result.timeline_entries_checked += 1

            if entry is None:
                result.add_error(
                    f"Timeline entry {index} is null."
                )
                continue

            event_id = getattr(
                entry,
                "event_id",
                None,
            )

            if not event_id:
                result.add_error(
                    f"Timeline entry {index} has no event ID."
                )
            else:
                event_id = str(event_id)

                if event_id in timeline_event_ids:
                    result.add_error(
                        f"Timeline entry {index} duplicates "
                        f"event ID: {event_id}"
                    )

                timeline_event_ids.add(
                    event_id
                )

                if (
                    known_event_ids
                    and event_id not in known_event_ids
                ):
                    result.add_warning(
                        f"Timeline entry {index} references "
                        f"an event ID not present in evidence: "
                        f"{event_id}"
                    )

            source = getattr(
                entry,
                "source",
                None,
            )

            if not source:
                result.add_warning(
                    f"Timeline entry {index} has no source."
                )

            timestamp = getattr(
                entry,
                "timestamp",
                None,
            )

            parsed_timestamp = None

            if timestamp:
                parsed_timestamp = (
                    parse_event_timestamp(
                        timestamp
                    )
                )

                if parsed_timestamp is None:
                    result.add_error(
                        f"Timeline entry {index} has an invalid "
                        f"timestamp: {timestamp}"
                    )
            else:
                result.add_warning(
                    f"Timeline entry {index} has no timestamp."
                )

            if (
                previous_timestamp is not None
                and parsed_timestamp is not None
                and parsed_timestamp < previous_timestamp
            ):
                result.add_error(
                    f"Timeline entry {index} is out of chronological order."
                )

            if parsed_timestamp is not None:
                previous_timestamp = parsed_timestamp

            gap = getattr(
                entry,
                "gap_from_previous_seconds",
                None,
            )

            if gap is not None:
                if not isinstance(
                    gap,
                    (int, float),
                ):
                    result.add_error(
                        f"Timeline entry {index} has an invalid "
                        "gap_from_previous_seconds value."
                    )
                elif gap < 0:
                    result.add_error(
                        f"Timeline entry {index} has a negative "
                        "gap_from_previous_seconds value."
                    )

            related_event_ids = getattr(
                entry,
                "related_event_ids",
                None,
            )

            if related_event_ids is not None:
                if not isinstance(
                    related_event_ids,
                    list,
                ):
                    result.add_error(
                        f"Timeline entry {index} related_event_ids "
                        "must be a list."
                    )

        if (
            entries
            and len(entries)
            != len(timeline_event_ids)
        ):
            result.add_error(
                "Timeline contains entries with duplicate or "
                "missing event IDs."
            )

    @staticmethod
    def _known_event_ids(
        investigation: InvestigationContext,
    ) -> Set[str]:
        event_ids: Set[str] = set()

        for finding in investigation.findings:
            for evidence in (
                getattr(
                    finding,
                    "evidence",
                    None,
                )
                or []
            ):
                event_id = getattr(
                    evidence,
                    "event_id",
                    None,
                )

                if event_id:
                    event_ids.add(
                        str(event_id)
                    )

        return event_ids

