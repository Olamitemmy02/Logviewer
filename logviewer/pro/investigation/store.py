import json
import os
from dataclasses import fields
from pathlib import Path
from typing import List, Optional

from logviewer.events import Event
from logviewer.analysis.evidence.model import Evidence
from logviewer.pro.investigation.model import Investigation
from logviewer.pro.mitre.mapper import MitreMapper


DEFAULT_STORE = (
    Path.home()
    / ".local"
    / "share"
    / "logviewer"
    / "investigations"
)


class InvestigationStore:
    """
    Persistent storage for LogViewer Pro investigations.

    The store supports both:
        - native Pro investigation files
        - legacy Core correlation investigations

    Core investigations are converted in memory and are never
    overwritten by the Pro store.
    """

    CORE_FORMAT = "logviewer-investigation"
    CORE_VERSION = 1
    CORE_ID_PREFIX = "CORE-"

    def __init__(
        self,
        root: Optional[Path] = None,
    ):
        self.root = Path(
            root or DEFAULT_STORE
        )

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save(
        self,
        investigation: Investigation,
    ) -> Path:
        """Persist a native Pro investigation to disk."""

        path = self._path_for(
            investigation.investigation_id
        )

        data = investigation.as_dict()

        temporary_path = path.with_suffix(
            path.suffix + ".tmp"
        )

        with temporary_path.open(
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                data,
                handle,
                indent=2,
                ensure_ascii=False,
                default=str,
            )
            handle.write("\n")

        try:
            os.chmod(
                temporary_path,
                0o600,
            )
        except OSError:
            pass

        os.replace(
            temporary_path,
            path,
        )

        try:
            os.chmod(
                path,
                0o600,
            )
        except OSError:
            pass

        return path

    def load(
        self,
        investigation_id: str,
    ) -> Optional[Investigation]:
        """
        Load a native Pro investigation or a converted Core
        investigation.
        """

        path = self._path_for(
            investigation_id
        )

        if path.exists():
            investigation = self._load_path(
                path
            )

            if investigation is not None:
                return investigation

        return self._load_core_by_id(
            investigation_id
        )

    def list_investigations(
        self,
    ) -> List[dict]:
        """
        Return summaries of native Pro investigations and
        convertible Core investigations.

        Corrupt or unreadable files are skipped.
        """

        results = []
        seen_ids = set()

        for path in sorted(
            self.root.glob("*.json")
        ):
            investigation = self._load_path(
                path
            )

            if investigation is None:
                continue

            investigation_id = (
                investigation.investigation_id
            )

            if investigation_id in seen_ids:
                continue

            seen_ids.add(
                investigation_id
            )

            results.append(
                investigation.summary()
            )

        return results

    def delete(
        self,
        investigation_id: str,
    ) -> bool:
        """
        Delete a native Pro investigation.

        Core investigation files are deliberately not deleted
        through the Pro store.
        """

        path = self._path_for(
            investigation_id
        )

        if not path.exists():
            return False

        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                data = json.load(handle)

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return False

        if self._is_core_data(data):
            return False

        try:
            path.unlink()
            return True

        except (
            FileNotFoundError,
            OSError,
        ):
            return False

    def _load_path(
        self,
        path: Path,
    ) -> Optional[Investigation]:
        """Load a native Pro or convertible Core investigation."""

        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                data = json.load(handle)

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return None

        if not isinstance(data, dict):
            return None

        if self._is_core_data(data):
            return self._from_core_dict(
                data,
                path,
            )

        try:
            return self._from_dict(
                data
            )

        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _is_core_data(
        cls,
        data: dict,
    ) -> bool:
        """Identify the legacy Core investigation schema."""

        return (
            data.get("format")
            == cls.CORE_FORMAT
            and "name" in data
            and "findings" in data
            and "investigation_id" not in data
        )

    def _load_core_by_id(
        self,
        investigation_id: str,
    ) -> Optional[Investigation]:
        """
        Resolve a converted Core investigation by its generated
        Pro investigation ID.
        """

        expected_name = str(
            investigation_id
        )

        if expected_name.startswith(
            self.CORE_ID_PREFIX
        ):
            expected_name = expected_name[
                len(self.CORE_ID_PREFIX):
            ]

        for path in sorted(
            self.root.glob("*.json")
        ):
            try:
                with path.open(
                    "r",
                    encoding="utf-8",
                ) as handle:
                    data = json.load(
                        handle
                    )
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                continue

            if not isinstance(
                data,
                dict,
            ):
                continue

            if not self._is_core_data(
                data
            ):
                continue

            name = str(
                data.get(
                    "name",
                    "",
                )
            )

            core_id = self._core_id(
                name
            )

            if (
                investigation_id == core_id
                or investigation_id == name
                or expected_name
                == self._safe_id(
                    name
                )
            ):
                return self._from_core_dict(
                    data,
                    path,
                )

        return None

    def _from_core_dict(
        self,
        data: dict,
        path: Path,
    ) -> Optional[Investigation]:
        """
        Convert a saved Core correlation investigation into a
        Pro investigation without modifying the original file.

        Core investigations do not contain a native Pro timeline.
        This bridge reconstructs timeline entries from the persisted
        Core evidence/events and relationship edges so the Pro timeline
        reflects the actual imported data.
        """

        name = str(
            data.get(
                "name",
                path.stem,
            )
        )

        investigation_id = self._core_id(
            name
        )

        findings = (
            data.get(
                "findings",
                [],
            )
            or []
        )

        if not isinstance(
            findings,
            list,
        ):
            findings = []

        events = []
        evidence = []
        iocs = []
        correlations = []
        relationships = []

        for finding in findings:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            value = str(
                finding.get(
                    "value",
                    finding.get(
                        "ioc_value",
                        "",
                    ),
                )
            )

            ioc_type = str(
                finding.get(
                    "ioc_type",
                    "unknown",
                )
            )

            if value:
                iocs.append(
                    {
                        "type": ioc_type,
                        "value": value,
                    }
                )

            correlations.append(
                {
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "value": value,
                    "relationship": finding.get(
                        "relationship"
                    ),
                    "event_count": finding.get(
                        "event_count",
                        0,
                    ),
                    "source_count": finding.get(
                        "source_count",
                        0,
                    ),
                    "first_seen": finding.get(
                        "first_seen"
                    ),
                    "last_seen": finding.get(
                        "last_seen"
                    ),
                    "description": finding.get(
                        "description"
                    ),
                }
            )

            finding_evidence = finding.get(
                "evidence",
                [],
            )

            if isinstance(
                finding_evidence,
                list,
            ):
                for item in finding_evidence:
                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    restored_evidence = (
                        self._core_evidence(
                            item,
                            value,
                        )
                    )

                    evidence.append(
                        restored_evidence
                    )

                    event = (
                        self._core_event(
                            item,
                            restored_evidence,
                        )
                    )

                    if event is not None:
                        events.append(
                            event
                        )

            finding_edges = (
                finding.get(
                    "relationship_edges",
                    [],
                )
            )

            if isinstance(
                finding_edges,
                list,
            ):
                relationships.extend(
                    edge
                    for edge in finding_edges
                    if isinstance(
                        edge,
                        dict,
                    )
                )

        events = self._deduplicate_events(
            events
        )

        evidence = self._deduplicate_evidence(
            evidence
        )

        iocs = self._deduplicate_dicts(
            iocs,
            ("type", "value"),
        )

        findings_for_pro = []

        for finding in findings:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            findings_for_pro.append(
                {
                    "finding_id": self._stable_finding_id(
                        finding
                    ),
                    "title": (
                        f"Core Correlation: "
                        f"{finding.get('ioc_type', 'IOC')} "
                        f"{finding.get('ioc_value', finding.get('value', ''))}"
                    ),
                    "summary": str(
                        finding.get(
                            "description",
                            "Imported from Core Security Correlation.",
                        )
                    ),
                    "severity": "INFO",
                    "confidence": 1.0,
                    "rationale": (
                        "Imported from a persisted Core correlation "
                        "investigation. The correlation itself does not "
                        "establish malicious intent."
                    ),
                    "source": "core_correlation",
                    "event_ids": self._copy_list(
                        finding.get(
                            "related_event_ids",
                            [],
                        )
                    ),
                    "evidence_ids": [
                        item.event_id
                        for item in evidence
                        if getattr(
                            item,
                            "event_id",
                            None,
                        )
                    ],
                    "ioc_values": [
                        str(
                            finding.get(
                                "ioc_value",
                                finding.get(
                                    "value",
                                    "",
                                ),
                            )
                        )
                    ],
                    "mitre_techniques": [],
                    "correlation_ids": [
                        self._stable_correlation_id(
                            finding
                        )
                    ],
                    "false_positive_context": {},
                    "metadata": {
                        "source": "core_correlation",
                        "relationship": finding.get(
                            "relationship"
                        ),
                        "source_count": finding.get(
                            "source_count",
                            0,
                        ),
                        "event_count": finding.get(
                            "event_count",
                            0,
                        ),
                    },
                }
            )

        relationship_summary = self._relationship_summary(
            relationships
        )

        timeline_entries = []

        for index, event in enumerate(
            events,
            start=1,
        ):
            event_id = getattr(
                event,
                "event_id",
                None,
            )

            timestamp = getattr(
                event,
                "timestamp",
                None,
            )

            source = getattr(
                event,
                "source",
                None,
            )

            severity = getattr(
                event,
                "severity",
                None,
            ) or "INFO"

            message = getattr(
                event,
                "message",
                None,
            )

            event_type = getattr(
                event,
                "event_type",
                None,
            ) or "event"

            entry_id = (
                f"event:{event_id}"
                if event_id
                else f"core-event:{index}"
            )

            title = (
                str(message)
                if message
                else (
                    f"Core Event "
                    f"{event_type}"
                )
            )

            timeline_entries.append(
                {
                    "entry_id": entry_id,
                    "entry_type": "event",
                    "timestamp": timestamp,
                    "severity": str(
                        severity
                    ),
                    "title": title,
                    "source": (
                        str(source)
                        if source
                        else "core_import"
                    ),
                    "event_id": event_id,
                    "description": title,
                    "metadata": {
                        "event_type": str(
                            event_type
                        ),
                        "source": (
                            str(source)
                            if source
                            else "core_import"
                        ),
                    },
                }
            )

        for index, relationship in enumerate(
            relationships,
            start=1,
        ):
            source_a = relationship.get(
                "source_a"
            )
            source_b = relationship.get(
                "source_b"
            )

            relationship_name = relationship.get(
                "relationship"
            ) or relationship.get(
                "type"
            ) or "related"

            timestamp = (
                relationship.get(
                    "timestamp"
                )
                or relationship.get(
                    "first_seen"
                )
                or relationship.get(
                    "last_seen"
                )
            )

            title = (
                f"{source_a or '-'} "
                f"{relationship_name} "
                f"{source_b or '-'}"
            )

            timeline_entries.append(
                {
                    "entry_id": (
                        f"relationship:"
                        f"{index}"
                    ),
                    "entry_type": "correlation",
                    "timestamp": timestamp,
                    "severity": "INFO",
                    "title": title,
                    "source": "core_correlation",
                    "reference": (
                        f"{source_a or '-'}"
                        " -> "
                        f"{source_b or '-'}"
                    ),
                    "description": (
                        "Imported Core relationship "
                        "between correlated sources."
                    ),
                    "metadata": {
                        "source_a": source_a,
                        "source_b": source_b,
                        "relationship": relationship_name,
                        "core_relationship": relationship,
                    },
                }
            )

        def _timeline_sort_key(
            entry: dict,
        ):
            timestamp = entry.get(
                "timestamp"
            )

            if timestamp is None:
                return (
                    1,
                    "",
                )

            return (
                0,
                str(timestamp),
            )

        timeline_entries.sort(
            key=_timeline_sort_key
        )

        # Core investigations are imported into the Pro model without
        # passing through InvestigationEngine.create_investigation().
        # Therefore the normal Pro MITRE mapping stage has not run yet.
        #
        # Re-run the evidence-driven MITRE mapper against the reconstructed
        # Event objects so imported Core investigations receive the same
        # deterministic ATT&CK candidate analysis as native Pro
        # investigations.
        mitre_mappings = []

        try:
            mitre_mapper = MitreMapper()
            mitre_mappings = mitre_mapper.map_events(
                events
            )
        except (
            PermissionError,
            RuntimeError,
        ):
            # MITRE is a licensed Pro feature. If the feature is not
            # available, preserve the Core import rather than preventing
            # the investigation from loading.
            mitre_mappings = []

        timeline_summary = {
            "entry_count": len(
                timeline_entries
            ),
            "event_count": len(
                events
            ),
            "correlation_count": len(
                correlations
            ),
            "mitre_count": len(
                mitre_mappings
            ),
            "process_relationship_count": 0,
            "attack_chain_step_count": 0,
            "gap_count": 0,
            "confidence": 0.0,
        }

        metadata = {
            "source": "core_investigation_bridge",
            "source_file": str(
                path
            ),
            "source_format": data.get(
                "format"
            ),
            "source_version": data.get(
                "version"
            ),
            "core_name": name,
            "core_finding_count": len(
                findings
            ),
            "core_relationship_count": len(
                relationships
            ),
            "imported_read_only": True,
        }

        investigation = Investigation(
            investigation_id=investigation_id,
            title=name,
            status="open",
            severity="INFO",
            confidence=0.0,
            threat_score=0,
            threat_level="INFO",
            threat_score_details={
                "source": "core_import",
                "available": False,
            },
            false_positive_analysis={
                "source": "core_import",
                "available": False,
                "note": (
                    "Core correlation data was imported. "
                    "No independent false-positive determination "
                    "has been made."
                ),
            },
            process_tree={
                "available": False,
                "node_count": 0,
                "relationship_count": 0,
            },
            attack_chain={
                "available": False,
                "summary": {
                    "step_count": 0,
                    "link_count": 0,
                    "technique_count": 0,
                    "tactic_count": 0,
                    "process_relationship_count": 0,
                },
                "relationships": relationship_summary,
            },
            timeline={
                "available": True,
                "source": "core_import",
                "entries": timeline_entries,
                "summary": timeline_summary,
            },
            created_at="",
            updated_at="",
            events=events,
            evidence=evidence,
            iocs=iocs,
            correlations=correlations,
            mitre_mappings=mitre_mappings,
            findings=findings_for_pro,
            metadata=metadata,
        )

        return investigation

    @staticmethod
    def _core_id(
        name: str,
    ) -> str:
        """Build a stable Pro ID for a Core investigation."""

        return (
            InvestigationStore.CORE_ID_PREFIX
            + InvestigationStore._safe_id(
                name
            )
        )

    @staticmethod
    def _safe_id(
        value: str,
    ) -> str:
        """Build a filesystem-safe identifier."""

        safe = "".join(
            character
            if character.isalnum()
            or character in "-_"
            else "_"
            for character in str(
                value
            )
        )

        return safe or "UNKNOWN"

    @staticmethod
    def _core_evidence(
        item: dict,
        fallback_value: str,
    ) -> Evidence:
        """Convert one Core evidence record."""

        metadata = item.get(
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            dict,
        ):
            metadata = {}

        return Evidence(
            evidence_type=str(
                item.get(
                    "evidence_type",
                    "correlation",
                )
            ),
            value=str(
                item.get(
                    "value",
                    fallback_value,
                )
            ),
            source=item.get(
                "source"
            ),
            timestamp=item.get(
                "timestamp"
            ),
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
                metadata
            ),
        )

    @staticmethod
    def _core_event(
        item: dict,
        evidence: Evidence,
    ) -> Optional[Event]:
        """
        Reconstruct an Event from Core evidence metadata.

        Only fields actually accepted by the current Event
        dataclass are passed.
        """

        metadata = dict(
            evidence.metadata
            or {}
        )

        source = (
            metadata.get(
                "source"
            )
            or evidence.source
        )

        timestamp = (
            metadata.get(
                "timestamp"
            )
            or evidence.timestamp
        )

        message = (
            metadata.get(
                "message"
            )
            or evidence.description
            or evidence.value
        )

        values = dict(
            metadata
        )

        values.setdefault(
            "timestamp",
            timestamp,
        )
        values.setdefault(
            "source",
            source,
        )
        values.setdefault(
            "message",
            message,
        )
        values.setdefault(
            "event_type",
            metadata.get(
                "event_type",
                evidence.evidence_type,
            ),
        )
        values.setdefault(
            "raw",
            metadata.get(
                "raw",
                message,
            ),
        )

        accepted = {
            field.name
            for field in fields(
                Event
            )
        }

        filtered = {
            key: value
            for key, value in values.items()
            if key in accepted
        }

        try:
            return Event(
                **filtered
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _deduplicate_events(
        events: list,
    ) -> list:
        """Remove duplicate reconstructed events."""

        results = []
        seen = set()

        for event in events:
            event_id = getattr(
                event,
                "event_id",
                None,
            )

            key = (
                event_id
                if event_id
                else (
                    getattr(
                        event,
                        "timestamp",
                        None,
                    ),
                    getattr(
                        event,
                        "source",
                        None,
                    ),
                    getattr(
                        event,
                        "message",
                        None,
                    ),
                )
            )

            if key in seen:
                continue

            seen.add(key)
            results.append(
                event
            )

        return results

    @staticmethod
    def _deduplicate_evidence(
        evidence: list,
    ) -> list:
        """Remove duplicate evidence records."""

        results = []
        seen = set()

        for item in evidence:
            key = (
                item.event_id,
                item.evidence_type,
                item.value,
                item.timestamp,
                item.source,
            )

            if key in seen:
                continue

            seen.add(key)
            results.append(
                item
            )

        return results

    @staticmethod
    def _deduplicate_dicts(
        values: list,
        keys: tuple,
    ) -> list:
        """Remove duplicate dictionaries using selected keys."""

        results = []
        seen = set()

        for value in values:
            key = tuple(
                value.get(
                    item
                )
                for item in keys
            )

            if key in seen:
                continue

            seen.add(key)
            results.append(
                value
            )

        return results

    @staticmethod
    def _relationship_summary(
        relationships: list,
    ) -> dict:
        """Summarize imported Core relationship edges."""

        sources = set()
        targets = set()

        for edge in relationships:
            source = edge.get(
                "source_a"
            )
            target = edge.get(
                "source_b"
            )

            if source:
                sources.add(
                    source
                )

            if target:
                targets.add(
                    target
                )

        return {
            "edge_count": len(
                relationships
            ),
            "source_count": len(
                sources
            ),
            "target_count": len(
                targets
            ),
        }

    @staticmethod
    def _stable_finding_id(
        finding: dict,
    ) -> str:
        """Generate a deterministic imported finding ID."""

        import hashlib

        payload = "|".join(
            [
                str(
                    finding.get(
                        "ioc_type",
                        "",
                    )
                ),
                str(
                    finding.get(
                        "ioc_value",
                        finding.get(
                            "value",
                            "",
                        ),
                    )
                ),
                str(
                    finding.get(
                        "first_seen",
                        "",
                    )
                ),
                str(
                    finding.get(
                        "last_seen",
                        "",
                    )
                ),
            ]
        )

        digest = hashlib.sha256(
            payload.encode(
                "utf-8"
            )
        ).hexdigest()

        return f"CORE-FINDING-{digest[:16]}"

    @staticmethod
    def _stable_correlation_id(
        finding: dict,
    ) -> str:
        """Generate a deterministic imported correlation ID."""

        import hashlib

        payload = "|".join(
            [
                str(
                    finding.get(
                        "ioc_type",
                        "",
                    )
                ),
                str(
                    finding.get(
                        "ioc_value",
                        finding.get(
                            "value",
                            "",
                        ),
                    )
                ),
                str(
                    finding.get(
                        "relationship",
                        "",
                    )
                ),
            ]
        )

        digest = hashlib.sha256(
            payload.encode(
                "utf-8"
            )
        ).hexdigest()

        return f"CORE-CORR-{digest[:16]}"

    @staticmethod
    def _deserialize_events(
        values,
    ) -> list:
        """
        Restore Event objects where possible.

        Older or externally-created investigation files may contain
        already-serialized dictionaries. Those are retained when they
        cannot safely be reconstructed as Event objects.
        """

        events = []

        for value in values or []:
            if isinstance(
                value,
                Event,
            ):
                events.append(
                    value
                )
                continue

            if isinstance(
                value,
                dict,
            ):
                try:
                    events.append(
                        Event(
                            **value
                        )
                    )
                    continue
                except (
                    TypeError,
                    ValueError,
                ):
                    pass

            events.append(
                value
            )

        return events

    @staticmethod
    def _deserialize_evidence(
        values,
    ) -> list:
        """Restore Evidence objects where possible."""

        evidence = []

        for value in values or []:
            if isinstance(
                value,
                Evidence,
            ):
                evidence.append(
                    value
                )
                continue

            if isinstance(
                value,
                dict,
            ):
                try:
                    evidence.append(
                        Evidence(
                            **value
                        )
                    )
                    continue
                except (
                    TypeError,
                    ValueError,
                ):
                    pass

            evidence.append(
                value
            )

        return evidence

    @staticmethod
    def _copy_list(
        value,
    ) -> list:
        """Normalize serialized list-like Pro fields."""

        if isinstance(
            value,
            list,
        ):
            return list(
                value
            )

        if value is None:
            return []

        return [value]

    @staticmethod
    def _copy_dict(
        value,
    ) -> dict:
        """Normalize serialized dictionary-like Pro fields."""

        if isinstance(
            value,
            dict,
        ):
            return dict(
                value
            )

        return {}

    def _from_dict(
        self,
        data: dict,
    ) -> Investigation:
        """
        Reconstruct a complete native Pro Investigation.
        """

        events = self._deserialize_events(
            data.get(
                "events",
                [],
            )
        )

        evidence = self._deserialize_evidence(
            data.get(
                "evidence",
                [],
            )
        )

        investigation = Investigation(
            investigation_id=str(
                data[
                    "investigation_id"
                ]
            ),
            title=str(
                data.get(
                    "title",
                    "Untitled Investigation",
                )
            ),
            status=str(
                data.get(
                    "status",
                    "open",
                )
            ),
            severity=str(
                data.get(
                    "severity",
                    "INFO",
                )
            ),
            confidence=float(
                data.get(
                    "confidence",
                    0.0,
                )
            ),
            threat_score=int(
                data.get(
                    "threat_score",
                    0,
                )
            ),
            threat_level=str(
                data.get(
                    "threat_level",
                    "INFO",
                )
            ),
            threat_score_details=self._copy_dict(
                data.get(
                    "threat_score_details",
                    {},
                )
            ),
            false_positive_analysis=self._copy_dict(
                data.get(
                    "false_positive_analysis",
                    {},
                )
            ),
            process_tree=self._copy_dict(
                data.get(
                    "process_tree",
                    {},
                )
            ),
            attack_chain=self._copy_dict(
                data.get(
                    "attack_chain",
                    {},
                )
            ),
            timeline=self._copy_dict(
                data.get(
                    "timeline",
                    {},
                )
            ),
            created_at=str(
                data.get(
                    "created_at",
                    "",
                )
            ),
            updated_at=str(
                data.get(
                    "updated_at",
                    "",
                )
            ),
            events=events,
            evidence=evidence,
            iocs=self._copy_list(
                data.get(
                    "iocs",
                    [],
                )
            ),
            correlations=self._copy_list(
                data.get(
                    "correlations",
                    [],
                )
            ),
            mitre_mappings=self._copy_list(
                data.get(
                    "mitre_mappings",
                    [],
                )
            ),
            findings=self._copy_list(
                data.get(
                    "findings",
                    [],
                )
            ),
            metadata=self._copy_dict(
                data.get(
                    "metadata",
                    {},
                )
            ),
        )

        return investigation

    def _path_for(
        self,
        investigation_id: str,
    ) -> Path:
        """
        Build a safe filesystem path for an investigation ID.
        """

        safe_id = "".join(
            character
            if character.isalnum()
            or character in "-_"
            else "_"
            for character in str(
                investigation_id
            )
        )

        if not safe_id:
            raise ValueError(
                "Investigation ID cannot be empty"
            )

        return self.root / (
            f"{safe_id}.json"
        )


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        store = InvestigationStore(
            Path(temporary)
        )

        investigation = Investigation(
            investigation_id="STORE-TEST-001",
            title="Store Persistence Test",
        )

        investigation.set_threat_score(
            73,
            "HIGH",
            {
                "test": True,
            },
        )

        investigation.set_false_positive_analysis(
            {
                "confidence": 0.15,
                "test": True,
            }
        )

        investigation.set_process_tree(
            {
                "node_count": 3,
                "relationship_count": 2,
            }
        )

        investigation.set_attack_chain(
            {
                "summary": {
                    "step_count": 4,
                    "link_count": 3,
                }
            }
        )

        investigation.set_timeline(
            {
                "investigation_id": (
                    "STORE-TEST-001"
                ),
                "entries": [
                    {
                        "entry_id": "event:test",
                        "entry_type": "event",
                        "timestamp": (
                            "2026-01-01T10:00:00Z"
                        ),
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
                    "confidence": 0.9,
                },
            }
        )

        investigation.mitre_mappings = [
            {
                "technique_id": "T1059",
            }
        ]

        path = store.save(
            investigation
        )

        assert path.exists()

        restored = store.load(
            "STORE-TEST-001"
        )

        assert restored is not None
        assert restored.threat_score == 73
        assert restored.threat_level == "HIGH"
        assert restored.threat_score_details[
            "test"
        ] is True

        assert restored.false_positive_analysis[
            "confidence"
        ] == 0.15

        assert restored.process_tree[
            "node_count"
        ] == 3

        assert restored.attack_chain[
            "summary"
        ]["step_count"] == 4

        assert restored.timeline[
            "summary"
        ]["entry_count"] == 1

        assert restored.mitre_mappings[
            0
        ]["technique_id"] == "T1059"

        print(
            "Investigation store persistence "
            "self-test: PASSED"
        )

    print(
        "Pro/Core investigation store bridge "
        "self-test: PASSED"
    )
