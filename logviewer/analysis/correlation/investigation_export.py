
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from .investigation import InvestigationContext


class InvestigationExporter:
    """
    Export a LogViewer investigation into analyst-friendly formats.

    Supported formats:
        - JSON
        - CSV
        - TXT

    Exports include selected findings, evidence, relationship edges,
    and the timeline derived from those findings.

    Exporting does not modify the investigation.
    """

    FORMAT_NAME = "logviewer-investigation-export"
    FORMAT_VERSION = 2

    CSV_FIELDS = [
        "record_type",
        "investigation",
        "ioc_type",
        "ioc_value",
        "relationship",
        "description",
        "event_count",
        "source_count",
        "sources",
        "event_types",
        "first_seen",
        "last_seen",
        "time_span_seconds",
        "closest_cross_source_gap_seconds",
        "relationship_edge_count",
        "relationship_type",
        "relationship_source_event_id",
        "relationship_target_event_id",
        "relationship_source",
        "relationship_target",
        "relationship_time_gap_seconds",
        "relationship_description",
        "timeline_event_id",
        "timeline_timestamp",
        "timeline_source",
        "timeline_event_type",
        "timeline_ioc_type",
        "timeline_ioc_value",
        "timeline_relationship_types",
        "timeline_related_event_ids",
        "timeline_previous_event_id",
        "timeline_gap_from_previous_seconds",
        "evidence_type",
        "evidence_value",
        "evidence_source",
        "evidence_timestamp",
        "evidence_confidence",
        "event_id",
        "severity",
        "host",
        "user",
        "process",
        "pid",
        "parent_pid",
        "command",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "domain",
        "url",
        "file_path",
        "hash_value",
        "signature",
        "gid",
        "sid",
        "revision",
        "priority",
        "action",
        "message",
        "analyst_note",
    ]

    def __init__(self, directory: str = "."):
        self.directory = Path(
            directory
        ).expanduser()

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def export_json(
        self,
        investigation: InvestigationContext,
        filename: str = "investigation.json",
    ) -> Path:
        """Export findings, evidence, relationships, and timeline as JSON."""

        path = self.directory / self._safe_filename(
            filename
        )

        timeline = investigation.timeline

        payload = {
            "format": self.FORMAT_NAME,
            "version": self.FORMAT_VERSION,
            "name": investigation.name,
            "summary": investigation.summary(),
            "notes": list(investigation.notes),
            "findings": [
                finding.as_dict()
                for finding in investigation.findings
            ],
            "relationship_edges": [
                edge.as_dict()
                for finding in investigation.findings
                for edge in (
                    finding.relationship_edges or []
                )
            ],
            "timeline": timeline.as_dict(),
        }

        path.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                default=self._json_default,
            ),
            encoding="utf-8",
        )

        return path

    def export_csv(
        self,
        investigation: InvestigationContext,
        filename: str = "investigation.csv",
    ) -> Path:
        """
        Export an investigation as a flat CSV.

        Rows use record_type to distinguish:
            - evidence records
            - relationship records
            - timeline records
            - analyst notes

        Finding-level fields are repeated where useful for context.
        """

        path = self.directory / self._safe_filename(
            filename
        )

        timeline = investigation.timeline

        with path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=self.CSV_FIELDS,
                extrasaction="ignore",
            )
            writer.writeheader()

            for finding in investigation.findings:
                base = self._finding_row(
                    investigation,
                    finding,
                )

                evidence_items = (
                    finding.evidence or [None]
                )

                for evidence in evidence_items:
                    row = dict(base)
                    row["record_type"] = "evidence"

                    if evidence is not None:
                        metadata = (
                            evidence.metadata or {}
                        )

                        row.update({
                            "evidence_type": (
                                evidence.evidence_type
                            ),
                            "evidence_value": evidence.value,
                            "evidence_source": (
                                evidence.source or ""
                            ),
                            "evidence_timestamp": (
                                evidence.timestamp or ""
                            ),
                            "evidence_confidence": (
                                evidence.confidence
                            ),
                            "event_id": (
                                evidence.event_id or ""
                            ),
                        })

                        for key in (
                            "severity",
                            "host",
                            "user",
                            "process",
                            "pid",
                            "parent_pid",
                            "command",
                            "protocol",
                            "src_ip",
                            "src_port",
                            "dst_ip",
                            "dst_port",
                            "domain",
                            "url",
                            "file_path",
                            "hash_value",
                            "signature",
                            "gid",
                            "sid",
                            "revision",
                            "priority",
                            "action",
                            "message",
                        ):
                            row[key] = metadata.get(
                                key,
                                "",
                            )

                    writer.writerow(row)

                for edge in (
                    finding.relationship_edges or []
                ):
                    row = dict(base)
                    row["record_type"] = "relationship"
                    row.update({
                        "relationship_type": (
                            edge.relationship_type
                        ),
                        "relationship_source_event_id": (
                            edge.source_event_id or ""
                        ),
                        "relationship_target_event_id": (
                            edge.target_event_id or ""
                        ),
                        "relationship_source": (
                            edge.source or ""
                        ),
                        "relationship_target": (
                            edge.target or ""
                        ),
                        "relationship_time_gap_seconds": (
                            edge.time_gap_seconds
                            if edge.time_gap_seconds is not None
                            else ""
                        ),
                        "relationship_description": (
                            edge.description or ""
                        ),
                    })
                    writer.writerow(row)

            for entry in timeline:
                writer.writerow({
                    "record_type": "timeline",
                    "investigation": investigation.name,
                    "timeline_event_id": entry.event_id,
                    "timeline_timestamp": entry.timestamp,
                    "timeline_source": entry.source,
                    "timeline_event_type": (
                        entry.event_type or ""
                    ),
                    "timeline_ioc_type": entry.ioc_type,
                    "timeline_ioc_value": entry.ioc_value,
                    "timeline_relationship_types": (
                        self._join_values(
                            entry.relationship_types
                        )
                    ),
                    "timeline_related_event_ids": (
                        self._join_values(
                            entry.related_event_ids
                        )
                    ),
                    "timeline_previous_event_id": (
                        entry.previous_event_id or ""
                    ),
                    "timeline_gap_from_previous_seconds": (
                        entry.gap_from_previous_seconds
                        if entry.gap_from_previous_seconds is not None
                        else ""
                    ),
                    "description": entry.description or "",
                })

            for index, note in enumerate(
                investigation.notes,
                start=1,
            ):
                writer.writerow({
                    "record_type": "analyst_note",
                    "investigation": investigation.name,
                    "analyst_note": note,
                    "description": f"Note {index}",
                })

        return path

    def export_txt(
        self,
        investigation: InvestigationContext,
        filename: str = "investigation.txt",
    ) -> Path:
        """Export a readable investigation report."""

        path = self.directory / self._safe_filename(
            filename
        )

        lines: List[str] = []

        summary = investigation.summary()
        timeline = investigation.timeline

        lines.extend([
            "LOGVIEWER INVESTIGATION REPORT",
            "=" * 34,
            "",
            f"Investigation: {investigation.name}",
            "",
            "SUMMARY",
            "-" * 34,
            f"Findings: {summary.get('findings', 0)}",
            f"Evidence: {summary.get('evidence', 0)}",
            f"Events: {summary.get('events', 0)}",
            f"IOCs: {summary.get('iocs', 0)}",
            f"Sources: {summary.get('sources', 0)}",
            f"Notes: {summary.get('notes', 0)}",
            f"Relationship edges: "
            f"{investigation.relationship_edge_count}",
            f"Timeline entries: {len(timeline)}",
            "",
        ])

        relationship_counts = (
            investigation.relationship_counts()
        )

        if relationship_counts:
            lines.extend([
                "RELATIONSHIPS",
                "-" * 34,
            ])

            for relationship, count in sorted(
                relationship_counts.items()
            ):
                lines.append(
                    f"{relationship}: {count}"
                )

            lines.append("")

        lines.extend([
            "FINDINGS",
            "-" * 34,
        ])

        if not investigation.findings:
            lines.append("No findings selected.")
        else:
            for index, finding in enumerate(
                investigation.findings,
                start=1,
            ):
                lines.extend([
                    f"[{index}] "
                    f"{finding.ioc_type.upper()}: "
                    f"{finding.value}",
                    f"    Relationship: "
                    f"{finding.relationship}",
                    f"    Description: "
                    f"{finding.description}",
                    f"    Events: {finding.event_count}",
                    f"    Sources: {finding.source_count}",
                    f"    Evidence: {finding.evidence_count}",
                ])

                if finding.sources:
                    lines.append(
                        "    Source names: "
                        + ", ".join(finding.sources)
                    )

                if finding.first_seen:
                    lines.append(
                        f"    First seen: {finding.first_seen}"
                    )

                if finding.last_seen:
                    lines.append(
                        f"    Last seen: {finding.last_seen}"
                    )

                if finding.time_span_seconds is not None:
                    lines.append(
                        f"    Time span: "
                        f"{finding.time_span_seconds:.1f}s"
                    )

                closest_gap = getattr(
                    finding,
                    "closest_cross_source_gap_seconds",
                    None,
                )
                if closest_gap is not None:
                    lines.append(
                        f"    Closest cross-source gap: "
                        f"{closest_gap:.1f}s"
                    )

                if finding.evidence:
                    lines.append("")
                    lines.append("    Supporting evidence:")

                    for evidence_index, evidence in enumerate(
                        finding.evidence,
                        start=1,
                    ):
                        lines.append(
                            f"      {evidence_index}. "
                            f"{evidence.evidence_type}: "
                            f"{evidence.value}"
                        )

                        if evidence.source:
                            lines.append(
                                f"         Source: "
                                f"{evidence.source}"
                            )

                        if evidence.timestamp:
                            lines.append(
                                f"         Time: "
                                f"{evidence.timestamp}"
                            )

                        if evidence.description:
                            lines.append(
                                f"         Context: "
                                f"{evidence.description}"
                            )

                edges = finding.relationship_edges or []
                if edges:
                    lines.append("")
                    lines.append(
                        "    Evidence relationships:"
                    )

                    for edge_index, edge in enumerate(
                        edges,
                        start=1,
                    ):
                        lines.append(
                            f"      {edge_index}. "
                            f"{edge.relationship_type}"
                        )
                        lines.append(
                            f"         From: "
                            f"{edge.source or '-'} "
                            f"[{edge.source_event_id or '-'}]"
                        )
                        lines.append(
                            f"         To: "
                            f"{edge.target or '-'} "
                            f"[{edge.target_event_id or '-'}]"
                        )

                        if edge.time_gap_seconds is not None:
                            lines.append(
                                f"         Time gap: "
                                f"{edge.time_gap_seconds:.1f}s"
                            )

                        if edge.description:
                            lines.append(
                                f"         Context: "
                                f"{edge.description}"
                            )

                lines.append("")

        lines.extend([
            "INVESTIGATION TIMELINE",
            "-" * 34,
        ])

        if not timeline:
            lines.append("No timeline entries.")
        else:
            for index, entry in enumerate(
                timeline,
                start=1,
            ):
                lines.append(
                    f"[{index}] {entry.timestamp or 'Unknown time'}"
                )
                lines.append(
                    f"    IOC: {entry.ioc_type}: "
                    f"{entry.ioc_value}"
                )
                lines.append(
                    f"    Source: {entry.source or '-'}"
                )

                if entry.event_type:
                    lines.append(
                        f"    Event type: {entry.event_type}"
                    )

                if entry.relationship_types:
                    lines.append(
                        "    Relationships: "
                        + self._join_values(
                            entry.relationship_types
                        )
                    )

                if entry.related_event_ids:
                    lines.append(
                        "    Related event IDs: "
                        + self._join_values(
                            entry.related_event_ids
                        )
                    )

                if entry.previous_event_id:
                    lines.append(
                        f"    Previous event ID: "
                        f"{entry.previous_event_id}"
                    )

                if entry.gap_from_previous_seconds is not None:
                    lines.append(
                        f"    Gap from previous: "
                        f"{entry.gap_from_previous_seconds:.1f}s"
                    )

                if entry.description:
                    lines.append(
                        f"    Context: {entry.description}"
                    )

                lines.append("")

        lines.extend([
            "ANALYST NOTES",
            "-" * 34,
        ])

        if not investigation.notes:
            lines.append("No analyst notes.")
        else:
            for index, note in enumerate(
                investigation.notes,
                start=1,
            ):
                lines.append(
                    f"{index}. {note}"
                )

        lines.extend([
            "",
            "Generated by LogViewer.",
        ])

        path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return path

    @staticmethod
    def _finding_row(
        investigation: InvestigationContext,
        finding: Any,
    ) -> Dict[str, Any]:
        return {
            "investigation": investigation.name,
            "ioc_type": finding.ioc_type,
            "ioc_value": finding.value,
            "relationship": finding.relationship,
            "description": finding.description,
            "event_count": finding.event_count,
            "source_count": finding.source_count,
            "sources": "; ".join(
                finding.sources or []
            ),
            "event_types": "; ".join(
                finding.event_types or []
            ),
            "first_seen": finding.first_seen or "",
            "last_seen": finding.last_seen or "",
            "time_span_seconds": (
                finding.time_span_seconds
                if finding.time_span_seconds is not None
                else ""
            ),
            "closest_cross_source_gap_seconds": (
                getattr(
                    finding,
                    "closest_cross_source_gap_seconds",
                    None,
                )
                if getattr(
                    finding,
                    "closest_cross_source_gap_seconds",
                    None,
                ) is not None
                else ""
            ),
            "relationship_edge_count": len(
                finding.relationship_edges or []
            ),
        }

    @staticmethod
    def _join_values(values) -> str:
        if not values:
            return ""
        return "; ".join(
            str(value)
            for value in values
            if value is not None
        )

    @staticmethod
    def _json_default(value):
        if isinstance(value, Path):
            return str(value)

        if hasattr(value, "as_dict"):
            return value.as_dict()

        if hasattr(value, "__dict__"):
            return value.__dict__

        return str(value)

    @staticmethod
    def _safe_filename(
        filename: str,
    ) -> str:
        """
        Prevent directory traversal through export filenames.
        """

        value = Path(
            str(filename)
        ).name.strip()

        if not value:
            value = "investigation"

        return value
