from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class InvestigationReportGenerator:
    """Generate analyst-ready reports from an existing Investigation."""

    REPORT_VERSION = "1.0"

    def build_data(self, investigation: Any) -> Dict[str, Any]:
        """Build a stable, serializable report representation."""

        summary = investigation.summary()

        return {
            "report_version": self.REPORT_VERSION,
            "investigation": {
                "investigation_id": investigation.investigation_id,
                "title": investigation.title,
                "status": investigation.status,
                "severity": investigation.severity,
                "confidence": investigation.confidence,
                "created_at": investigation.created_at,
                "updated_at": investigation.updated_at,
            },
            "overview": summary,
            "threat_assessment": {
                "score": investigation.threat_score,
                "level": investigation.threat_level,
                "details": investigation.threat_score_details,
            },
            "false_positive_analysis": investigation.false_positive_analysis,
            "findings": list(investigation.findings),
            "events": list(investigation.events),
            "evidence": list(investigation.evidence),
            "iocs": list(investigation.iocs),
            "correlations": list(investigation.correlations),
            "mitre_mappings": list(investigation.mitre_mappings),
            "process_tree": investigation.process_tree,
            "attack_chain": investigation.attack_chain,
            "timeline": investigation.timeline,
            "metadata": investigation.metadata,
        }

    def render_markdown(self, investigation: Any) -> str:
        """Render an investigation as an analyst-readable Markdown report."""

        data = self.build_data(investigation)
        info = data["investigation"]
        threat = data["threat_assessment"]
        overview = data["overview"]

        lines: List[str] = []

        lines.extend(
            [
                f"# Investigation Report: {info['title']}",
                "",
                f"**Report Version:** {data['report_version']}",
                f"**Investigation ID:** `{info['investigation_id']}`",
                f"**Status:** {info['status']}",
                f"**Severity:** {info['severity']}",
                f"**Confidence:** {self._format_value(info['confidence'])}",
                f"**Created:** {info['created_at']}",
                f"**Updated:** {info['updated_at']}",
                "",
                "---",
                "",
                "## 1. Investigation Overview",
                "",
                self._overview_table(overview),
                "",
                "## 2. Threat Assessment",
                "",
                f"- **Threat Score:** {self._format_value(threat['score'])}",
                f"- **Threat Level:** {self._format_value(threat['level'])}",
                "",
            ]
        )

        if threat["details"]:
            lines.extend(
                [
                    "### Threat Score Details",
                    "",
                    self._render_mapping(threat["details"]),
                    "",
                ]
            )

        lines.extend(
            [
                "## 3. Findings",
                "",
                self._render_findings(data["findings"]),
                "",
                "## 4. Evidence",
                "",
                self._render_collection(data["evidence"], "No evidence recorded."),
                "",
                "## 5. Indicators of Compromise",
                "",
                self._render_collection(data["iocs"], "No IOCs recorded."),
                "",
                "## 6. Correlations",
                "",
                self._render_collection(
                    data["correlations"],
                    "No correlations recorded.",
                ),
                "",
                "## 7. MITRE ATT&CK Mappings",
                "",
                self._render_collection(
                    data["mitre_mappings"],
                    "No MITRE ATT&CK mappings recorded.",
                ),
                "",
                "## 8. Process Tree",
                "",
                self._render_mapping(data["process_tree"]),
                "",
                "## 9. Attack Chain",
                "",
                self._render_mapping(data["attack_chain"]),
                "",
                "## 10. Timeline",
                "",
                self._render_mapping(data["timeline"]),
                "",
                "## 11. False-Positive Analysis",
                "",
                self._render_mapping(
                    data["false_positive_analysis"],
                    empty_text="No false-positive analysis recorded.",
                ),
                "",
                "## 12. Analyst-Ready Conclusion",
                "",
                self._build_conclusion(data),
                "",
                "## 13. Investigation Metadata",
                "",
                self._render_mapping(
                    data["metadata"],
                    empty_text="No additional metadata recorded.",
                ),
                "",
                "---",
                "",
                (
                    "*This report summarizes evidence and analysis already "
                    "present in the investigation. Findings and mappings "
                    "should be reviewed by an analyst before final disposition.*"
                ),
                "",
            ]
        )

        return "\n".join(lines)

    def render_text(self, investigation: Any) -> str:
        """Render a compact plain-text version of the Markdown report."""

        markdown = self.render_markdown(investigation)

        text = markdown
        replacements = {
            "**": "",
            "`": "",
            "# ": "",
            "## ": "",
            "### ": "",
        }

        for old, new in replacements.items():
            text = text.replace(old, new)

        return text

    def write_markdown(
        self,
        investigation: Any,
        output_path: str | Path,
    ) -> Path:
        """Write the investigation report to a Markdown file."""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            self.render_markdown(investigation),
            encoding="utf-8",
        )
        return path

    def write_json(
        self,
        investigation: Any,
        output_path: str | Path,
    ) -> Path:
        """Write the investigation report data to JSON."""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.build_data(investigation),
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )

        return path

    def _overview_table(self, overview: Dict[str, Any]) -> str:
        rows = [
            ("Events", overview.get("event_count", 0)),
            ("Evidence", overview.get("evidence_count", 0)),
            ("IOCs", overview.get("ioc_count", 0)),
            ("Correlations", overview.get("correlation_count", 0)),
            ("MITRE Mappings", overview.get("mitre_mapping_count", 0)),
            ("Findings", overview.get("finding_count", 0)),
            ("Process Nodes", overview.get("process_node_count", 0)),
            ("Process Relationships", overview.get("process_relationship_count", 0)),
            ("Attack-Chain Steps", overview.get("attack_chain_step_count", 0)),
            ("Timeline Entries", overview.get("timeline_entry_count", 0)),
        ]

        lines = [
            "| Metric | Value |",
            "|---|---:|",
        ]

        for name, value in rows:
            lines.append(f"| {name} | {self._format_value(value)} |")

        return "\n".join(lines)

    def _render_findings(self, findings: List[Any]) -> str:
        if not findings:
            return "No findings recorded."

        lines: List[str] = []

        for index, finding in enumerate(findings, start=1):
            if isinstance(finding, dict):
                title = finding.get("title", f"Finding {index}")
                severity = finding.get("severity", "unknown")
                confidence = finding.get("confidence", "unknown")
                summary = finding.get("summary", "")
                rationale = finding.get("rationale", "")
                source = finding.get("source", "")
                finding_id = finding.get("finding_id", "")
            else:
                title = f"Finding {index}"
                severity = "unknown"
                confidence = "unknown"
                summary = str(finding)
                rationale = ""
                source = ""
                finding_id = ""

            lines.extend(
                [
                    f"### {index}. {title}",
                    "",
                    f"- **Finding ID:** `{finding_id}`",
                    f"- **Severity:** {self._format_value(severity)}",
                    f"- **Confidence:** {self._format_value(confidence)}",
                    f"- **Source:** {self._format_value(source)}",
                ]
            )

            if summary:
                lines.extend(["", f"**Summary:** {summary}"])

            if rationale:
                lines.extend(["", f"**Rationale:** {rationale}"])

            if isinstance(finding, dict):
                self._append_optional_finding_field(
                    lines,
                    "Event IDs",
                    finding.get("event_ids"),
                )
                self._append_optional_finding_field(
                    lines,
                    "Evidence IDs",
                    finding.get("evidence_ids"),
                )
                self._append_optional_finding_field(
                    lines,
                    "IOC Values",
                    finding.get("ioc_values"),
                )
                self._append_optional_finding_field(
                    lines,
                    "MITRE Techniques",
                    finding.get("mitre_techniques"),
                )
                self._append_optional_finding_field(
                    lines,
                    "Correlation IDs",
                    finding.get("correlation_ids"),
                )

            lines.append("")

        return "\n".join(lines).rstrip()

    def _append_optional_finding_field(
        self,
        lines: List[str],
        label: str,
        value: Any,
    ) -> None:
        if value:
            lines.extend(
                [
                    "",
                    f"**{label}:** {self._format_value(value)}",
                ]
            )

    def _render_collection(
        self,
        collection: List[Any],
        empty_text: str,
    ) -> str:
        if not collection:
            return empty_text

        lines: List[str] = []

        for index, item in enumerate(collection, start=1):
            if isinstance(item, dict):
                lines.append(f"### Item {index}")
                lines.append("")
                lines.append(self._render_mapping(item))
            else:
                lines.append(f"- {self._format_value(item)}")

            lines.append("")

        return "\n".join(lines).rstrip()

    def _render_mapping(
        self,
        mapping: Any,
        empty_text: str = "No data recorded.",
    ) -> str:
        if not mapping:
            return empty_text

        if not isinstance(mapping, dict):
            return self._format_value(mapping)

        lines: List[str] = []

        for key, value in mapping.items():
            label = str(key).replace("_", " ").title()

            if isinstance(value, dict):
                lines.extend(
                    [
                        f"### {label}",
                        "",
                        self._render_mapping(value),
                        "",
                    ]
                )
            elif isinstance(value, list):
                lines.append(f"**{label}:**")

                if not value:
                    lines.append("- None")
                else:
                    for item in value:
                        if isinstance(item, dict):
                            lines.append(
                                f"- {self._format_value(item)}"
                            )
                        else:
                            lines.append(
                                f"- {self._format_value(item)}"
                            )

                lines.append("")
            else:
                lines.append(
                    f"- **{label}:** {self._format_value(value)}"
                )

        return "\n".join(lines).rstrip()

    def _build_conclusion(self, data: Dict[str, Any]) -> str:
        investigation = data["investigation"]
        threat = data["threat_assessment"]
        findings = data["findings"]
        fp = data["false_positive_analysis"]

        score = threat.get("score")
        level = threat.get("level")
        confidence = investigation.get("confidence")

        parts = [
            (
                f"The investigation contains {len(findings)} finding(s), "
                f"with a recorded threat score of {self._format_value(score)} "
                f"and threat level of {self._format_value(level)}."
            )
        ]

        if confidence is not None:
            parts.append(
                f"The recorded investigation confidence is "
                f"{self._format_value(confidence)}."
            )

        if fp:
            parts.append(
                "False-positive analysis is available and should be "
                "considered when reviewing the findings."
            )
        else:
            parts.append(
                "No false-positive analysis is currently recorded."
            )

        parts.append(
            "The report reflects the evidence and analysis stored in the "
            "investigation and does not independently establish malicious "
            "intent or successful compromise."
        )

        return " ".join(parts)

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return "N/A"

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (dict, list, tuple)):
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )

        return str(value)


__all__ = ["InvestigationReportGenerator"]
