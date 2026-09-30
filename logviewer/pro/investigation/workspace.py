from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Confirm, Prompt


class InvestigationWorkspace:
    """
    Interactive Pro Investigation workspace.

    This class is intentionally UI-only. It consumes the existing
    InvestigationService/model/display/reporting functionality and does not
    implement or bypass licensing.
    """

    def __init__(self, service: Any, console: Optional[Console] = None) -> None:
        self.service = service
        self.console = console or Console()

    @staticmethod
    def _value(data: Any, key: str, default: Any = None) -> Any:
        if isinstance(data, dict):
            return data.get(key, default)
        return getattr(data, key, default)

    @staticmethod
    def _items(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return [value]

    def _list_investigations(self) -> List[Any]:
        try:
            records = self.service.list()
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to load investigations.[/red]\n\n{exc}",
                    title="Investigation Store Error",
                    border_style="red",
                )
            )
            return []

        return self._items(records)

    def _get_investigation(self, investigation_id: str) -> Any:
        try:
            return self.service.get(investigation_id)
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to open investigation.[/red]\n\n{exc}",
                    title="Investigation Error",
                    border_style="red",
                )
            )
            return None

    def _overview(self, investigation: Any) -> None:
        summary = (
            investigation.summary()
            if hasattr(investigation, "summary")
            else investigation
        )

        table = Table(
            title="Investigation Overview",
            show_header=False,
            expand=True,
        )
        table.add_column("Field", style="cyan", width=24)
        table.add_column("Value", style="white")

        fields = (
            ("Investigation ID", self._value(investigation, "investigation_id", "N/A")),
            ("Title", self._value(investigation, "title", "Untitled")),
            ("Status", self._value(investigation, "status", "N/A")),
            ("Severity", self._value(investigation, "severity", "N/A")),
            ("Confidence", self._value(investigation, "confidence", "N/A")),
            ("Threat Score", self._value(investigation, "threat_score", "N/A")),
            ("Threat Level", self._value(investigation, "threat_level", "N/A")),
            ("Events", len(self._items(self._value(investigation, "events", [])))),
            ("Evidence", len(self._items(self._value(investigation, "evidence", [])))),
            ("IOCs", len(self._items(self._value(investigation, "iocs", [])))),
            (
                "Correlations",
                len(self._items(self._value(investigation, "correlations", []))),
            ),
            (
                "MITRE Mappings",
                len(self._items(self._value(investigation, "mitre_mappings", []))),
            ),
            (
                "Findings",
                len(self._items(self._value(investigation, "findings", []))),
            ),
        )

        for field, value in fields:
            table.add_row(field, str(value))

        self.console.print(table)

        if isinstance(summary, dict):
            description = summary.get("summary")
            if description:
                self.console.print(
                    Panel(
                        str(description),
                        title="Investigation Summary",
                        border_style="blue",
                    )
                )

    def _show_collection(
        self,
        investigation: Any,
        field: str,
        title: str,
        empty_message: str,
    ) -> None:
        records = self._items(self._value(investigation, field, []))

        if not records:
            self.console.print(
                Panel(
                    empty_message,
                    title=title,
                    border_style="yellow",
                )
            )
            return

        table = Table(title=title, expand=True)
        table.add_column("#", style="cyan", width=5)
        table.add_column("Details", style="white")

        for index, record in enumerate(records, start=1):
            if isinstance(record, dict):
                preferred = (
                    record.get("title")
                    or record.get("name")
                    or record.get("summary")
                    or record.get("description")
                    or record.get("technique")
                    or record.get("id")
                )

                if preferred is not None:
                    details = str(preferred)
                else:
                    details = ", ".join(
                        f"{key}={value}"
                        for key, value in record.items()
                    )
            else:
                details = str(record)

            table.add_row(str(index), details)

        self.console.print(table)

    def _findings(self, investigation: Any) -> None:
        try:
            from .display import display_findings

            display_findings(investigation, self.console)
        except Exception:
            self._show_collection(
                investigation,
                "findings",
                "Investigation Findings",
                "No findings are currently stored.",
            )

    def _timeline(self, investigation: Any) -> None:
        try:
            from .display import display_timeline

            display_timeline(investigation)
        except Exception:
            timeline = self._value(investigation, "timeline", {})
            entries = (
                timeline.get("entries", [])
                if isinstance(timeline, dict)
                else timeline
            )

            if not entries:
                self.console.print(
                    Panel(
                        "No timeline entries are currently stored.",
                        title="Investigation Timeline",
                        border_style="yellow",
                    )
                )
                return

            self._show_collection(
                {"entries": entries},
                "entries",
                "Investigation Timeline",
                "No timeline entries are currently stored.",
            )

    def _attack_chain(self, investigation: Any) -> None:
        attack_chain = self._value(investigation, "attack_chain", {})

        if isinstance(attack_chain, dict):
            steps = attack_chain.get("steps", [])
            summary = attack_chain.get("summary")

            if summary:
                self.console.print(
                    Panel(
                        str(summary),
                        title="Attack Chain Summary",
                        border_style="magenta",
                    )
                )

            self._show_collection(
                {"steps": steps},
                "steps",
                "Attack Chain",
                "No attack-chain steps are currently stored.",
            )
        else:
            self._show_collection(
                {"steps": attack_chain},
                "steps",
                "Attack Chain",
                "No attack-chain steps are currently stored.",
            )

    def _process_tree(self, investigation: Any) -> None:
        process_tree = self._value(investigation, "process_tree", {})

        if not process_tree:
            self.console.print(
                Panel(
                    "No process-tree data is currently stored.",
                    title="Process Tree",
                    border_style="yellow",
                )
            )
            return

        if isinstance(process_tree, dict):
            nodes = process_tree.get("nodes", [])
            relationships = process_tree.get("relationships", [])

            table = Table(title="Process Tree", expand=True)
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="white")

            table.add_row("Nodes", str(len(self._items(nodes))))
            table.add_row(
                "Relationships",
                str(len(self._items(relationships))),
            )

            self.console.print(table)

            if nodes:
                self._show_collection(
                    {"nodes": nodes},
                    "nodes",
                    "Process Nodes",
                    "No process nodes are stored.",
                )
        else:
            self.console.print(
                Panel(
                    str(process_tree),
                    title="Process Tree",
                    border_style="blue",
                )
            )

    def _mitre(self, investigation: Any) -> None:
        self._show_collection(
            investigation,
            "mitre_mappings",
            "MITRE ATT&CK Mappings",
            "No MITRE mappings are currently stored.",
        )

    def _threat_score(self, investigation: Any) -> None:
        score = self._value(investigation, "threat_score", "N/A")
        level = self._value(investigation, "threat_level", "N/A")
        details = self._value(investigation, "threat_score_details", {})

        table = Table(
            title="Threat Assessment",
            show_header=False,
            expand=True,
        )
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Threat Score", str(score))
        table.add_row("Threat Level", str(level))

        if isinstance(details, dict):
            for key, value in details.items():
                table.add_row(str(key), str(value))

        self.console.print(table)

    def _false_positive(self, investigation: Any) -> None:
        analysis = self._value(
            investigation,
            "false_positive_analysis",
            {},
        )

        if not analysis:
            self.console.print(
                Panel(
                    "No false-positive analysis is currently stored.",
                    title="False-Positive Analysis",
                    border_style="yellow",
                )
            )
            return

        table = Table(
            title="False-Positive Analysis",
            show_header=False,
            expand=True,
        )
        table.add_column("Field", style="cyan", width=28)
        table.add_column("Value", style="white")

        if isinstance(analysis, dict):
            for key, value in analysis.items():
                table.add_row(str(key), str(value))
        else:
            table.add_row("Analysis", str(analysis))

        self.console.print(table)

    def _evidence(self, investigation: Any) -> None:
        self._show_collection(
            investigation,
            "evidence",
            "Investigation Evidence",
            "No evidence is currently stored.",
        )

    def _iocs(self, investigation: Any) -> None:
        self._show_collection(
            investigation,
            "iocs",
            "Investigation IOCs",
            "No IOCs are currently stored.",
        )

    def _correlations(self, investigation: Any) -> None:
        self._show_collection(
            investigation,
            "correlations",
            "Investigation Correlations",
            "No correlations are currently stored.",
        )

    def _build_report_generator(self) -> Any:
        from ..reporting.investigation_report import InvestigationReportGenerator

        return InvestigationReportGenerator()

    def _build_report_exporter(self) -> Any:
        from ..reporting.exporter import InvestigationReportExporter

        return InvestigationReportExporter()

    def _build_evidence_package_builder(self) -> Any:
        from ..reporting.evidence_package import (
            InvestigationEvidencePackageBuilder,
        )

        return InvestigationEvidencePackageBuilder()

    def _build_evidence_package_verifier(self) -> Any:
        from ..reporting.evidence_package_verifier import (
            InvestigationEvidencePackageVerifier,
        )

        return InvestigationEvidencePackageVerifier()

    def _view_report(self, investigation: Any) -> None:
        try:
            generator = self._build_report_generator()
            markdown = generator.render_markdown(investigation)

            self.console.print(
                Panel(
                    markdown,
                    title="Investigation Markdown Report",
                    border_style="cyan",
                    expand=True,
                )
            )
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to generate the investigation report.[/red]\n\n{exc}",
                    title="Report Error",
                    border_style="red",
                )
            )

        Prompt.ask("Press Enter to return", default="")

    def _export_report(
        self,
        investigation: Any,
        format_name: str,
    ) -> None:
        try:
            exporter = self._build_report_exporter()

            if format_name == "markdown":
                path = exporter.export_markdown(investigation)
                label = "Markdown"
            elif format_name == "json":
                path = exporter.export_json(investigation)
                label = "JSON"
            else:
                raise ValueError(f"Unsupported report format: {format_name}")

            self.console.print(
                Panel(
                    f"[green]Report exported successfully.[/green]\n\n"
                    f"Format: {label}\n"
                    f"Path: {path}",
                    title="Report Export",
                    border_style="green",
                )
            )
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to export the report.[/red]\n\n{exc}",
                    title="Report Export Error",
                    border_style="red",
                )
            )

        Prompt.ask("Press Enter to return", default="")

    def _export_both_reports(self, investigation: Any) -> None:
        try:
            exporter = self._build_report_exporter()
            paths = exporter.export_all(investigation)

            if isinstance(paths, dict):
                details = "\n".join(
                    f"{key}: {value}"
                    for key, value in paths.items()
                )
            else:
                details = str(paths)

            self.console.print(
                Panel(
                    f"[green]All investigation reports exported successfully.[/green]\n\n"
                    f"{details}",
                    title="Report Export",
                    border_style="green",
                )
            )
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to export the reports.[/red]\n\n{exc}",
                    title="Report Export Error",
                    border_style="red",
                )
            )

        Prompt.ask("Press Enter to return", default="")

    def _build_evidence_package(self, investigation: Any) -> None:
        try:
            builder = self._build_evidence_package_builder()
            package_path = builder.build(investigation)

            self.console.print(
                Panel(
                    f"[green]Evidence package created successfully.[/green]\n\n"
                    f"Package: {package_path}\n\n"
                    f"The package contains the Markdown report, JSON report, "
                    f"and integrity manifest with SHA-256 hashes.",
                    title="Evidence Package",
                    border_style="green",
                )
            )
        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to build the evidence package.[/red]\n\n{exc}",
                    title="Evidence Package Error",
                    border_style="red",
                )
            )

        Prompt.ask("Press Enter to return", default="")

    def _verify_evidence_package(self, investigation: Any) -> None:
        investigation_id = str(
            self._value(
                investigation,
                "investigation_id",
                "unknown",
            )
        )

        package_path = (
            Path("exports")
            / f"investigation_{investigation_id}_evidence.zip"
        )

        try:
            verifier = self._build_evidence_package_verifier()
            result = verifier.verify(package_path)

            status = str(result.get("status", "error")).lower()
            verified = bool(result.get("verified", False))

            if status == "verified" and verified:
                border_style = "green"
                status_text = "[bold green]VERIFIED[/bold green]"
                title = "Evidence Package Verification"
            elif status == "failed":
                border_style = "red"
                status_text = "[bold red]FAILED[/bold red]"
                title = "Evidence Package Verification Failed"
            else:
                border_style = "yellow"
                status_text = "[bold yellow]ERROR[/bold yellow]"
                title = "Evidence Package Verification Error"

            investigation_info = result.get("investigation") or {}

            display_id = investigation_info.get(
                "id",
                investigation_id,
            )
            display_title = investigation_info.get(
                "title",
                self._value(
                    investigation,
                    "title",
                    "Untitled Investigation",
                ),
            )

            summary = (
                f"{status_text}\n\n"
                f"Package: {package_path}\n"
                f"Investigation ID: {display_id}\n"
                f"Title: {display_title}\n"
                f"Algorithm: {result.get('algorithm', 'N/A')}"
            )

            self.console.print(
                Panel(
                    summary,
                    title=title,
                    border_style=border_style,
                )
            )

            files = result.get("files", [])

            if files:
                table = Table(
                    title="Integrity Verification",
                    expand=True,
                )
                table.add_column("#", style="cyan", width=4)
                table.add_column("Artifact", style="white")
                table.add_column("Format", style="white")
                table.add_column("Size", style="white")
                table.add_column("SHA-256", style="white")
                table.add_column("State", style="bold")

                for index, file_result in enumerate(
                    files,
                    start=1,
                ):
                    expected_size = file_result.get(
                        "expected_size"
                    )
                    actual_size = file_result.get(
                        "actual_size"
                    )

                    if (
                        isinstance(expected_size, int)
                        and isinstance(actual_size, int)
                        and expected_size == actual_size
                    ):
                        size_text = (
                            f"{self._format_file_size(actual_size)} "
                            "(match)"
                        )
                    elif actual_size is None:
                        size_text = (
                            f"expected "
                            f"{self._format_file_size(expected_size)}"
                            if isinstance(expected_size, int)
                            else "N/A"
                        )
                    else:
                        size_text = (
                            f"{self._format_file_size(actual_size)} "
                            f"/ expected "
                            f"{self._format_file_size(expected_size)}"
                            if isinstance(expected_size, int)
                            else self._format_file_size(actual_size)
                        )

                    expected_hash = str(
                        file_result.get(
                            "expected_sha256",
                            "N/A",
                        )
                    )
                    actual_hash = file_result.get(
                        "actual_sha256"
                    )

                    if actual_hash:
                        if expected_hash.lower() == str(
                            actual_hash
                        ).lower():
                            hash_text = (
                                f"{str(actual_hash)[:16]}... "
                                "(match)"
                            )
                        else:
                            hash_text = (
                                f"expected {expected_hash[:16]}...\n"
                                f"actual {str(actual_hash)[:16]}..."
                            )
                    else:
                        hash_text = (
                            f"expected {expected_hash[:16]}..."
                        )

                    state = bool(
                        file_result.get(
                            "verified",
                            False,
                        )
                    )

                    state_text = (
                        "[green]VERIFIED[/green]"
                        if state
                        else "[red]FAILED[/red]"
                    )

                    table.add_row(
                        str(index),
                        str(file_result.get("path", "N/A")),
                        str(file_result.get("format", "N/A")),
                        size_text,
                        hash_text,
                        state_text,
                    )

                self.console.print(table)

            errors = result.get("errors", [])

            if errors:
                error_text = "\n".join(
                    f"• {error}"
                    for error in errors
                )

                self.console.print(
                    Panel(
                        error_text,
                        title="Verification Errors",
                        border_style="red",
                    )
                )

            warnings = result.get("warnings", [])

            if warnings:
                warning_text = "\n".join(
                    f"• {warning}"
                    for warning in warnings
                )

                self.console.print(
                    Panel(
                        warning_text,
                        title="Verification Warnings",
                        border_style="yellow",
                    )
                )

            limitations = result.get("limitations", [])

            if limitations:
                limitation_text = "\n".join(
                    f"• {limitation}"
                    for limitation in limitations
                )

                self.console.print(
                    Panel(
                        limitation_text,
                        title="Verification Limitations",
                        border_style="dim",
                    )
                )

        except Exception as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to verify the evidence package.[/red]\n\n"
                    f"Package: {package_path}\n\n"
                    f"{exc}",
                    title="Evidence Package Verification Error",
                    border_style="red",
                )
            )

        Prompt.ask("Press Enter to return", default="")

    @staticmethod
    def _format_file_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"

        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"

        return f"{size / (1024 * 1024):.1f} MB"

    @staticmethod
    def _format_modified_time(path: Path) -> str:
        try:
            timestamp = path.stat().st_mtime
            return datetime.fromtimestamp(
                timestamp
            ).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            return "N/A"

    def _report_history(self, investigation: Any) -> None:
        while True:
            try:
                exporter = self._build_report_exporter()
                reports = exporter.list_exports(investigation)
            except Exception as exc:
                self.console.print(
                    Panel(
                        f"[red]Unable to load report history.[/red]\n\n{exc}",
                        title="Report History Error",
                        border_style="red",
                    )
                )
                Prompt.ask("Press Enter to return", default="")
                return

            if not reports:
                self.console.print(
                    Panel(
                        "No exported reports were found for this investigation.",
                        title="Report History",
                        border_style="yellow",
                    )
                )
            else:
                table = Table(
                    title="Exported Investigation Reports",
                    expand=True,
                )
                table.add_column("#", style="cyan", width=5)
                table.add_column("File", style="white")
                table.add_column("Format", style="bold")
                table.add_column("Size", style="white")
                table.add_column("Modified", style="white")

                for index, report_path in enumerate(
                    reports,
                    start=1,
                ):
                    suffix = report_path.suffix.lower()
                    format_name = (
                        "Markdown"
                        if suffix == ".md"
                        else "JSON"
                    )

                    try:
                        size = report_path.stat().st_size
                    except OSError:
                        size = 0

                    table.add_row(
                        str(index),
                        report_path.name,
                        format_name,
                        self._format_file_size(size),
                        self._format_modified_time(report_path),
                    )

                self.console.print(table)

            menu = Table(
                show_header=False,
                box=None,
                expand=True,
            )
            menu.add_column("Option", style="bold cyan", width=8)
            menu.add_column("History Action", style="white")

            if reports:
                menu.add_row("1", "View Markdown Export")
                menu.add_row("2", "Delete Export")
            menu.add_row("3", "Refresh")
            menu.add_row("0", "Back")

            self.console.print(menu)

            choices = ["0", "3"]

            if reports:
                choices.extend(["1", "2"])

            choice = Prompt.ask(
                "\nSelect history option",
                choices=choices,
                default="0",
            )

            if choice == "0":
                return

            if choice == "3":
                continue

            if choice == "1" and reports:
                markdown_reports = [
                    path
                    for path in reports
                    if path.suffix.lower() == ".md"
                ]

                if not markdown_reports:
                    self.console.print(
                        Panel(
                            "No Markdown exports are available to view.",
                            title="Report History",
                            border_style="yellow",
                        )
                    )
                    Prompt.ask("Press Enter to return", default="")
                    continue

                markdown_choices = [
                    str(index)
                    for index in range(
                        1,
                        len(markdown_reports) + 1,
                    )
                ]

                table = Table(
                    title="Markdown Exports",
                    show_header=False,
                    expand=True,
                )
                table.add_column("#", style="cyan", width=5)
                table.add_column("File", style="white")

                for index, path in enumerate(
                    markdown_reports,
                    start=1,
                ):
                    table.add_row(
                        str(index),
                        path.name,
                    )

                self.console.print(table)

                selected = Prompt.ask(
                    "\nSelect Markdown export",
                    choices=markdown_choices + ["0"],
                    default="0",
                )

                if selected == "0":
                    continue

                selected_path = markdown_reports[
                    int(selected) - 1
                ]

                try:
                    content = exporter.read_markdown(
                        selected_path
                    )

                    self.console.print(
                        Panel(
                            content,
                            title=selected_path.name,
                            border_style="cyan",
                            expand=True,
                        )
                    )
                except Exception as exc:
                    self.console.print(
                        Panel(
                            f"[red]Unable to read the report.[/red]\n\n{exc}",
                            title="Report Read Error",
                            border_style="red",
                        )
                    )

                Prompt.ask("Press Enter to return", default="")
                continue

            if choice == "2" and reports:
                choices_for_delete = [
                    str(index)
                    for index in range(
                        1,
                        len(reports) + 1,
                    )
                ]

                selected = Prompt.ask(
                    "\nSelect export to delete",
                    choices=choices_for_delete + ["0"],
                    default="0",
                )

                if selected == "0":
                    continue

                selected_path = reports[
                    int(selected) - 1
                ]

                confirmed = Confirm.ask(
                    f"Delete '{selected_path.name}'?",
                    default=False,
                )

                if not confirmed:
                    self.console.print(
                        Panel(
                            "Deletion cancelled.",
                            title="Report History",
                            border_style="yellow",
                        )
                    )
                    continue

                try:
                    deleted = exporter.delete_export(
                        selected_path
                    )

                    if deleted:
                        self.console.print(
                            Panel(
                                f"[green]Deleted successfully.[/green]\n\n"
                                f"{selected_path.name}",
                                title="Report Deleted",
                                border_style="green",
                            )
                        )
                    else:
                        self.console.print(
                            Panel(
                                "The selected report no longer exists.",
                                title="Report History",
                                border_style="yellow",
                            )
                        )
                except Exception as exc:
                    self.console.print(
                        Panel(
                            f"[red]Unable to delete the report.[/red]\n\n{exc}",
                            title="Report Delete Error",
                            border_style="red",
                        )
                    )

                Prompt.ask("Press Enter to return", default="")

    def _report_menu(self, investigation: Any) -> None:
        while True:
            investigation_id = self._value(
                investigation,
                "investigation_id",
                "unknown",
            )

            menu = Table(
                title="Investigation Reporting",
                show_header=False,
                box=None,
                expand=True,
            )
            menu.add_column("Option", style="bold cyan", width=8)
            menu.add_column("Report Action", style="white")

            menu.add_row("1", "View Markdown Report")
            menu.add_row("2", "Export Markdown")
            menu.add_row("3", "Export JSON")
            menu.add_row("4", "Export Both")
            menu.add_row("5", "Build Evidence Package")
            menu.add_row("6", "Verify Evidence Package")
            menu.add_row("7", "Report History")
            menu.add_row("8", "Back")

            self.console.print(
                Panel(
                    Text.assemble(
                        ("INVESTIGATION REPORTING\n", "bold cyan"),
                        (f"Investigation: {investigation_id}", "dim"),
                    ),
                    border_style="cyan",
                )
            )
            self.console.print(menu)

            choice = Prompt.ask(
                "\nSelect report option",
                choices=[
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                ],
                default="8",
            )

            if choice == "1":
                self._view_report(investigation)
            elif choice == "2":
                self._export_report(investigation, "markdown")
            elif choice == "3":
                self._export_report(investigation, "json")
            elif choice == "4":
                self._export_both_reports(investigation)
            elif choice == "5":
                self._build_evidence_package(investigation)
            elif choice == "6":
                self._verify_evidence_package(investigation)
            elif choice == "7":
                self._report_history(investigation)
            elif choice == "8":
                return

    def _workspace_menu(self, investigation: Any) -> None:
        while True:
            investigation_id = self._value(
                investigation,
                "investigation_id",
                "unknown",
            )
            title = self._value(
                investigation,
                "title",
                "Untitled Investigation",
            )

            self.console.print(
                Panel(
                    Text.assemble(
                        ("PRO INVESTIGATION WORKSPACE\n", "bold cyan"),
                        (f"{title}\n", "bold white"),
                        (f"ID: {investigation_id}", "dim"),
                    ),
                    border_style="cyan",
                    expand=True,
                )
            )

            menu = Table(
                show_header=False,
                box=None,
                expand=True,
            )
            menu.add_column("Option", style="bold cyan", width=8)
            menu.add_column("Workspace", style="white")

            menu.add_row("1", "Investigation Overview")
            menu.add_row("2", "Findings")
            menu.add_row("3", "Timeline")
            menu.add_row("4", "Attack Chain")
            menu.add_row("5", "Process Tree")
            menu.add_row("6", "MITRE ATT&CK Mappings")
            menu.add_row("7", "Threat Assessment")
            menu.add_row("8", "False-Positive Analysis")
            menu.add_row("9", "Evidence")
            menu.add_row("10", "IOCs")
            menu.add_row("11", "Correlations")
            menu.add_row("12", "Investigation Report")
            menu.add_row("0", "Back")

            self.console.print(menu)

            choice = Prompt.ask(
                "\nSelect workspace option",
                choices=[
                    "0",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                    "9",
                    "10",
                    "11",
                    "12",
                ],
                default="0",
            )

            if choice == "0":
                return
            if choice == "1":
                self._overview(investigation)
            elif choice == "2":
                self._findings(investigation)
            elif choice == "3":
                self._timeline(investigation)
            elif choice == "4":
                self._attack_chain(investigation)
            elif choice == "5":
                self._process_tree(investigation)
            elif choice == "6":
                self._mitre(investigation)
            elif choice == "7":
                self._threat_score(investigation)
            elif choice == "8":
                self._false_positive(investigation)
            elif choice == "9":
                self._evidence(investigation)
            elif choice == "10":
                self._iocs(investigation)
            elif choice == "11":
                self._correlations(investigation)
            elif choice == "12":
                self._report_menu(investigation)

    def run(self) -> None:
        investigations = self._list_investigations()

        if not investigations:
            self.console.print(
                Panel(
                    "No stored investigations were found.",
                    title="Pro Investigation Workspace",
                    border_style="yellow",
                )
            )
            Prompt.ask("Press Enter to return", default="")
            return

        table = Table(
            title="Stored Pro Investigations",
            expand=True,
        )
        table.add_column("#", style="cyan", width=5)
        table.add_column("ID", style="white")
        table.add_column("Title", style="bold")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Threat")

        for index, record in enumerate(investigations, start=1):
            investigation_id = self._value(
                record,
                "investigation_id",
                self._value(record, "id", "unknown"),
            )
            title = self._value(record, "title", "Untitled")
            status = self._value(record, "status", "N/A")
            severity = self._value(record, "severity", "N/A")
            threat = self._value(record, "threat_level", "N/A")

            table.add_row(
                str(index),
                str(investigation_id),
                str(title),
                str(status),
                str(severity),
                str(threat),
            )

        self.console.print(table)

        valid_choices = ["0"] + [
            str(i)
            for i in range(1, len(investigations) + 1)
        ]

        choice = Prompt.ask(
            "\nSelect an investigation to open",
            choices=valid_choices,
            default="0",
        )

        if choice == "0":
            return

        selected = investigations[int(choice) - 1]
        investigation_id = self._value(
            selected,
            "investigation_id",
            self._value(selected, "id", None),
        )

        if investigation_id is None:
            self.console.print(
                Panel(
                    "The selected investigation does not contain a valid ID.",
                    title="Investigation Error",
                    border_style="red",
                )
            )
            Prompt.ask("Press Enter to return", default="")
            return

        investigation = self._get_investigation(str(investigation_id))

        if investigation is None:
            Prompt.ask("Press Enter to return", default="")
            return

        self._workspace_menu(investigation)


def run_investigation_workspace(
    service: Any,
    console: Optional[Console] = None,
) -> None:
    InvestigationWorkspace(service=service, console=console).run()
