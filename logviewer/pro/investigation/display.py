from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from logviewer.pro.investigation.model import Investigation


console = Console()


ENTRY_TYPE_LABELS = {
    "event": "EVENT",
    "correlation": "CORRELATION",
    "mitre": "MITRE",
    "process_relationship": "PROCESS",
    "attack_chain": "ATTACK CHAIN",
}


FINDING_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


TIMELINE_EMPTY_MESSAGES = {
    "mitre": (
        "No MITRE ATT&CK mappings are currently stored "
        "for this investigation."
    ),
    "process_relationship": (
        "No process relationships are currently stored "
        "for this investigation."
    ),
    "attack_chain": (
        "No attack-chain steps are currently stored "
        "for this investigation."
    ),
}


TIMELINE_EMPTY_HINTS = {
    "mitre": (
        "MITRE ATT&CK entries will appear here when the "
        "investigation pipeline produces technique mappings."
    ),
    "process_relationship": (
        "Process relationships will appear here when the "
        "investigation contains process-tree relationship data."
    ),
    "attack_chain": (
        "Attack-chain steps will appear here when the "
        "investigation pipeline produces attack-chain data."
    ),
}


def _safe_text(
    value: Any,
    default: str = "-",
) -> str:
    """Convert arbitrary values into display-safe text."""

    if value is None:
        return default

    text = str(value).strip()

    return text or default


def _format_timestamp(
    value: Any,
) -> str:
    """Format a serialized timestamp for terminal display."""

    if value is None:
        return "-"

    text = str(value)

    try:
        normalized = text.replace(
            "Z",
            "+00:00",
        )

        parsed = datetime.fromisoformat(
            normalized
        )

        return parsed.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        TypeError,
        ValueError,
    ):
        return text


def _string_list(
    value: Any,
) -> List[str]:
    """
    Convert finding values into a predictable list of strings.
    """

    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        text = value.strip()

        return [text] if text else []

    if isinstance(
        value,
        dict,
    ):
        values = []

        for key, item in value.items():
            if item is None:
                values.append(
                    str(key)
                )
                continue

            values.append(
                f"{key}: {item}"
            )

        return values

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return [
            str(item)
            for item in value
            if str(item).strip()
        ]

    return [str(value)]


def _finding_severity(
    finding: Dict[str, Any],
) -> str:
    """Return a normalized finding severity."""

    return _safe_text(
        finding.get(
            "severity",
            "unknown",
        ),
        default="unknown",
    ).lower()


def _finding_confidence(
    finding: Dict[str, Any],
) -> Optional[float]:
    """Return finding confidence as a float when possible."""

    value = finding.get(
        "confidence"
    )

    if value is None:
        return None

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def _finding_confidence_text(
    finding: Dict[str, Any],
) -> str:
    """Format finding confidence for display."""

    confidence = _finding_confidence(
        finding
    )

    if confidence is None:
        return "-"

    if confidence > 1:
        confidence /= 100

    confidence = max(
        0.0,
        min(
            1.0,
            confidence,
        ),
    )

    return f"{confidence:.1%}"


def _finding_source(
    finding: Dict[str, Any],
) -> str:
    """Return the finding source."""

    return _safe_text(
        finding.get(
            "source"
        )
    )


def _finding_title(
    finding: Dict[str, Any],
) -> str:
    """Return the finding title."""

    return _safe_text(
        finding.get(
            "title"
        ),
        default="Untitled Finding",
    )


def _finding_summary(
    finding: Dict[str, Any],
) -> str:
    """Return the finding summary."""

    return _safe_text(
        finding.get(
            "summary"
        )
    )


def _finding_rationale(
    finding: Dict[str, Any],
) -> str:
    """Return the finding rationale."""

    return _safe_text(
        finding.get(
            "rationale"
        )
    )


def _finding_id(
    finding: Dict[str, Any],
) -> str:
    """Return the stable finding identifier."""

    return _safe_text(
        finding.get(
            "finding_id"
        )
    )


def _finding_event_ids(
    finding: Dict[str, Any],
) -> List[str]:
    """Return related event IDs."""

    return _string_list(
        finding.get(
            "event_ids",
            [],
        )
    )


def _finding_evidence_ids(
    finding: Dict[str, Any],
) -> List[str]:
    """Return related evidence IDs."""

    return _string_list(
        finding.get(
            "evidence_ids",
            [],
        )
    )


def _finding_iocs(
    finding: Dict[str, Any],
) -> List[str]:
    """Return finding IOC values."""

    return _string_list(
        finding.get(
            "ioc_values",
            [],
        )
    )


def _finding_mitre(
    finding: Dict[str, Any],
) -> List[str]:
    """Return related MITRE techniques."""

    return _string_list(
        finding.get(
            "mitre_techniques",
            [],
        )
    )


def _finding_correlations(
    finding: Dict[str, Any],
) -> List[str]:
    """Return related correlation IDs."""

    return _string_list(
        finding.get(
            "correlation_ids",
            [],
        )
    )


def _finding_fp_context(
    finding: Dict[str, Any],
) -> Any:
    """Return false-positive context."""

    return finding.get(
        "false_positive_context"
    )


def _finding_severity_markup(
    severity: str,
) -> str:
    """Return Rich markup appropriate for finding severity."""

    normalized = severity.lower()

    if normalized == "critical":
        return "[bold red]CRITICAL[/bold red]"

    if normalized == "high":
        return "[red]HIGH[/red]"

    if normalized == "medium":
        return "[yellow]MEDIUM[/yellow]"

    if normalized == "low":
        return "[green]LOW[/green]"

    if normalized == "info":
        return "[cyan]INFO[/cyan]"

    return "[dim]UNKNOWN[/dim]"


def _sorted_findings(
    investigation: Investigation,
) -> List[Dict[str, Any]]:
    """Return structured findings sorted by severity and confidence."""

    findings = investigation.findings

    if not isinstance(
        findings,
        list,
    ):
        return []

    structured = [
        finding
        for finding in findings
        if isinstance(
            finding,
            dict,
        )
    ]

    return sorted(
        structured,
        key=lambda finding: (
            FINDING_SEVERITY_ORDER.get(
                _finding_severity(
                    finding
                ),
                5,
            ),
            -(
                _finding_confidence(
                    finding
                )
                or 0.0
            ),
            _finding_title(
                finding
            ).lower(),
        ),
    )


def _print_findings_summary(
    investigation: Investigation,
) -> None:
    """Display a compact findings summary."""

    findings = _sorted_findings(
        investigation
    )

    table = Table(
        title="FINDINGS SUMMARY",
        border_style="cyan",
    )

    table.add_column(
        "Severity",
        style="bold",
    )

    table.add_column(
        "Count",
        style="green",
        justify="right",
    )

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = _finding_severity(
            finding
        )

        if severity not in counts:
            severity = "unknown"

        counts[severity] += 1

    for severity in (
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
    ):
        table.add_row(
            _finding_severity_markup(
                severity
            ),
            str(
                counts[severity]
            ),
        )

    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{len(findings)}[/bold]",
    )

    console.print(
        Panel(
            table,
            title=(
                "[bold cyan]LOGVIEWER PRO • "
                "FINDINGS[/bold cyan]"
            ),
            border_style="cyan",
        )
    )


def display_findings(
    investigation: Investigation,
) -> None:
    """
    Display structured investigation findings.
    """

    findings = _sorted_findings(
        investigation
    )

    if not findings:
        console.print(
            Panel(
                "[yellow]No structured findings were "
                "generated for this investigation.[/yellow]",
                title="PRO FINDINGS",
                border_style="yellow",
            )
        )

        return

    _print_findings_summary(
        investigation
    )

    console.print()

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        severity = _finding_severity(
            finding
        )

        title = _finding_title(
            finding
        )

        summary = _finding_summary(
            finding
        )

        rationale = _finding_rationale(
            finding
        )

        table = Table(
            title=(
                f"FINDING #{index} • {title}"
            ),
            border_style="cyan",
            show_header=True,
        )

        table.add_column(
            "Property",
            style="bold yellow",
            width=22,
        )

        table.add_column(
            "Value",
            style="white",
        )

        table.add_row(
            "Finding ID",
            _finding_id(
                finding
            ),
        )

        table.add_row(
            "Severity",
            _finding_severity_markup(
                severity
            ),
        )

        table.add_row(
            "Confidence",
            _finding_confidence_text(
                finding
            ),
        )

        table.add_row(
            "Source",
            _finding_source(
                finding
            ),
        )

        table.add_row(
            "Summary",
            summary,
        )

        table.add_row(
            "Rationale",
            rationale,
        )

        event_ids = _finding_event_ids(
            finding
        )

        if event_ids:
            table.add_row(
                "Event IDs",
                ", ".join(
                    event_ids
                ),
            )

        evidence_ids = _finding_evidence_ids(
            finding
        )

        if evidence_ids:
            table.add_row(
                "Evidence IDs",
                ", ".join(
                    evidence_ids
                ),
            )

        iocs = _finding_iocs(
            finding
        )

        if iocs:
            table.add_row(
                "IOC Values",
                ", ".join(
                    iocs
                ),
            )

        mitre = _finding_mitre(
            finding
        )

        if mitre:
            table.add_row(
                "MITRE Techniques",
                ", ".join(
                    mitre
                ),
            )

        correlations = _finding_correlations(
            finding
        )

        if correlations:
            table.add_row(
                "Correlation IDs",
                ", ".join(
                    correlations
                ),
            )

        fp_context = _finding_fp_context(
            finding
        )

        if fp_context:
            table.add_row(
                "FP Context",
                _safe_text(
                    fp_context
                ),
            )

        created_at = finding.get(
            "created_at"
        )

        if created_at:
            table.add_row(
                "Created",
                _format_timestamp(
                    created_at
                ),
            )

        updated_at = finding.get(
            "updated_at"
        )

        if updated_at:
            table.add_row(
                "Updated",
                _format_timestamp(
                    updated_at
                ),
            )

        console.print(
            table
        )


def findings_menu(
    investigation: Investigation,
) -> None:
    """
    Interactive findings interface for a stored investigation.
    """

    while True:
        console.print()

        table = Table(
            title="PRO FINDINGS",
            border_style="cyan",
        )

        table.add_column(
            "Option",
            style="yellow",
        )

        table.add_column(
            "View",
            style="green",
        )

        table.add_row(
            "1",
            "View Findings",
        )

        table.add_row(
            "2",
            "Findings Summary",
        )

        table.add_row(
            "0",
            "Exit",
        )

        console.print(table)

        choice = Prompt.ask(
            "Select option"
        )

        if choice == "0":
            return

        if choice == "1":
            display_findings(
                investigation
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        if choice == "2":
            _print_findings_summary(
                investigation
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        console.print(
            "[red]Invalid option[/red]"
        )


def _timeline_entries(
    investigation: Investigation,
) -> List[Dict[str, Any]]:
    """
    Return serialized timeline entries from an investigation.
    """

    timeline = (
        investigation.timeline
        if isinstance(
            investigation.timeline,
            dict,
        )
        else {}
    )

    entries = timeline.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        return []

    return [
        entry
        for entry in entries
        if isinstance(
            entry,
            dict,
        )
    ]


def _entry_type(
    entry: Dict[str, Any],
) -> str:
    """Return the normalized timeline entry type."""

    return str(
        entry.get(
            "entry_type",
            "unknown",
        )
    ).strip().lower()


def _entry_label(
    entry: Dict[str, Any],
) -> str:
    """Return a human-readable entry type label."""

    entry_type = _entry_type(
        entry
    )

    return ENTRY_TYPE_LABELS.get(
        entry_type,
        entry_type.upper(),
    )


def _entry_source(
    entry: Dict[str, Any],
) -> str:
    """Return a useful source label."""

    source = entry.get(
        "source"
    )

    if source:
        return str(source)

    metadata = entry.get(
        "metadata",
        {},
    )

    if isinstance(
        metadata,
        dict,
    ):
        source = metadata.get(
            "source"
        )

        if source:
            return str(source)

    return "-"


def _entry_reference(
    entry: Dict[str, Any],
) -> str:
    """
    Return the most useful event/technique/process reference.
    """

    event_id = entry.get(
        "event_id"
    )

    if event_id:
        return f"event:{event_id}"

    technique_id = entry.get(
        "technique_id"
    )

    if technique_id:
        return f"technique:{technique_id}"

    process = entry.get(
        "process"
    )

    pid = entry.get(
        "pid"
    )

    if process and pid:
        return f"{process} ({pid})"

    if process:
        return str(process)

    return _safe_text(
        entry.get(
            "entry_id"
        )
    )


def _entry_description(
    entry: Dict[str, Any],
) -> str:
    """Build a compact timeline description."""

    description = entry.get(
        "description"
    )

    if description:
        return str(
            description
        )

    title = entry.get(
        "title"
    )

    if title:
        return str(title)

    technique_name = entry.get(
        "technique_name"
    )

    if technique_name:
        return str(
            technique_name
        )

    return "-"


def _normalize_timeline_filter(
    filter_name: Any,
) -> str:
    """
    Normalize timeline filter names.

    The internal timeline schema uses singular entry types such as
    'event' and 'correlation', while callers or future UI code may
    naturally provide plural forms such as 'events' or 'correlations'.
    """

    normalized = str(
        filter_name or "all"
    ).strip().lower()

    aliases = {
        "all": "all",
        "event": "event",
        "events": "event",
        "correlation": "correlation",
        "correlations": "correlation",
        "mitre": "mitre",
        "mitres": "mitre",
        "mitre_mapping": "mitre",
        "mitre_mappings": "mitre",
        "process": "process_relationship",
        "processes": "process_relationship",
        "process_relationship": "process_relationship",
        "process_relationships": "process_relationship",
        "attack_chain": "attack_chain",
        "attack-chain": "attack_chain",
        "attack_chains": "attack_chain",
        "attack-chain_steps": "attack_chain",
    }

    return aliases.get(
        normalized,
        normalized,
    )


def _entry_matches_filter(
    entry: Dict[str, Any],
    filter_name: str,
) -> bool:
    """Determine whether an entry belongs to the selected filter."""

    normalized_filter = _normalize_timeline_filter(
        filter_name
    )

    if normalized_filter == "all":
        return True

    return (
        _entry_type(entry)
        == normalized_filter
    )


def _timeline_empty_message(
    filter_name: str,
) -> str:
    """
    Return a specific empty-state message for a timeline category.
    """

    normalized_filter = _normalize_timeline_filter(
        filter_name
    )

    return TIMELINE_EMPTY_MESSAGES.get(
        normalized_filter,
        "No timeline entries match the selected filter.",
    )


def _timeline_empty_hint(
    filter_name: str,
) -> Optional[str]:
    """
    Return an explanatory hint for a timeline category when available.
    """

    normalized_filter = _normalize_timeline_filter(
        filter_name
    )

    return TIMELINE_EMPTY_HINTS.get(
        normalized_filter
    )


def _print_timeline_empty_state(
    filter_name: str,
) -> None:
    """
    Display a useful empty-state message for a timeline filter.
    """

    message = _timeline_empty_message(
        filter_name
    )

    hint = _timeline_empty_hint(
        filter_name
    )

    content = (
        f"[yellow]{message}[/yellow]"
    )

    if hint:
        content += (
            f"\n\n[dim]{hint}[/dim]"
        )

    console.print(
        Panel(
            content,
            title=(
                "[bold cyan]TIMELINE • "
                f"{_entry_label({'entry_type': _normalize_timeline_filter(filter_name)})}"
                "[/bold cyan]"
            ),
            border_style="yellow",
        )
    )


def _print_timeline_category_status(
    investigation: Investigation,
    filter_name: str,
) -> None:
    """
    Display the stored count for an empty Pro timeline category.

    This keeps the UI explicit about whether the category is genuinely
    empty rather than silently treating an empty category as a filter
    failure.
    """

    normalized_filter = _normalize_timeline_filter(
        filter_name
    )

    entries = _timeline_entries(
        investigation
    )

    count = sum(
        1
        for entry in entries
        if _entry_matches_filter(
            entry,
            normalized_filter,
        )
    )

    label = _entry_label(
        {
            "entry_type": normalized_filter
        }
    )

    if count == 0:
        _print_timeline_empty_state(
            normalized_filter
        )


def _print_timeline_summary(
    investigation: Investigation,
) -> None:
    """Display the timeline summary."""

    timeline = (
        investigation.timeline
        if isinstance(
            investigation.timeline,
            dict,
        )
        else {}
    )

    summary = timeline.get(
        "summary",
        {},
    )

    if not isinstance(
        summary,
        dict,
    ):
        summary = {}

    entries = _timeline_entries(
        investigation
    )

    actual_counts = {
        "event_count": sum(
            1
            for entry in entries
            if _entry_matches_filter(
                entry,
                "event",
            )
        ),
        "correlation_count": sum(
            1
            for entry in entries
            if _entry_matches_filter(
                entry,
                "correlation",
            )
        ),
        "mitre_count": sum(
            1
            for entry in entries
            if _entry_matches_filter(
                entry,
                "mitre",
            )
        ),
        "process_relationship_count": sum(
            1
            for entry in entries
            if _entry_matches_filter(
                entry,
                "process_relationship",
            )
        ),
        "attack_chain_step_count": sum(
            1
            for entry in entries
            if _entry_matches_filter(
                entry,
                "attack_chain",
            )
        ),
    }

    table = Table(
        title="TIMELINE SUMMARY",
        border_style="cyan",
    )

    table.add_column(
        "Metric",
        style="yellow",
    )

    table.add_column(
        "Value",
        style="green",
    )

    table.add_row(
        "Entries",
        str(
            summary.get(
                "entry_count",
                len(entries),
            )
        ),
    )

    table.add_row(
        "Events",
        str(
            actual_counts["event_count"]
        ),
    )

    table.add_row(
        "Correlations",
        str(
            actual_counts["correlation_count"]
        ),
    )

    table.add_row(
        "MITRE Mappings",
        str(
            actual_counts["mitre_count"]
        ),
    )

    table.add_row(
        "Process Relationships",
        str(
            actual_counts[
                "process_relationship_count"
            ]
        ),
    )

    table.add_row(
        "Attack-Chain Steps",
        str(
            actual_counts[
                "attack_chain_step_count"
            ]
        ),
    )

    table.add_row(
        "Timeline Gaps",
        str(
            summary.get(
                "gap_count",
                0,
            )
        ),
    )

    confidence = summary.get(
        "confidence",
        0.0,
    )

    try:
        confidence_text = (
            f"{float(confidence):.1%}"
        )
    except (
        TypeError,
        ValueError,
    ):
        confidence_text = "-"

    table.add_row(
        "Confidence",
        confidence_text,
    )

    start = timeline.get(
        "start"
    )

    end = timeline.get(
        "end"
    )

    table.add_row(
        "Start",
        _format_timestamp(start),
    )

    table.add_row(
        "End",
        _format_timestamp(end),
    )

    console.print(
        Panel(
            table,
            title=(
                "[bold cyan]LOGVIEWER PRO • "
                "TIMELINE[/bold cyan]"
            ),
            border_style="cyan",
        )
    )


def display_timeline(
    investigation: Investigation,
    filter_name: str = "all",
) -> None:
    """
    Display a filtered investigation timeline.
    """

    entries = _timeline_entries(
        investigation
    )

    normalized_filter = _normalize_timeline_filter(
        filter_name
    )

    if normalized_filter == "all":
        filtered_entries = list(
            entries
        )
    else:
        filtered_entries = [
            entry
            for entry in entries
            if _entry_matches_filter(
                entry,
                normalized_filter,
            )
        ]

    if not filtered_entries:
        if normalized_filter == "all" and not entries:
            console.print(
                Panel(
                    "[yellow]This investigation does not "
                    "contain any timeline entries.[/yellow]\n\n"
                    "[dim]Timeline data will appear here when "
                    "the investigation pipeline produces "
                    "chronological evidence.[/dim]",
                    title="TIMELINE",
                    border_style="yellow",
                )
            )
        else:
            _print_timeline_empty_state(
                normalized_filter
            )

        return

    table = Table(
        title=(
            "INVESTIGATION TIMELINE"
            if normalized_filter == "all"
            else (
                "INVESTIGATION TIMELINE • "
                f"{_entry_label({'entry_type': normalized_filter})}"
            )
        ),
        border_style="cyan",
        show_lines=False,
    )

    table.add_column(
        "#",
        style="yellow",
        width=5,
    )

    table.add_column(
        "Timestamp",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Type",
        style="magenta",
        no_wrap=True,
    )

    table.add_column(
        "Severity",
        style="red",
        no_wrap=True,
    )

    table.add_column(
        "Title",
        style="bold",
    )

    table.add_column(
        "Source",
        style="green",
    )

    table.add_column(
        "Reference",
        style="white",
    )

    for index, entry in enumerate(
        filtered_entries,
        start=1,
    ):
        table.add_row(
            str(index),
            _format_timestamp(
                entry.get(
                    "timestamp"
                )
            ),
            _entry_label(
                entry
            ),
            _safe_text(
                entry.get(
                    "severity"
                )
            ),
            _safe_text(
                entry.get(
                    "title"
                )
            ),
            _entry_source(
                entry
            ),
            _entry_reference(
                entry
            ),
        )

    console.print(table)

    console.print()

    for index, entry in enumerate(
        filtered_entries,
        start=1,
    ):
        description = _entry_description(
            entry
        )

        technique = entry.get(
            "technique_id"
        )

        tactic = entry.get(
            "tactic"
        )

        confidence = entry.get(
            "confidence"
        )

        details = description

        if technique:
            details += (
                f" | Technique: {technique}"
            )

        if tactic:
            details += (
                f" | Tactic: {tactic}"
            )

        if confidence is not None:
            try:
                details += (
                    f" | Confidence: "
                    f"{float(confidence):.1%}"
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        console.print(
            f"[bold cyan]{index}.[/bold cyan] "
            f"{details}"
        )


def timeline_filter_menu(
    investigation: Investigation,
) -> None:
    """
    Interactive timeline filter menu.
    """

    while True:
        console.print()

        table = Table(
            title="TIMELINE FILTER",
            border_style="cyan",
        )

        table.add_column(
            "Option",
            style="yellow",
        )

        table.add_column(
            "View",
            style="green",
        )

        table.add_row(
            "1",
            "All Timeline Entries",
        )

        table.add_row(
            "2",
            "Events",
        )

        table.add_row(
            "3",
            "Correlations",
        )

        table.add_row(
            "4",
            "MITRE Mappings",
        )

        table.add_row(
            "5",
            "Process Relationships",
        )

        table.add_row(
            "6",
            "Attack-Chain Steps",
        )

        table.add_row(
            "7",
            "Timeline Summary",
        )

        table.add_row(
            "0",
            "Exit",
        )

        console.print(table)

        choice = Prompt.ask(
            "Select option"
        )

        filters = {
            "1": "all",
            "2": "event",
            "3": "correlation",
            "4": "mitre",
            "5": "process_relationship",
            "6": "attack_chain",
        }

        if choice == "0":
            return

        if choice == "7":
            _print_timeline_summary(
                investigation
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        filter_name = filters.get(
            choice
        )

        if filter_name is None:
            console.print(
                "[red]Invalid option[/red]"
            )
            continue

        display_timeline(
            investigation,
            filter_name=filter_name,
        )

        Prompt.ask(
            "\nPress Enter to return",
            default="",
        )


def timeline_investigation_menu(
    investigations,
    service,
) -> None:
    """
    Interactive selection of a stored investigation followed by its
    timeline interface.
    """

    if not investigations:
        console.print(
            Panel(
                "[yellow]No stored Pro investigations "
                "were found.[/yellow]\n\n"
                "[dim]Create an investigation through the "
                "Pro investigation pipeline before opening "
                "the timeline.[/dim]",
                title="PRO INVESTIGATION TIMELINE",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default="",
        )

        return

    while True:
        console.print()

        table = Table(
            title="PRO INVESTIGATIONS",
            border_style="cyan",
        )

        table.add_column(
            "#",
            style="yellow",
            width=5,
        )

        table.add_column(
            "Investigation ID",
            style="cyan",
        )

        table.add_column(
            "Title",
            style="green",
        )

        table.add_column(
            "Severity",
            style="red",
        )

        table.add_column(
            "Threat",
            style="magenta",
        )

        table.add_column(
            "Events",
            style="white",
        )

        table.add_column(
            "Timeline",
            style="white",
        )

        for index, item in enumerate(
            investigations,
            start=1,
        ):
            table.add_row(
                str(index),
                _safe_text(
                    item.get(
                        "investigation_id"
                    )
                ),
                _safe_text(
                    item.get(
                        "title"
                    )
                ),
                _safe_text(
                    item.get(
                        "severity"
                    )
                ),
                (
                    f"{item.get('threat_score', 0)} "
                    f"({item.get('threat_level', 'INFO')})"
                ),
                str(
                    item.get(
                        "event_count",
                        0,
                    )
                ),
                str(
                    item.get(
                        "timeline_entries",
                        0,
                    )
                ),
            )

        console.print(table)

        console.print(
            "\n[dim]Enter the investigation number "
            "to open its timeline.[/dim]"
        )

        choice = Prompt.ask(
            "Investigation"
        )

        if choice.lower() in {
            "0",
            "q",
            "quit",
            "exit",
        }:
            return

        try:
            index = int(
                choice
            )

        except ValueError:
            console.print(
                "[red]Invalid investigation number[/red]"
            )
            continue

        if not (
            1 <= index <= len(
                investigations
            )
        ):
            console.print(
                "[red]Investigation number "
                "out of range[/red]"
            )
            continue

        selected = investigations[
            index - 1
        ]

        investigation_id = selected.get(
            "investigation_id"
        )

        try:
            investigation = service.get(
                investigation_id
            )

        except Exception as exc:
            console.print(
                "[red]Unable to load investigation.[/red]"
            )

            console.print(
                f"[dim]Reason: {exc}[/dim]"
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        if investigation is None:
            console.print(
                "[red]Investigation could not be found "
                "on disk.[/red]"
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        if not investigation.timeline:
            console.print(
                Panel(
                    "[yellow]This investigation does not "
                    "contain a stored timeline.[/yellow]",
                    title="TIMELINE",
                    border_style="yellow",
                )
            )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

            continue

        _print_timeline_summary(
            investigation
        )

        timeline_filter_menu(
            investigation
        )


def display_investigation(
    investigation: Investigation,
) -> None:
    """Display an investigation in a readable CLI format."""

    table = Table(
        title="Investigation Overview",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Property",
        style="bold",
    )

    table.add_column(
        "Value",
    )

    table.add_row(
        "Investigation ID",
        investigation.investigation_id,
    )

    table.add_row(
        "Title",
        investigation.title,
    )

    table.add_row(
        "Status",
        investigation.status,
    )

    table.add_row(
        "Severity",
        investigation.severity,
    )

    table.add_row(
        "Events",
        str(
            len(
                investigation.events
            )
        ),
    )

    table.add_row(
        "Evidence",
        str(
            len(
                investigation.evidence
            )
        ),
    )

    table.add_row(
        "IOC Types",
        str(
            len(
                investigation.iocs
            )
        ),
    )

    table.add_row(
        "Correlations",
        str(
            len(
                investigation.correlations
            )
        ),
    )

    table.add_row(
        "MITRE Mappings",
        str(
            len(
                investigation.mitre_mappings
            )
        ),
    )

    table.add_row(
        "Findings",
        str(
            len(
                _sorted_findings(
                    investigation
                )
            )
        ),
    )

    table.add_row(
        "Threat Score",
        (
            f"{investigation.threat_score} "
            f"({investigation.threat_level})"
        ),
    )

    table.add_row(
        "Timeline Entries",
        str(
            investigation.summary().get(
                "timeline_entries",
                0,
            )
        ),
    )

    table.add_row(
        "Confidence",
        f"{investigation.confidence:.0%}",
    )

    console.print(
        Panel(
            table,
            title=(
                "LogViewer Pro • Investigation"
            ),
            border_style="cyan",
        )
    )

    if investigation.iocs:
        console.print(
            "\n[bold]Indicators[/bold]"
        )

        if isinstance(
            investigation.iocs,
            list,
        ):
            for item in investigation.iocs:
                console.print(
                    f"  • {item}"
                )

        elif isinstance(
            investigation.iocs,
            dict,
        ):
            for ioc_type, values in (
                investigation.iocs.items()
            ):
                if isinstance(
                    values,
                    list,
                ):
                    value_text = ", ".join(
                        str(value)
                        for value in values
                    )
                else:
                    value_text = str(
                        values
                    )

                console.print(
                    f"  [cyan]{ioc_type}[/cyan]: "
                    f"{value_text}"
                )

    if investigation.findings:
        display_findings(
            investigation
        )
