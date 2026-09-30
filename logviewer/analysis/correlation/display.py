from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .engine import CorrelationFinding


console = Console()


RELATIONSHIP_STYLES = {
    "cross_source_temporal": "bold red",
    "cross_source": "bold yellow",
    "repeated": "cyan",
    "observed": "green",
}


RELATIONSHIP_LABELS = {
    "cross_source_temporal": "Cross-source + temporal",
    "cross_source": "Cross-source",
    "repeated": "Repeated",
    "observed": "Observed",
}


def relationship_style(
    relationship: str,
) -> str:
    return RELATIONSHIP_STYLES.get(
        relationship,
        "white",
    )


def relationship_label(
    relationship: str,
) -> str:
    return RELATIONSHIP_LABELS.get(
        relationship,
        relationship.replace(
            "_",
            " ",
        ).title(),
    )


def _parse_timestamp(
    value: Optional[str],
) -> Optional[datetime]:

    if not value:
        return None

    value = str(value).strip()

    if not value:
        return None

    formats = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    )

    for timestamp_format in formats:
        try:
            parsed = datetime.strptime(
                value,
                timestamp_format,
            )

            if parsed.tzinfo is not None:
                parsed = (
                    parsed.astimezone()
                    .replace(
                        tzinfo=None
                    )
                )

            return parsed

        except ValueError:
            continue

    try:
        normalized = value

        if normalized.endswith("Z"):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        parsed = datetime.fromisoformat(
            normalized
        )

        if parsed.tzinfo is not None:
            parsed = (
                parsed.astimezone()
                .replace(
                    tzinfo=None
                )
            )

        return parsed

    except ValueError:
        return None


def _sort_evidence(
    finding: CorrelationFinding,
):
    return sorted(
        enumerate(
            finding.evidence
        ),
        key=lambda item: (
            _parse_timestamp(
                item[1].timestamp
            ) is None,
            _parse_timestamp(
                item[1].timestamp
            ) or datetime.max,
            item[0],
        ),
    )


def _format_timestamp(
    timestamp: Optional[str],
) -> str:

    if not timestamp:
        return "-"

    parsed = _parse_timestamp(
        timestamp
    )

    if parsed is None:
        return str(timestamp)

    return parsed.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _format_event_type(
    evidence,
) -> str:

    return str(
        evidence.metadata.get(
            "event_type",
            "-",
        )
    )


def _format_gap(
    previous_timestamp: Optional[str],
    current_timestamp: Optional[str],
) -> Optional[float]:

    previous = _parse_timestamp(
        previous_timestamp
    )

    current = _parse_timestamp(
        current_timestamp
    )

    if previous is None or current is None:
        return None

    return (
        current - previous
    ).total_seconds()


def _build_relationship_chain(
    finding: CorrelationFinding,
) -> List[Tuple[str, Optional[float]]]:

    ordered = _sort_evidence(
        finding
    )

    chain = []

    previous_source = None
    previous_timestamp = None

    for _, evidence in ordered:

        source = (
            evidence.source
            or "Unknown source"
        )

        if source == previous_source:
            previous_timestamp = (
                evidence.timestamp
                or previous_timestamp
            )
            continue

        gap = _format_gap(
            previous_timestamp,
            evidence.timestamp,
        )

        chain.append(
            (
                source,
                gap,
            )
        )

        previous_source = source

        previous_timestamp = (
            evidence.timestamp
            or previous_timestamp
        )

    return chain


def display_correlation_summary(
    findings: Iterable[CorrelationFinding],
    event_count: int,
) -> None:

    findings = list(
        findings
    )

    total_findings = len(
        findings
    )

    observed = sum(
        1
        for finding in findings
        if finding.relationship
        == "observed"
    )

    repeated = sum(
        1
        for finding in findings
        if finding.relationship
        == "repeated"
    )

    cross_source = sum(
        1
        for finding in findings
        if finding.relationship
        == "cross_source"
    )

    temporal = sum(
        1
        for finding in findings
        if finding.relationship
        == "cross_source_temporal"
    )

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    table.add_column(
        "Metric",
        style="bold cyan",
        width=30,
    )

    table.add_column(
        "Value",
        justify="right",
        style="bold",
    )

    table.add_row(
        "Events analyzed",
        f"{event_count:,}",
    )

    table.add_row(
        "Correlation findings",
        f"{total_findings:,}",
    )

    table.add_row(
        "Observed",
        f"{observed:,}",
    )

    table.add_row(
        "Repeated",
        f"{repeated:,}",
    )

    table.add_row(
        "Cross-source",
        f"{cross_source:,}",
    )

    table.add_row(
        "Cross-source + temporal",
        f"{temporal:,}",
    )

    console.print(
        Panel(
            table,
            title="LogViewer • Security Correlation",
            border_style="cyan",
        )
    )


def display_correlation_menu() -> None:

    table = Table(
        title="Correlation Views",
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )

    table.add_column(
        "Option",
        justify="center",
        width=8,
    )

    table.add_column(
        "View",
        style="bold",
        width=30,
    )

    table.add_column(
        "Description",
        width=60,
    )

    table.add_row(
        "1",
        "Cross-source + temporal",
        "Same IOC observed across multiple sources within the correlation window.",
    )

    table.add_row(
        "2",
        "Cross-source",
        "Same IOC observed across multiple log sources.",
    )

    table.add_row(
        "3",
        "Repeated",
        "Same IOC observed repeatedly within a source.",
    )

    table.add_row(
        "4",
        "Observed",
        "IOC observed once in the analyzed evidence.",
    )

    table.add_row(
        "5",
        "Search IOC",
        "Search findings by IOC value, type, source, or supporting context.",
    )

    table.add_row(
        "6",
        "Show all",
        "Browse all correlation findings.",
    )

    table.add_row(
        "7",
        "Investigation filters",
        "Narrow findings by IOC, source, severity, relationship, event count, and time.",
    )

    table.add_row(
        "I",
        "Investigation workspace",
        "Review selected findings, evidence, IOCs, sources, and analyst notes.",
    )

    table.add_row(
        "8",
        "Refresh analysis",
        "Reload current system data and rebuild correlations.",
    )

    table.add_row(
        "0",
        "Return",
        "Return to the main LogViewer menu.",
    )

    console.print()
    console.print(table)


def display_correlation_findings(
    findings: Iterable[CorrelationFinding],
    page: int = 1,
    page_size: int = 20,
    title: str = "Security Correlation Findings",
) -> List[CorrelationFinding]:

    findings = list(
        findings
    )

    total = len(
        findings
    )

    if total == 0:

        console.print(
            Panel(
                "[yellow]No correlation findings match "
                "this view.[/yellow]\n\n"
                "Try another relationship filter or "
                "search term.",
                title="Security Correlation",
                border_style="yellow",
            )
        )

        return []

    if page_size <= 0:
        page_size = 20

    total_pages = max(
        1,
        (
            total
            + page_size
            - 1
        )
        // page_size,
    )

    page = max(
        1,
        min(
            page,
            total_pages,
        ),
    )

    start = (
        page - 1
    ) * page_size

    end = min(
        start + page_size,
        total,
    )

    visible_findings = findings[
        start:end
    ]

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    table.add_column(
        "#",
        justify="right",
        style="yellow",
        width=5,
    )

    table.add_column(
        "IOC Type",
        width=12,
    )

    table.add_column(
        "IOC",
        ratio=2,
    )

    table.add_column(
        "Events",
        justify="right",
        width=9,
    )

    table.add_column(
        "Sources",
        justify="right",
        width=9,
    )

    table.add_column(
        "Relationship",
        width=25,
    )

    for index, finding in enumerate(
        visible_findings,
        start=start + 1,
    ):

        relationship = (
            relationship_label(
                finding.relationship
            )
        )

        table.add_row(
            str(index),
            finding.ioc_type,
            finding.value,
            f"{finding.event_count:,}",
            f"{finding.source_count:,}",
            Text(
                relationship,
                style=relationship_style(
                    finding.relationship
                ),
            ),
        )

    console.print(table)

    console.print(
        f"\n[dim]Showing {start + 1:,}–"
        f"{end:,} of {total:,} finding(s) • "
        f"Page {page}/{total_pages}[/dim]"
    )

    return visible_findings


def display_correlation_detail(
    finding: CorrelationFinding,
) -> None:

    details = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    details.add_column(
        "Field",
        style="bold cyan",
        width=22,
    )

    details.add_column(
        "Value",
        overflow="fold",
    )

    details.add_row(
        "IOC Type",
        finding.ioc_type,
    )

    details.add_row(
        "IOC",
        finding.value,
    )

    details.add_row(
        "Relationship",
        Text(
            relationship_label(
                finding.relationship
            ),
            style=relationship_style(
                finding.relationship
            ),
        ),
    )

    details.add_row(
        "Events",
        f"{finding.event_count:,}",
    )

    details.add_row(
        "Sources",
        f"{finding.source_count:,}",
    )

    details.add_row(
        "Evidence Items",
        f"{finding.evidence_count:,}",
    )

    details.add_row(
        "First Seen",
        finding.first_seen or "-",
    )

    details.add_row(
        "Last Seen",
        finding.last_seen or "-",
    )

    if finding.time_span_seconds is not None:

        details.add_row(
            "Time Span",
            f"{finding.time_span_seconds:.2f} seconds",
        )

    console.print(
        Panel(
            details,
            title="Correlation Finding",
            border_style="cyan",
        )
    )

    if finding.sources:

        source_text = "\n".join(
            f"• {source}"
            for source in finding.sources
        )

        console.print(
            Panel(
                source_text,
                title="Sources Involved",
                border_style="blue",
            )
        )

    console.print(
        Panel(
            finding.description,
            title="Assessment",
            border_style="yellow",
        )
    )

    display_evidence_timeline(
        finding
    )

    display_relationship_context(
        finding
    )

    display_evidence_drilldown(
        finding
    )

    console.print(
        "\n[dim]Correlation describes observed "
        "relationships between evidence. It does not "
        "by itself establish malicious activity.[/dim]\n"
    )


def display_evidence_timeline(
    finding: CorrelationFinding,
) -> None:

    ordered = _sort_evidence(
        finding
    )

    if not ordered:

        console.print(
            Panel(
                "[yellow]No supporting evidence is "
                "available for this finding.[/yellow]",
                title="Evidence Timeline",
                border_style="yellow",
            )
        )

        return

    table = Table(
        title="Evidence Timeline",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    table.add_column(
        "#",
        justify="right",
        width=5,
        style="yellow",
    )

    table.add_column(
        "Time",
        width=22,
    )

    table.add_column(
        "Source",
        ratio=2,
    )

    table.add_column(
        "Event Type",
        width=20,
    )

    table.add_column(
        "Evidence",
        ratio=3,
        overflow="fold",
    )

    for index, (
        _,
        evidence,
    ) in enumerate(
        ordered,
        start=1,
    ):

        description = (
            evidence.description
            or (
                f"{evidence.evidence_type}: "
                f"{evidence.value}"
            )
        )

        table.add_row(
            str(index),
            _format_timestamp(
                evidence.timestamp
            ),
            evidence.source or "-",
            _format_event_type(
                evidence
            ),
            description,
        )

    console.print(table)


def display_relationship_context(
    finding: CorrelationFinding,
) -> None:

    chain = _build_relationship_chain(
        finding
    )

    if not chain:
        return

    console.print()

    console.print(
        "[bold cyan]Relationship Context[/bold cyan]"
    )

    console.print(
        "[dim]Chronological source sequence represented "
        "by the supporting evidence.[/dim]\n"
    )

    relationship_table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    relationship_table.add_column(
        "#",
        justify="right",
        width=5,
    )

    relationship_table.add_column(
        "Source",
        ratio=3,
    )

    relationship_table.add_column(
        "Gap From Previous",
        justify="right",
        width=22,
    )

    for index, (
        source,
        gap,
    ) in enumerate(
        chain,
        start=1,
    ):

        if gap is None:
            gap_text = "-"

        elif gap < 1:
            gap_text = f"{gap:.3f}s"

        elif gap < 60:
            gap_text = f"{gap:.1f}s"

        else:
            gap_text = f"{gap / 60:.1f} min"

        relationship_table.add_row(
            str(index),
            source,
            gap_text,
        )

    console.print(
        relationship_table
    )

    chain_text = " → ".join(
        source
        for source, _ in chain
    )

    console.print(
        Panel(
            chain_text,
            title="Observed Source Flow",
            border_style="blue",
        )
    )


def display_evidence_drilldown(
    finding: CorrelationFinding,
) -> None:

    ordered = _sort_evidence(
        finding
    )

    if not ordered:
        return

    console.print()

    console.print(
        "[bold cyan]Evidence Drill-Down[/bold cyan]"
    )

    console.print(
        "[dim]Inspect the normalized event context behind "
        "a correlation finding.[/dim]\n"
    )

    while True:

        table = Table(
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )

        table.add_column(
            "#",
            justify="right",
            width=5,
        )

        table.add_column(
            "Time",
            width=22,
        )

        table.add_column(
            "Source",
            ratio=2,
        )

        table.add_column(
            "Severity",
            width=12,
        )

        table.add_column(
            "Event Type",
            width=20,
        )

        for index, (
            _,
            evidence,
        ) in enumerate(
            ordered,
            start=1,
        ):

            severity = str(
                evidence.metadata.get(
                    "severity",
                    "-",
                )
            )

            table.add_row(
                str(index),
                _format_timestamp(
                    evidence.timestamp
                ),
                evidence.source or "-",
                severity,
                _format_event_type(
                    evidence
                ),
            )

        console.print(
            table
        )

        choice = input(
            "\nEnter evidence number to inspect "
            "or press Enter to continue: "
        ).strip()

        if not choice:
            break

        if not choice.isdigit():

            console.print(
                "[red]Enter a valid evidence number.[/red]"
            )

            continue

        number = int(
            choice
        )

        if not (
            1 <= number <= len(ordered)
        ):

            console.print(
                "[red]Evidence number is out of range.[/red]"
            )

            continue

        _, evidence = ordered[
            number - 1
        ]

        display_evidence_detail(
            evidence
        )


def display_evidence_detail(
    evidence,
) -> None:

    metadata = evidence.metadata

    details = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    details.add_column(
        "Field",
        style="bold cyan",
        width=22,
    )

    details.add_column(
        "Value",
        overflow="fold",
    )

    details.add_row(
        "Evidence Type",
        evidence.evidence_type,
    )

    details.add_row(
        "IOC",
        evidence.value,
    )

    details.add_row(
        "Timestamp",
        _format_timestamp(
            evidence.timestamp
        ),
    )

    details.add_row(
        "Source",
        evidence.source or "-",
    )

    details.add_row(
        "Event ID",
        evidence.event_id or "-",
    )

    details.add_row(
        "Confidence",
        f"{evidence.confidence:.2f}",
    )

    details.add_row(
        "Event Type",
        str(
            metadata.get(
                "event_type",
                "-",
            )
        ),
    )

    details.add_row(
        "Severity",
        str(
            metadata.get(
                "severity",
                "-",
            )
        ),
    )

    details.add_row(
        "Parser",
        str(
            metadata.get(
                "parser",
                "-",
            )
        ),
    )

    details.add_row(
        "Parse Status",
        str(
            metadata.get(
                "parse_status",
                "-",
            )
        ),
    )

    console.print(
        Panel(
            details,
            title="Evidence Detail",
            border_style="cyan",
        )
    )

    display_event_context(
        metadata
    )

    console.print(
        Panel(
            evidence.description
            or "No additional evidence description.",
            title="Evidence Description",
            border_style="yellow",
        )
    )


def display_event_context(
    metadata,
) -> None:

    context_fields = [
        ("Host", "host"),
        ("User", "user"),
        ("Protocol", "protocol"),
        ("Source IP", "src_ip"),
        ("Source Port", "src_port"),
        ("Destination IP", "dst_ip"),
        ("Destination Port", "dst_port"),
        ("Domain", "domain"),
        ("URL", "url"),
        ("Process", "process"),
        ("PID", "pid"),
        ("Parent PID", "parent_pid"),
        ("Command", "command"),
        ("File Path", "file_path"),
        ("Hash", "hash_value"),
        ("Signature", "signature"),
        ("GID", "gid"),
        ("SID", "sid"),
        ("Revision", "revision"),
        ("Priority", "priority"),
        ("Action", "action"),
    ]

    available = []

    for label, key in context_fields:

        value = metadata.get(
            key
        )

        if (
            value is not None
            and str(value).strip()
        ):
            available.append(
                (
                    label,
                    str(value),
                )
            )

    if available:

        table = Table(
            title="Normalized Event Context",
            show_header=False,
            box=None,
            padding=(0, 1),
        )

        table.add_column(
            "Field",
            style="bold cyan",
            width=22,
        )

        table.add_column(
            "Value",
            overflow="fold",
        )

        for label, value in available:

            table.add_row(
                label,
                value,
            )

        console.print(
            Panel(
                table,
                border_style="blue",
            )
        )

    message = metadata.get(
        "message"
    )

    if message:

        console.print(
            Panel(
                str(message),
                title="Original Event Message",
                border_style="green",
            )
        )

    raw = metadata.get(
        "raw"
    )

    if raw:

        raw_table = Table(
            title="Source-specific Fields",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )

        raw_table.add_column(
            "Field",
            width=25,
        )

        raw_table.add_column(
            "Value",
            overflow="fold",
        )

        for key, value in raw.items():

            if isinstance(
                value,
                (dict, list, tuple),
            ):
                value = str(
                    value
                )

            raw_table.add_row(
                str(key),
                str(value),
            )

        console.print(
            raw_table
        )


def display_filter_summary(
    filter_values: dict,
    result_count: int,
    total_count: int,
) -> None:

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    table.add_column(
        "Filter",
        style="bold cyan",
        width=25,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    for key, value in filter_values.items():

        if value in (
            None,
            "",
        ):
            continue

        table.add_row(
            key,
            str(value),
        )

    table.add_row(
        "Matching findings",
        f"{result_count:,}",
    )

    table.add_row(
        "Total findings",
        f"{total_count:,}",
    )

    console.print(
        Panel(
            table,
            title="Investigation Filter",
            border_style="cyan",
        )
    )


def display_search_results(
    findings: Iterable[CorrelationFinding],
    query: str,
) -> None:

    findings = list(
        findings
    )

    if not findings:

        console.print(
            Panel(
                f"[yellow]No findings matched:[/yellow] "
                f"{query}",
                title="IOC Search",
                border_style="yellow",
            )
        )

        return

    display_correlation_findings(
        findings,
        page=1,
        page_size=20,
        title=f"IOC Search • {query}",
    )
