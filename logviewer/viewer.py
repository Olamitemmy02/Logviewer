from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table

from .analysis.events.service import EventService
from .discovery import discover_sources


console = Console()

PAGE_SIZE = 12
EVENT_DISPLAY_LIMIT = 100


STATUS_STYLES = {
    "SUPPORTED": "green",
    "PARTIAL": "yellow",
    "UNSUPPORTED": "red",
    "EMPTY": "yellow",
    "UNREADABLE": "red",
    "BACKUP": "bright_black",
    "ROTATED": "bright_black",
}


@dataclass
class JournalSource:
    """
    Logical representation of the systemd journal.

    The journal is not a normal text file. It is accessed through
    journalctl, so this object gives the Source Browser a consistent
    representation without pretending that .journal files are
    directly parsed by LogViewer.
    """

    path: str = "systemd-journal"
    name: str = "systemd-journal"
    source_type: str = "Structured systemd journal"
    status: str = "SUPPORTED"
    parser: str = "systemd-journal-json"
    description: str = (
        "Structured systemd journal accessed through journalctl."
    )
    size: int = 0
    readable: bool = True
    parse_coverage: float = 100.0
    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    is_analyzable: bool = True

    @property
    def is_journal(self):
        return True


def _format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"

    return f"{size / (1024 * 1024 * 1024):.1f} GB"


def _format_coverage(coverage):
    return f"{coverage:.2f}%"


def _status_text(status):
    style = STATUS_STYLES.get(
        status,
        "white",
    )

    return (
        f"[{style}]{status}[/{style}]"
    )


def _coverage_text(source):
    if source.total_lines == 0:
        return "-"

    coverage = source.parse_coverage

    if coverage >= 100:
        return (
            f"[green]{coverage:.2f}%[/green]"
        )

    if coverage > 0:
        return (
            f"[yellow]{coverage:.2f}%[/yellow]"
        )

    return "[red]0.00%[/red]"


def _build_summary(sources):
    counts = {
        "SUPPORTED": 0,
        "PARTIAL": 0,
        "UNSUPPORTED": 0,
        "EMPTY": 0,
        "UNREADABLE": 0,
        "BACKUP": 0,
        "ROTATED": 0,
    }

    for source in sources:
        if source.status in counts:
            counts[source.status] += 1

    return counts


def _show_summary(sources):
    counts = _build_summary(sources)

    table = Table(
        title="LOG SOURCE STATUS",
        border_style="cyan",
        expand=False,
    )

    table.add_column(
        "Status",
        style="bold",
    )

    table.add_column(
        "Count",
        justify="right",
    )

    table.add_row(
        "[green]Supported[/green]",
        str(counts["SUPPORTED"]),
    )

    table.add_row(
        "[yellow]Partial[/yellow]",
        str(counts["PARTIAL"]),
    )

    table.add_row(
        "[red]Unsupported[/red]",
        str(counts["UNSUPPORTED"]),
    )

    table.add_row(
        "[yellow]Empty[/yellow]",
        str(counts["EMPTY"]),
    )

    table.add_row(
        "[red]Unreadable[/red]",
        str(counts["UNREADABLE"]),
    )

    table.add_row(
        "[bright_black]Backup[/bright_black]",
        str(counts["BACKUP"]),
    )

    table.add_row(
        "[bright_black]Rotated[/bright_black]",
        str(counts["ROTATED"]),
    )

    console.print(table)


def _filter_sources(
    sources,
    status_filter,
    search_term,
):
    filtered = sources

    if status_filter != "ALL":
        filtered = [
            source
            for source in filtered
            if source.status
            == status_filter
        ]

    if search_term:
        search_term = (
            search_term.lower()
        )

        filtered = [
            source
            for source in filtered
            if search_term
            in str(source.path).lower()
            or search_term
            in str(source.name).lower()
            or search_term
            in str(
                source.description
            ).lower()
        ]

    return filtered


def _show_source_page(
    sources,
    page,
):
    total = len(sources)

    if total == 0:
        console.print(
            Panel(
                "[yellow]No sources match the "
                "current filters.[/yellow]",
                title="SOURCE SEARCH",
                border_style="yellow",
            )
        )
        return

    start = page * PAGE_SIZE
    end = start + PAGE_SIZE

    page_sources = sources[
        start:end
    ]

    total_pages = (
        total
        + PAGE_SIZE
        - 1
    ) // PAGE_SIZE

    table = Table(
        title=(
            f"LOG SOURCES  •  "
            f"Page {page + 1}/{total_pages}"
        ),
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "#",
        style="yellow",
        width=5,
    )

    table.add_column(
        "Source",
        style="white",
    )

    table.add_column(
        "Status",
        width=14,
    )

    table.add_column(
        "Parser",
        width=22,
    )

    table.add_column(
        "Coverage",
        justify="right",
        width=12,
    )

    table.add_column(
        "Size",
        justify="right",
        width=12,
    )

    table.add_column(
        "Analyze",
        width=10,
    )

    for index, source in enumerate(
        page_sources,
        start=1,
    ):
        global_index = (
            start + index
        )

        analyze = (
            "[green]YES[/green]"
            if source.is_analyzable
            else "[dim]NO[/dim]"
        )

        source_name = (
            source.name
            if getattr(
                source,
                "is_journal",
                False,
            )
            else str(source.path)
        )

        table.add_row(
            str(global_index),
            source_name,
            _status_text(
                source.status
            ),
            source.parser or "-",
            _coverage_text(
                source
            ),
            _format_size(
                source.size
            ),
            analyze,
        )

    console.print(table)

    console.print(
        f"\n[dim]Showing {start + 1}-"
        f"{min(end, total)} of "
        f"{total} matching sources.[/dim]"
    )


def _show_source_details(source):
    console.print()

    details = Table(
        title="SOURCE DETAILS",
        border_style="cyan",
        show_header=False,
    )

    details.add_row(
        "Path",
        str(source.path),
    )

    details.add_row(
        "Name",
        source.name,
    )

    details.add_row(
        "Type",
        source.source_type,
    )

    details.add_row(
        "Status",
        _status_text(
            source.status
        ),
    )

    details.add_row(
        "Parser",
        source.parser or "-",
    )

    details.add_row(
        "Description",
        source.description or "-",
    )

    details.add_row(
        "Size",
        (
            "N/A — structured source"
            if getattr(
                source,
                "is_journal",
                False,
            )
            else _format_size(
                source.size
            )
        ),
    )

    details.add_row(
        "Readable",
        (
            "[green]YES[/green]"
            if source.readable
            else "[red]NO[/red]"
        ),
    )

    if source.parser:
        details.add_row(
            "Parse Coverage",
            _coverage_text(
                source
            ),
        )

        details.add_row(
            "Total Entries",
            str(
                source.total_lines
            ),
        )

        details.add_row(
            "Parsed Entries",
            str(
                source.parsed_lines
            ),
        )

        details.add_row(
            "Unparsed Entries",
            str(
                source.unparsed_lines
            ),
        )

    details.add_row(
        "Analyzable",
        (
            "[green]YES[/green]"
            if source.is_analyzable
            else "[yellow]NO[/yellow]"
        ),
    )

    console.print(details)

    if getattr(
        source,
        "is_journal",
        False,
    ):
        console.print(
            Panel(
                "[green]The systemd journal is available "
                "through journalctl.[/green]\n\n"
                "LogViewer reads structured JSON records "
                "through the supported journalctl interface.\n\n"
                "[dim]The underlying .journal binary files "
                "are not parsed directly.[/dim]",
                title="SYSTEMD JOURNAL",
                border_style="green",
            )
        )

    elif source.status == "PARTIAL":
        console.print(
            Panel(
                "[yellow]This parser does not fully understand "
                "the source.[/yellow]\n\n"
                f"Parsed: {source.parsed_lines}\n"
                f"Unparsed: {source.unparsed_lines}\n"
                f"Coverage: "
                f"{_format_coverage(source.parse_coverage)}\n\n"
                "[dim]This source should be reviewed before "
                "relying on it for complete security analysis.[/dim]",
                title="PARTIAL PARSING",
                border_style="yellow",
            )
        )

    elif source.status == "SUPPORTED":
        console.print(
            Panel(
                "[green]The assigned parser successfully parsed "
                "all non-empty lines.[/green]",
                title="PARSER STATUS",
                border_style="green",
            )
        )

    elif source.status == "EMPTY":
        console.print(
            Panel(
                "[yellow]The source exists but currently "
                "contains no readable event data.[/yellow]",
                title="EMPTY SOURCE",
                border_style="yellow",
            )
        )

    elif source.status == "UNSUPPORTED":
        console.print(
            Panel(
                "[yellow]LogViewer does not currently have "
                "a parser for this source.[/yellow]",
                title="UNSUPPORTED SOURCE",
                border_style="yellow",
            )
        )


def _load_source_events(source):
    service = EventService()

    # ---------------------------------------------------------
    # systemd journal
    # ---------------------------------------------------------
    if getattr(
        source,
        "is_journal",
        False,
    ):
        console.print(
            "\n[cyan]Loading:[/cyan] systemd journal"
        )

        events = service.journal_events(
            limit=5000
        )

        if not events:
            console.print(
                Panel(
                    "[yellow]The systemd journal is available, "
                    "but no events were returned.[/yellow]",
                    title="NO JOURNAL EVENTS",
                    border_style="yellow",
                )
            )
            return

        console.print(
            f"[green]Loaded {len(events)} "
            f"journal event(s).[/green]"
        )

        _show_events(events)

        return

    # ---------------------------------------------------------
    # Normal file source
    # ---------------------------------------------------------
    if not source.is_analyzable:
        console.print(
            Panel(
                "[yellow]This source is not currently analyzable "
                "by LogViewer.[/yellow]\n\n"
                f"Status: {source.status}\n"
                f"Parser: {source.parser or 'None'}",
                title="SOURCE NOT ANALYZABLE",
                border_style="yellow",
            )
        )
        return

    console.print(
        f"\n[cyan]Loading:[/cyan] "
        f"{source.path}"
    )

    events = service.from_file(
        source.path
    )

    if not events:
        console.print(
            Panel(
                "[yellow]The source is supported, but no events "
                "were returned.[/yellow]",
                title="NO EVENTS",
                border_style="yellow",
            )
        )
        return

    console.print(
        f"[green]Loaded {len(events)} "
        f"event(s).[/green]"
    )

    _show_events(events)


def _event_sort_key(event):
    """
    Convert supported timestamps into a comparable UTC timestamp.

    Events with invalid or missing timestamps are placed last.
    """
    value = (
        event.timestamp or ""
    ).strip()

    if not value:
        return float("-inf")

    try:
        normalized = value.replace(
            "Z",
            "+00:00",
        )

        dt = datetime.fromisoformat(
            normalized,
        )

        if dt.tzinfo is None:
            dt = dt.replace(
                tzinfo=timezone.utc,
            )

        return dt.timestamp()

    except ValueError:
        return float("-inf")


def _show_events(events):
    """
    Display the newest events first.

    Processing:
        1. Sort all events chronologically.
        2. Select the newest EVENT_DISPLAY_LIMIT events.
        3. Reverse the selected window.
        4. Display newest -> oldest.
    """
    chronological_events = sorted(
        events,
        key=_event_sort_key,
    )

    newest_events = chronological_events[
        -EVENT_DISPLAY_LIMIT:
    ]

    display_events = list(
        reversed(
            newest_events
        )
    )

    table = Table(
        title=(
            f"EVENTS  •  Newest → Oldest  •  "
            f"Showing {len(display_events)} "
            f"of {len(events)}"
        ),
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "#",
        style="yellow",
        width=5,
    )

    table.add_column(
        "Timestamp",
        width=26,
    )

    table.add_column(
        "Severity",
        width=10,
    )

    table.add_column(
        "Type",
        width=20,
    )

    table.add_column(
        "Process",
        width=18,
    )

    table.add_column(
        "Message",
    )

    for index, event in enumerate(
        display_events,
        start=1,
    ):
        severity = (
            event.severity
            or "INFO"
        ).upper()

        if severity in {
            "HIGH",
            "CRITICAL",
        }:
            severity_text = (
                f"[red]{severity}[/red]"
            )

        elif severity in {
            "MEDIUM",
            "WARNING",
            "WARN",
        }:
            severity_text = (
                f"[yellow]{severity}[/yellow]"
            )

        else:
            severity_text = (
                f"[green]{severity}[/green]"
            )

        event_type = (
            event.event_type
            or "-"
        )

        process = (
            event.process
            or "-"
        )

        message = (
            event.message
            or "-"
        )

        if len(message) > 100:
            message = (
                message[:97]
                + "..."
            )

        table.add_row(
            str(index),
            event.timestamp or "-",
            severity_text,
            event_type,
            process,
            message,
        )

    console.print(table)

    if display_events:
        newest = (
            display_events[0].timestamp
            or "-"
        )

        oldest = (
            display_events[-1].timestamp
            or "-"
        )

        console.print(
            f"\n[dim]Window: "
            f"{newest} → {oldest}[/dim]"
        )

    console.print(
        "[dim]Newest available events are shown first. "
        "Events without valid timestamps are placed last.[/dim]"
    )


def _build_journal_source():
    """
    Build the logical systemd journal source.

    A small read is used to determine whether journalctl is
    available and whether the journal currently returns data.
    """
    service = EventService()

    events = service.journal_events(
        limit=1
    )

    if events:
        return JournalSource(
            status="SUPPORTED",
            readable=True,
            parse_coverage=100.0,
            total_lines=1,
            parsed_lines=1,
            unparsed_lines=0,
            is_analyzable=True,
        )

    # journalctl may be available even when no entries are
    # currently returned. Keep the logical source visible,
    # but clearly represent its current state.
    return JournalSource(
        status="EMPTY",
        readable=True,
        parse_coverage=0.0,
        total_lines=0,
        parsed_lines=0,
        unparsed_lines=0,
        is_analyzable=True,
    )


def _get_browser_sources():
    """
    Return filesystem sources plus the logical systemd journal.

    Binary .journal files remain classified by the filesystem
    source classifier, but the actual journal is represented by
    the logical journal source below.
    """
    sources = discover_sources(
        "/var/log"
    )

    journal_source = _build_journal_source()

    return [
        journal_source,
        *sources,
    ]


def _select_source(sources):
    if not sources:
        return None

    choice = IntPrompt.ask(
        "\nSelect source number",
        default=1,
    )

    if choice < 1 or choice > len(
        sources
    ):
        console.print(
            "[red]Invalid source number.[/red]"
        )
        return None

    return sources[
        choice - 1
    ]


def _source_browser():
    sources = _get_browser_sources()

    if not sources:
        console.print(
            Panel(
                "[yellow]No log sources were discovered "
                "under /var/log.[/yellow]",
                title="LOG SOURCES",
                border_style="yellow",
            )
        )
        return

    status_filter = "ALL"
    search_term = ""
    page = 0

    while True:
        filtered = _filter_sources(
            sources,
            status_filter,
            search_term,
        )

        total_pages = max(
            1,
            (
                len(filtered)
                + PAGE_SIZE
                - 1
            )
            // PAGE_SIZE,
        )

        if page >= total_pages:
            page = (
                total_pages - 1
            )

        console.clear()

        console.print(
            Panel(
                "[bold cyan]LogViewer Source Browser[/bold cyan]\n"
                "Discover, classify, and select system log sources.",
                border_style="cyan",
            )
        )

        _show_summary(
            sources
        )

        console.print()

        console.print(
            f"[dim]Filter:[/dim] "
            f"{status_filter}    "
            f"[dim]Search:[/dim] "
            f"{search_term or 'None'}"
        )

        console.print()

        _show_source_page(
            filtered,
            page,
        )

        console.print()

        console.print(
            "[cyan]Commands:[/cyan]"
        )

        console.print(
            "  [yellow]n[/yellow]  Next page"
        )

        console.print(
            "  [yellow]p[/yellow]  Previous page"
        )

        console.print(
            "  [yellow]f[/yellow]  Change status filter"
        )

        console.print(
            "  [yellow]s[/yellow]  Search sources"
        )

        console.print(
            "  [yellow]v[/yellow]  View selected source"
        )

        console.print(
            "  [yellow]q[/yellow]  Back"
        )

        command = Prompt.ask(
            "\nCommand",
            default="q",
        ).strip().lower()

        if command == "q":
            break

        if command == "n":
            if page + 1 < total_pages:
                page += 1
            else:
                console.print(
                    "[yellow]Already on the last page.[/yellow]"
                )

        elif command == "p":
            if page > 0:
                page -= 1
            else:
                console.print(
                    "[yellow]Already on the first page.[/yellow]"
                )

        elif command == "f":
            console.print(
                "\n[cyan]Status filters:[/cyan]"
            )

            console.print(
                "  ALL"
            )

            console.print(
                "  SUPPORTED"
            )

            console.print(
                "  PARTIAL"
            )

            console.print(
                "  UNSUPPORTED"
            )

            console.print(
                "  EMPTY"
            )

            console.print(
                "  UNREADABLE"
            )

            console.print(
                "  BACKUP"
            )

            console.print(
                "  ROTATED"
            )

            selected = Prompt.ask(
                "Select filter",
                default=status_filter,
            ).strip().upper()

            valid_filters = {
                "ALL",
                "SUPPORTED",
                "PARTIAL",
                "UNSUPPORTED",
                "EMPTY",
                "UNREADABLE",
                "BACKUP",
                "ROTATED",
            }

            if selected in valid_filters:
                status_filter = selected
                page = 0

            else:
                console.print(
                    "[red]Invalid status filter.[/red]"
                )

        elif command == "s":
            search_term = Prompt.ask(
                "Search source path or name",
                default=search_term,
            ).strip()

            page = 0

        elif command == "v":
            selected = _select_source(
                filtered
            )

            if selected is None:
                continue

            console.clear()

            _show_source_details(
                selected
            )

            action = Prompt.ask(
                "\nAction",
                choices=[
                    "open",
                    "back",
                ],
                default="open",
            ).lower()

            if action == "open":
                _load_source_events(
                    selected
                )

            Prompt.ask(
                "\nPress Enter to return",
                default="",
            )

        else:
            console.print(
                "[red]Unknown command.[/red]"
            )


def view_logs():
    """
    Entry point for the Log Viewer source browser.
    """
    _source_browser()
