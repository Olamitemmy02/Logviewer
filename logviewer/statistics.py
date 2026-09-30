from collections import Counter
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.table import Table

from .discovery import (
    discover_system_logs,
    discover_snort_logs,
)
from .analysis.events.service import EventService


console = Console()
event_service = EventService()


def get_statistics_sources():
    """
    Return real file-based log sources used by Statistics.

    Backup files are excluded. systemd journal is handled
    separately through journalctl.
    """
    sources = []

    sources.extend(
        discover_system_logs()
    )

    sources.extend(
        discover_snort_logs()
    )

    unique_sources = set()

    for source in sources:
        path = Path(source)

        if not path.is_file():
            continue

        if path.name.lower().endswith(
            (
                ".backup",
                ".bak",
                ".old",
                ".orig",
                ".save",
            )
        ):
            continue

        unique_sources.add(path)

    return sorted(
        unique_sources,
        key=lambda path: str(path).lower(),
    )


def load_statistics_events():
    """
    Load normalized events from file logs, Snort,
    and the systemd journal.

    Returns:
        tuple:
            events
            readable_file_sources
            journal_available
    """
    events = []
    readable_file_sources = 0

    for source in get_statistics_sources():
        source_events = event_service.from_file(
            source
        )

        if not source_events:
            continue

        readable_file_sources += 1
        events.extend(source_events)

    journal_events = event_service.journal_events(
        limit=5000
    )

    journal_available = bool(
        journal_events
    )

    if journal_events:
        events.extend(
            journal_events
        )

    events = event_service.sort_events(
        events
    )

    return (
        events,
        readable_file_sources,
        journal_available,
    )


def calculate_statistics(
    events: Iterable,
):
    """
    Calculate normalized event statistics.
    """
    events = list(events)

    severity_counts = Counter()
    source_counts = Counter()
    event_type_counts = Counter()
    parser_counts = Counter()
    process_counts = Counter()
    host_counts = Counter()
    user_counts = Counter()

    parsed_count = 0
    unparsed_count = 0
    timestamped_count = 0
    untimestamped_count = 0

    for event in events:
        severity = (
            event.severity
            or "INFO"
        ).upper()

        source = (
            event.source
            or "unknown"
        )

        event_type = (
            event.event_type
            or "unknown"
        )

        parser = (
            event.parser
            or "unknown"
        )

        process = (
            event.process
            or "unknown"
        )

        host = (
            event.host
            or "unknown"
        )

        user = (
            event.user
            or "unknown"
        )

        severity_counts[
            severity
        ] += 1

        source_counts[
            source
        ] += 1

        event_type_counts[
            event_type
        ] += 1

        parser_counts[
            parser
        ] += 1

        process_counts[
            process
        ] += 1

        host_counts[
            host
        ] += 1

        user_counts[
            user
        ] += 1

        if (
            event.parse_status
            == "parsed"
        ):
            parsed_count += 1
        else:
            unparsed_count += 1

        if (
            event.timestamp
            and event.timestamp.strip()
        ):
            timestamped_count += 1
        else:
            untimestamped_count += 1

    return {
        "total_events": len(events),
        "severity": severity_counts,
        "source": source_counts,
        "event_type": event_type_counts,
        "parser": parser_counts,
        "process": process_counts,
        "host": host_counts,
        "user": user_counts,
        "parsed": parsed_count,
        "unparsed": unparsed_count,
        "timestamped": timestamped_count,
        "untimestamped": untimestamped_count,
    }


def _display_counter(
    title,
    counter,
    key_name,
    value_name="Count",
    limit=20,
):
    """
    Display a Counter using a consistent table style.
    """
    table = Table(
        title=title,
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        key_name,
        style="cyan",
        overflow="fold",
    )

    table.add_column(
        value_name,
        style="yellow",
        justify="right",
        no_wrap=True,
    )

    for key, value in counter.most_common(
        limit
    ):
        table.add_row(
            str(key),
            str(value),
        )

    console.print(table)


def display_overview(
    statistics,
    readable_file_sources=0,
    journal_available=False,
):
    """
    Display the main Statistics overview.
    """
    table = Table(
        title="LogViewer Statistics — Overview",
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "Metric",
        style="cyan",
    )

    table.add_column(
        "Value",
        style="yellow",
        justify="right",
    )

    table.add_row(
        "Total events",
        str(
            statistics[
                "total_events"
            ]
        ),
    )

    table.add_row(
        "Parsed events",
        str(
            statistics[
                "parsed"
            ]
        ),
    )

    table.add_row(
        "Unparsed events",
        str(
            statistics[
                "unparsed"
            ]
        ),
    )

    table.add_row(
        "Timestamped events",
        str(
            statistics[
                "timestamped"
            ]
        ),
    )

    table.add_row(
        "Untimestamped events",
        str(
            statistics[
                "untimestamped"
            ]
        ),
    )

    table.add_row(
        "Readable file sources",
        str(
            readable_file_sources
        ),
    )

    table.add_row(
        "systemd journal",
        (
            "AVAILABLE"
            if journal_available
            else "NO DATA"
        ),
    )

    console.print(table)


def display_severity_statistics(
    statistics,
):
    _display_counter(
        "Events by Severity",
        statistics["severity"],
        "Severity",
    )


def display_source_statistics(
    statistics,
):
    """
    Display event sources.

    systemd journal is shown as its own logical source
    rather than exposing .journal storage files.
    """
    display_counter = Counter()

    for source, count in (
        statistics["source"].items()
    ):
        if source == "systemd-journal":
            display_counter[
                "systemd-journal"
            ] += count
            continue

        display_counter[
            source
        ] += count

    table = Table(
        title="Events by Source",
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "Source",
        style="blue",
        overflow="fold",
    )

    table.add_column(
        "Events",
        style="yellow",
        justify="right",
    )

    for source, count in (
        display_counter.most_common()
    ):
        display_name = source

        if source != "systemd-journal":
            display_name = Path(
                source
            ).name

        table.add_row(
            display_name,
            str(count),
        )

    console.print(table)


def display_event_type_statistics(
    statistics,
):
    _display_counter(
        "Events by Type",
        statistics["event_type"],
        "Event Type",
    )


def display_parser_statistics(
    statistics,
):
    _display_counter(
        "Events by Parser",
        statistics["parser"],
        "Parser",
    )


def display_process_statistics(
    statistics,
):
    _display_counter(
        "Events by Process",
        statistics["process"],
        "Process",
    )


def display_host_statistics(
    statistics,
):
    _display_counter(
        "Events by Host",
        statistics["host"],
        "Host",
    )


def display_user_statistics(
    statistics,
):
    _display_counter(
        "Events by User",
        statistics["user"],
        "User",
    )


def statistics_menu():
    """
    Main Statistics dashboard.
    """
    console.print()

    console.print(
        "[cyan]Loading normalized event statistics...[/cyan]"
    )

    (
        events,
        readable_file_sources,
        journal_available,
    ) = load_statistics_events()

    if not events:
        console.print()
        console.print(
            "[yellow]No analyzable events were found.[/yellow]"
        )

        if journal_available:
            console.print(
                "[dim]The systemd journal is available, "
                "but no events were returned.[/dim]"
            )

        return

    statistics = calculate_statistics(
        events
    )

    console.print()

    display_overview(
        statistics,
        readable_file_sources,
        journal_available,
    )

    console.print()

    display_severity_statistics(
        statistics
    )

    console.print()

    display_source_statistics(
        statistics
    )

    console.print()

    display_event_type_statistics(
        statistics
    )

    console.print()

    display_parser_statistics(
        statistics
    )

    console.print()

    display_process_statistics(
        statistics
    )

    console.print()

    display_host_statistics(
        statistics
    )

    console.print()

    display_user_statistics(
        statistics
    )


def statistics_dashboard():
    """
    Compatibility wrapper used by the main menu.
    """
    statistics_menu()
