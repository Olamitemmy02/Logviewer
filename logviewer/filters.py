from pathlib import Path
from typing import Iterable, List

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .discovery import (
    discover_system_logs,
    discover_snort_logs,
)
from .analysis.events.service import EventService


console = Console()
event_service = EventService()


def get_filter_sources():
    """
    Return real file-based sources used by Filters.

    systemd journal is handled separately through journalctl.
    Backup files are excluded.
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


def load_all_events():
    """
    Load normalized events from file logs, Snort,
    and the systemd journal.
    """
    events = []

    for source in get_filter_sources():
        source_events = event_service.from_file(
            source
        )

        if source_events:
            events.extend(
                source_events
            )

    journal_events = event_service.journal_events(
        limit=5000
    )

    if journal_events:
        events.extend(
            journal_events
        )

    return event_service.sort_events(
        events
    )


def filter_by_severity(
    events: Iterable,
    severity: str,
) -> List:
    """
    Filter events by normalized severity.
    """
    return event_service.filter_by_severity(
        events,
        severity,
    )


def filter_by_event_type(
    events: Iterable,
    event_type: str,
) -> List:
    """
    Filter events by event type.
    """
    event_type = event_type.lower()

    return [
        event
        for event in events
        if (
            event.event_type
            or ""
        ).lower()
        == event_type
    ]


def filter_by_keyword(
    events: Iterable,
    keyword: str,
) -> List:
    """
    Search normalized event fields for a keyword.
    """
    keyword = keyword.lower()

    matches = []

    for event in events:
        values = [
            event.timestamp,
            event.source,
            event.severity,
            event.message,
            event.event_type,
            event.host,
            event.user,
            event.protocol,
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.domain,
            event.url,
            event.process,
            event.pid,
            event.parent_pid,
            event.command,
            event.file_path,
            event.hash_value,
            event.signature,
            event.gid,
            event.sid,
            event.revision,
            event.priority,
            event.action,
        ]

        searchable_text = " ".join(
            str(value)
            for value in values
            if value is not None
        ).lower()

        if keyword in searchable_text:
            matches.append(event)

    return matches


def display_events(
    events,
    title="Filtered Events",
):
    """
    Display filtered normalized events.
    """
    events = list(events)

    if not events:
        console.print(
            "[yellow]No matching events found.[/yellow]"
        )
        return

    table = Table(
        title=title,
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "Time",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Severity",
        style="yellow",
        no_wrap=True,
    )

    table.add_column(
        "Type",
        style="magenta",
        no_wrap=True,
    )

    table.add_column(
        "Source",
        style="blue",
        no_wrap=True,
    )

    table.add_column(
        "Message",
        overflow="fold",
    )

    for event in events[-100:]:
        source = event.source or "-"

        if source != "systemd-journal":
            source = Path(source).name

        table.add_row(
            event.timestamp or "-",
            event.severity or "INFO",
            event.event_type or "-",
            source,
            event.message or "-",
        )

    console.print(table)

    console.print(
        f"\n[green]Matching events: "
        f"{len(events)}[/green]"
    )


def severity_filter_menu():
    """
    Filter all available events by severity.
    """
    events = load_all_events()

    if not events:
        console.print(
            "[yellow]No analyzable events found.[/yellow]"
        )
        return

    severity = Prompt.ask(
        "Enter severity "
        "(DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)"
    ).strip().upper()

    if not severity:
        console.print(
            "[red]Severity cannot be empty.[/red]"
        )
        return

    matches = filter_by_severity(
        events,
        severity,
    )

    display_events(
        matches,
        f"Severity Filter — {severity}",
    )


def keyword_filter_menu():
    """
    Filter all available events by keyword.
    """
    events = load_all_events()

    if not events:
        console.print(
            "[yellow]No analyzable events found.[/yellow]"
        )
        return

    keyword = Prompt.ask(
        "Enter keyword"
    ).strip()

    if not keyword:
        console.print(
            "[red]Keyword cannot be empty.[/red]"
        )
        return

    matches = filter_by_keyword(
        events,
        keyword,
    )

    display_events(
        matches,
        f"Keyword Filter — {keyword}",
    )


def event_type_filter_menu():
    """
    Filter all available events by exact event type.
    """
    events = load_all_events()

    if not events:
        console.print(
            "[yellow]No analyzable events found.[/yellow]"
        )
        return

    event_types = sorted(
        {
            (
                event.event_type
                or ""
            ).strip()
            for event in events
            if (
                event.event_type
                or ""
            ).strip()
        },
        key=str.lower,
    )

    if not event_types:
        console.print(
            "[yellow]No event types are currently available.[/yellow]"
        )
        return

    table = Table(
        title="Available Event Types",
        border_style="cyan",
    )

    table.add_column(
        "#",
        style="cyan",
        justify="right",
        no_wrap=True,
    )

    table.add_column(
        "Event Type",
        style="magenta",
    )

    for index, event_type in enumerate(
        event_types,
        start=1,
    ):
        table.add_row(
            str(index),
            event_type,
        )

    console.print(table)

    choice = Prompt.ask(
        "Enter event type"
    ).strip()

    if not choice:
        console.print(
            "[red]Event type cannot be empty.[/red]"
        )
        return

    selected_type = None

    if choice.isdigit():
        index = int(choice)

        if 1 <= index <= len(
            event_types
        ):
            selected_type = (
                event_types[index - 1]
            )
    else:
        for event_type in event_types:
            if (
                event_type.lower()
                == choice.lower()
            ):
                selected_type = event_type
                break

    if selected_type is None:
        console.print(
            "[red]Invalid event type.[/red]"
        )
        return

    matches = filter_by_event_type(
        events,
        selected_type,
    )

    display_events(
        matches,
        f"Event Type Filter — {selected_type}",
    )


def filter_menu():
    """
    Main Filters menu.
    """
    while True:
        console.print()

        table = Table(
            title="LogViewer Filters",
            border_style="cyan",
            expand=True,
        )

        table.add_column(
            "Option",
            style="cyan",
            justify="center",
            no_wrap=True,
        )

        table.add_column(
            "Filter",
            style="white",
        )

        table.add_row(
            "1",
            "Filter by Severity",
        )

        table.add_row(
            "2",
            "Filter by Keyword",
        )

        table.add_row(
            "3",
            "Filter by Event Type",
        )

        table.add_row(
            "0",
            "Back",
        )

        console.print(table)

        choice = Prompt.ask(
            "Select option"
        ).strip()

        if choice == "1":
            severity_filter_menu()

        elif choice == "2":
            keyword_filter_menu()

        elif choice == "3":
            event_type_filter_menu()

        elif choice == "0":
            return

        else:
            console.print(
                "[red]Invalid option.[/red]"
            )
