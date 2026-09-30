from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .discovery import discover_system_logs, discover_snort_logs
from .analysis.events.service import EventService


console = Console()
event_service = EventService()


def get_search_sources():
    """
    Return searchable file-based log sources.

    systemd journal is handled separately because it is a
    structured binary journal accessed through journalctl.
    """
    sources = []
    sources.extend(discover_system_logs())
    sources.extend(discover_snort_logs())

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


def search_events(events, keyword):
    """
    Search normalized events across their available fields.
    """
    keyword = keyword.lower()
    matches = []

    for event in events:
        searchable_values = [
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
            for value in searchable_values
            if value is not None
        ).lower()

        if keyword in searchable_text:
            matches.append(event)

    return matches


def display_matches(
    matches,
    keyword,
    source_name=None,
):
    """
    Display matching events in a consistent Rich table.
    """
    if not matches:
        return

    title = f"Search Results — {keyword}"

    if source_name:
        title += f" — {source_name}"

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

    for event in matches[-100:]:
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


def search_journal(keyword):
    """
    Search recent systemd journal events.

    The journal is queried through journalctl rather than by
    reading .journal files directly.
    """
    events = event_service.journal_events(
        limit=5000
    )

    if not events:
        return []

    return search_events(
        events,
        keyword,
    )


def search_menu():
    """
    Search across normalized file logs, Snort events,
    and systemd journal events.
    """
    keyword = Prompt.ask(
        "Enter search keyword"
    ).strip()

    if not keyword:
        console.print(
            "[red]Keyword cannot be empty.[/red]"
        )
        return

    sources = get_search_sources()

    console.print()
    console.print(
        "[cyan]Searching normalized events...[/cyan]"
    )

    total_matches = 0
    searchable_sources = 0

    # ---------------------------------------------------------
    # File-based logs and Snort
    # ---------------------------------------------------------
    for source in sources:
        events = event_service.from_file(
            source
        )

        if not events:
            continue

        searchable_sources += 1

        matches = search_events(
            events,
            keyword,
        )

        if not matches:
            continue

        display_matches(
            matches,
            keyword,
            source.name,
        )

        total_matches += len(matches)

    # ---------------------------------------------------------
    # systemd journal
    # ---------------------------------------------------------
    journal_events = event_service.journal_events(
        limit=5000
    )

    if journal_events:
        searchable_sources += 1

        journal_matches = search_events(
            journal_events,
            keyword,
        )

        if journal_matches:
            display_matches(
                journal_matches,
                keyword,
                "systemd-journal",
            )

            total_matches += len(
                journal_matches
            )

    # ---------------------------------------------------------
    # Search summary
    # ---------------------------------------------------------
    console.print()

    if total_matches == 0:
        console.print(
            f"[yellow]No matches found for:[/yellow] "
            f"[bold]{keyword}[/bold]"
        )

        console.print(
            "[dim]The search completed across "
            f"{searchable_sources} readable "
            "event source(s), including the "
            "systemd journal when available.[/dim]"
        )

        return

    console.print(
        f"[green]Found {total_matches} "
        f"matching event(s).[/green]"
    )

    console.print(
        f"[dim]Searched {searchable_sources} "
        "readable event source(s).[/dim]"
    )
