from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from logviewer.events import Event


console = Console()


SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "WARNING": "yellow",
    "INFO": "green",
    "LOW": "cyan",
}


def severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get(
        severity.upper(),
        "white",
    )


def format_timestamp(timestamp: str) -> str:
    if not timestamp:
        return "-"

    try:
        value = datetime.fromisoformat(timestamp)
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp


def display_event(event: Event) -> None:
    """
    Display one normalized event in a human-friendly format.
    """

    severity = event.severity.upper()

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    table.add_column(
        "Field",
        style="bold cyan",
        width=14,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    table.add_row(
        "Severity",
        Text(
            severity,
            style=severity_style(severity),
        ),
    )

    table.add_row(
        "Timestamp",
        format_timestamp(event.timestamp),
    )

    table.add_row(
        "Source",
        str(event.source or "-"),
    )

    table.add_row(
        "Host",
        str(event.host or "-"),
    )

    table.add_row(
        "Process",
        str(event.process or "-"),
    )

    table.add_row(
        "PID",
        str(event.pid) if event.pid is not None else "-",
    )

    if event.user:
        table.add_row("User", event.user)

    if event.protocol:
        table.add_row("Protocol", event.protocol)

    if event.source_endpoint != "-":
        table.add_row(
            "Source",
            event.source_endpoint,
        )

    if event.destination_endpoint != "-":
        table.add_row(
            "Destination",
            event.destination_endpoint,
        )

    if event.signature:
        table.add_row(
            "Signature",
            event.signature,
        )

    if event.sid is not None:
        table.add_row(
            "SID",
            str(event.sid),
        )

    if event.action:
        table.add_row(
            "Action",
            event.action,
        )

    console.print(
        Panel(
            table,
            title="LogViewer • Event Details",
            border_style="cyan",
        )
    )

    console.print(
        Panel(
            event.message or "-",
            title="Message",
            border_style="dim",
        )
    )


def display_events(
    events: Iterable[Event],
    title: str = "LogViewer • Events",
) -> None:
    """
    Display multiple normalized events in a compact table.
    """

    events = list(events)

    if not events:
        console.print(
            Panel(
                "[yellow]No events available.[/yellow]\n\n"
                "The selected source did not return any "
                "normalized events.",
                title="LogViewer",
                border_style="yellow",
            )
        )
        return

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    table.add_column("Time", min_width=19)
    table.add_column("Severity", min_width=9)
    table.add_column("Source", min_width=20)
    table.add_column("Process", min_width=12)
    table.add_column("PID", justify="right", min_width=7)
    table.add_column("Message", ratio=1)

    for event in events:

        severity = event.severity.upper()

        table.add_row(
            format_timestamp(event.timestamp),
            Text(
                severity,
                style=severity_style(severity),
            ),
            str(event.source or "-"),
            str(event.process or "-"),
            str(event.pid) if event.pid is not None else "-",
            event.message or "-",
        )

    console.print(table)

    console.print(
        f"\n[dim]Showing {len(events)} event(s)[/dim]"
    )
