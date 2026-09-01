from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .snort.reader import read_snort_events, get_snort_log
from .snort.analyzer import summary


console = Console()


def show_snort_summary():

    events = read_snort_events()

    log_file = get_snort_log()

    if not events:

        console.print(
            Panel(
                "No Snort alerts were found.",
                title="SNORT SUMMARY",
                border_style="yellow"
            )
        )

        if log_file:
            console.print(
                f"[dim]Checked: {log_file}[/dim]"
            )

        return

    data = summary(events)

    console.print(
        Panel(
            f"[bold]Total Alerts:[/bold] {data['total']}\n"
            f"[bold]Unique SIDs:[/bold] {data['unique_sids']}\n"
            f"[bold]Log File:[/bold] {log_file}",
            title="SNORT SUMMARY",
            border_style="cyan"
        )
    )

    # Protocols

    table = Table(
        title="Protocol Distribution"
    )

    table.add_column("Protocol")
    table.add_column("Alerts", justify="right")

    for protocol, count in data["protocols"].most_common():

        table.add_row(
            str(protocol),
            str(count)
        )

    console.print(table)

    # Priorities

    table = Table(
        title="Alert Priorities"
    )

    table.add_column("Priority")
    table.add_column("Alerts", justify="right")

    for priority, count in data["priorities"].most_common():

        table.add_row(
            str(priority),
            str(count)
        )

    console.print(table)

    # Signatures

    table = Table(
        title="Top Signatures"
    )

    table.add_column("Signature")
    table.add_column("Alerts", justify="right")

    for signature, count in data["signatures"].most_common(10):

        table.add_row(
            str(signature),
            str(count)
        )

    console.print(table)

    # Recent events

    table = Table(
        title="Recent Snort Alerts"
    )

    table.add_column("Time")
    table.add_column("SID")
    table.add_column("Protocol")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Message")

    for event in events[-20:]:

        table.add_row(
            event.timestamp,
            str(event.sid or "-"),
            event.protocol or "-",
            event.source_endpoint,
            event.destination_endpoint,
            event.message,
        )

    console.print(table)

    # Actions

    table = Table(
        title="Actions"
    )

    table.add_column("Action")
    table.add_column("Count", justify="right")

    for action, count in data["actions"].most_common():

        table.add_row(
            str(action),
            str(count)
        )

    console.print(table)

