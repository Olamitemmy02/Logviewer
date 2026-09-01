from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .constants import MAX_RECENT_ALERTS


console = Console()


def display_summary(alerts, statistics):

    if not alerts:

        console.print(
            Panel(
                "No Snort alerts were found.",
                title="SNORT SUMMARY",
                border_style="yellow"
            )
        )

        return

    console.print(
        Panel(
            f"[bold]Total Alerts:[/bold] "
            f"{statistics['total']}\n"
            f"[bold]Unique SIDs:[/bold] "
            f"{statistics['unique_sids']}",
            title="SNORT SUMMARY",
            border_style="cyan"
        )
    )

    display_protocols(
        statistics["protocols"]
    )

    display_priorities(
        statistics["priorities"]
    )

    display_sources(
       statistics["sources"]
    )

    display_destinations(
       statistics["destinations"]
    )

    display_ports(
       statistics["destination_ports"]
    )

    display_connections(
       statistics["connections"]
    )

    display_actions(
       statistics["actions"]
    )

    display_signatures(
        statistics["signatures"]
    )

    display_recent_alerts(
        alerts
    )


def display_protocols(protocols):

    table = Table(
        title="Protocol Distribution"
    )

    table.add_column("Protocol")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for protocol, count in protocols.most_common():

        table.add_row(
            protocol,
            str(count)
        )

    console.print(table)


def display_priorities(priorities):

    table = Table(
        title="Alert Priorities"
    )

    table.add_column("Priority")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for priority, count in sorted(
        priorities.items()
    ):

        table.add_row(
            priority,
            str(count)
        )

    console.print(table)

def display_sources(sources):

    table = Table(
        title="Top Source IPs"
    )

    table.add_column("Source IP")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for source, count in sources.most_common(10):

        table.add_row(
            source,
            str(count)
        )

    console.print(table)


def display_destinations(destinations):

    table = Table(
        title="Top Destination IPs"
    )

    table.add_column("Destination IP")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for destination, count in destinations.most_common(10):

        table.add_row(
            destination,
            str(count)
        )

    console.print(table)


def display_ports(destination_ports):

    table = Table(
        title="Top Destination Ports"
    )

    table.add_column("Port")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for port, count in destination_ports.most_common(10):

        table.add_row(
            port,
            str(count)
        )

    console.print(table)


def display_connections(connections):

    table = Table(
        title="Top Network Connections"
    )

    table.add_column("Source → Destination")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for connection, count in connections.most_common(10):

        table.add_row(
            connection,
            str(count)
        )

    console.print(table)


def display_actions(actions):

    table = Table(
        title="Actions"
    )

    table.add_column("Action")
    table.add_column(
        "Count",
        justify="right"
    )

    for action, count in actions.most_common():

        table.add_row(
            action,
            str(count)
        )

    console.print(table)

def display_signatures(signatures):

    table = Table(
        title="Top Signatures"
    )

    table.add_column("Signature")
    table.add_column(
        "Alerts",
        justify="right"
    )

    for signature, count in signatures.most_common(10):

        table.add_row(
            signature,
            str(count)
        )

    console.print(table)


def display_recent_alerts(alerts):

    table = Table(
        title="Recent Snort Alerts"
    )

    table.add_column("Time")
    table.add_column("SID")
    table.add_column("Protocol")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Message")

    for alert in alerts[-MAX_RECENT_ALERTS:]:

        table.add_row(
            alert["timestamp"],
            alert["sid"],
            alert["protocol"],
            alert["source"],
            alert["destination"],
            alert["message"]
        )

    console.print(table)
