from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


IOC_LABELS = {
    "ipv4": "IPv4 Addresses",
    "domain": "Domains",
    "url": "URLs",
    "sha256": "SHA-256 Hashes",
    "sha1": "SHA-1 Hashes",
    "md5": "MD5 Hashes",
}


def display_iocs(iocs: Dict[str, List[str]]) -> None:
    """
    Display extracted IOCs in a clean, user-friendly format.
    """

    total = sum(len(values) for values in iocs.values())

    if total == 0:
        console.print(
            Panel(
                "[yellow]No indicators of compromise detected.[/yellow]",
                title="IOC Analysis",
                border_style="yellow",
            )
        )
        return

    table = Table(
        title="Indicators of Compromise",
        show_header=True,
        header_style="bold",
    )

    table.add_column("Type", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right")

    for ioc_type, values in iocs.items():
        if not values:
            continue

        label = IOC_LABELS.get(ioc_type, ioc_type.title())

        for index, value in enumerate(values):
            table.add_row(
                label,
                value,
                str(len(values)) if index == 0 else "",
            )

    console.print(
        Panel(
            table,
            title=f"IOC Analysis • {total} indicator(s)",
            border_style="cyan",
        )
    )
