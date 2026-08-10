from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel

console = Console()

LOG_DIRECTORY = Path("logs")


def get_logs():
    """
    Return every .log file in the logs directory.
    """
    if not LOG_DIRECTORY.exists():
        LOG_DIRECTORY.mkdir()
        return []

    return list(LOG_DIRECTORY.glob("*.log"))


def filter_logs(keyword):

    logs = get_logs()

    if not logs:
        console.print("[red]No log files found.[/red]")
        return

    table = Table(
        title=f"Filter Results ({keyword})",
        border_style="cyan"
    )

    table.add_column("File", style="green")
    table.add_column("Line", style="yellow")
    table.add_column("Entry", style="white")

    matches = 0

    for log in logs:

        try:

            with open(log, "r", errors="ignore") as file:

                for line_number, line in enumerate(file, start=1):

                    if keyword.lower() in line.lower():

                        matches += 1

                        table.add_row(
                            log.name,
                            str(line_number),
                            line.strip()
                        )

        except Exception as e:

            console.print(f"[red]{e}[/red]")

    if matches == 0:

        console.print(
            Panel(
                "No matching log entries.",
                title="Log Viewer",
                border_style="red"
            )
        )

    else:

        console.print(table)

        console.print(
            f"\n[bold green]Total Matches:[/bold green] {matches}"
        )


def filter_menu():

    while True:

        console.print()

        table = Table(
            title="Log Filters",
            border_style="cyan"
        )

        table.add_column("Option", style="yellow")
        table.add_column("Description", style="green")

        table.add_row("1", "INFO")
        table.add_row("2", "WARNING")
        table.add_row("3", "ERROR")
        table.add_row("4", "Custom Keyword")
        table.add_row("5", "Filter by Date")
        table.add_row("0", "Back")

        console.print(table)

        choice = Prompt.ask("Select option")

        if choice == "1":
            filter_logs("INFO")

        elif choice == "2":
            filter_logs("WARNING")

        elif choice == "3":
            filter_logs("ERROR")

        elif choice == "4":

            keyword = Prompt.ask("Keyword")

            filter_logs(keyword)

        elif choice == "5":

            date = Prompt.ask(
                "Date (YYYY-MM-DD)"
            )

            filter_logs(date)

        elif choice == "0":

            break

        else:

            console.print(
                "[red]Invalid option[/red]"
            )
