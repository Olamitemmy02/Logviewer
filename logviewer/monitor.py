from pathlib import Path
import time

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

LOG_DIRECTORY = Path("logs")


def get_logs():
    if not LOG_DIRECTORY.exists():
        LOG_DIRECTORY.mkdir()
        return []

    return list(LOG_DIRECTORY.glob("*.log"))


def color_line(line: str) -> str:
    upper = line.upper()

    if "ERROR" in upper:
        return f"[bold red]{line}[/bold red]"

    if "WARNING" in upper:
        return f"[bold yellow]{line}[/bold yellow]"

    if "INFO" in upper:
        return f"[bold green]{line}[/bold green]"

    return line


def monitor_log(log_file):

    console.print(
        Panel(
            f"Monitoring: {log_file.name}\n\nPress Ctrl+C to stop.",
            title="Live Monitor",
            border_style="green"
        )
    )

    try:

        with open(log_file, "r", errors="ignore") as file:

            file.seek(0, 2)

            while True:

                line = file.readline()

                if not line:

                    time.sleep(0.5)
                    continue

                console.print(
                    color_line(line.rstrip())
                )

    except KeyboardInterrupt:

        console.print(
            "\n[bold yellow]Monitoring stopped.[/bold yellow]"
        )


def monitor_menu():

    logs = get_logs()

    if not logs:

        console.print(
            "[red]No log files found.[/red]"
        )

        return

    console.print("\n[bold cyan]Available Logs[/bold cyan]\n")

    for index, log in enumerate(logs, start=1):

        console.print(
            f"[yellow]{index}[/yellow] {log.name}"
        )

    choice = Prompt.ask(
        "Select log"
    )

    try:

        selected = logs[int(choice) - 1]

        monitor_log(selected)

    except (ValueError, IndexError):

        console.print(
            "[red]Invalid selection[/red]"
        )

