from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()

LOG_DIRECTORY = Path("logs")


def statistics_dashboard():

    if not LOG_DIRECTORY.exists():

        console.print(
            "[red]Logs directory not found[/red]"
        )
        return


    logs = list(
        LOG_DIRECTORY.glob("*.log")
    )


    if not logs:

        console.print(
            Panel(
                "No log files available.",
                title="Statistics"
            )
        )

        return


    stats = {
        "files": len(logs),
        "entries": 0,
        "info": 0,
        "warning": 0,
        "error": 0,
        "critical": 0
    }


    largest_file = None
    largest_size = 0

    active_logs = {}


    for log in logs:

        count = 0

        size = log.stat().st_size


        if size > largest_size:

            largest_size = size
            largest_file = log.name


        try:

            with open(
                log,
                "r",
                errors="ignore"
            ) as file:


                for line in file:

                    count += 1
                    stats["entries"] += 1


                    upper = line.upper()


                    if "CRITICAL" in upper:
                        stats["critical"] += 1

                    elif "ERROR" in upper:
                        stats["error"] += 1

                    elif "WARNING" in upper:
                        stats["warning"] += 1

                    elif "INFO" in upper:
                        stats["info"] += 1



        except Exception as error:

            console.print(
                f"[red]{error}[/red]"
            )


        active_logs[log.name] = count



    most_active = max(
        active_logs,
        key=active_logs.get
    )


    table = Table(
        title="LOG VIEWER STATISTICS",
        border_style="cyan"
    )


    table.add_column(
        "Metric",
        style="yellow"
    )

    table.add_column(
        "Value",
        style="green"
    )


    table.add_row(
        "Log Files",
        str(stats["files"])
    )

    table.add_row(
        "Total Entries",
        str(stats["entries"])
    )

    table.add_row(
        "INFO",
        str(stats["info"])
    )

    table.add_row(
        "WARNING",
        str(stats["warning"])
    )

    table.add_row(
        "ERROR",
        str(stats["error"])
    )

    table.add_row(
        "CRITICAL",
        str(stats["critical"])
    )

    table.add_row(
        "Largest Log",
        str(largest_file)
    )

    table.add_row(
        "Most Active Log",
        str(most_active)
    )


    console.print(table)
