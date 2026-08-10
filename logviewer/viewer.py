from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel


console = Console()


# Location of log files
LOG_DIRECTORY = Path("logs")



def get_log_files():
    """
    Finds all .log files inside the logs folder.
    """

    if not LOG_DIRECTORY.exists():

        LOG_DIRECTORY.mkdir()

        return []


    return list(
        LOG_DIRECTORY.glob("*.log")
    )



def show_log_list():

    """
    Displays available log files.
    """

    logs = get_log_files()


    if not logs:

        console.print(
            Panel(
                "No log files found.\n"
                "Place .log files inside the logs folder.",
                title="Log Viewer",
                border_style="red"
            )
        )

        return None



    table = Table(
        title="Available Logs",
        border_style="cyan"
    )


    table.add_column(
        "ID",
        style="yellow"
    )


    table.add_column(
        "Log File",
        style="green"
    )


    for index, log in enumerate(logs, start=1):

        table.add_row(
            str(index),
            log.name
        )


    console.print(table)


    return logs



def read_log_file(log_file):

    """
    Reads and displays the selected log file.
    """

    try:

        with open(
            log_file,
            "r",
            errors="ignore"
        ) as file:

            lines = file.readlines()


        table = Table(
            title=log_file.name,
            border_style="blue"
        )


        table.add_column(
            "Line",
            style="yellow"
        )


        table.add_column(
            "Content",
            style="white"
        )


        for number, line in enumerate(lines, start=1):

            table.add_row(
                str(number),
                line.strip()
            )


        console.print(table)


    except Exception as error:

        console.print(
            f"[red]Error reading file:[/red] {error}"
        )



def view_logs():

    """
    Main viewer function.
    """

    logs = show_log_list()


    if not logs:

        return



    choice = Prompt.ask(
        "Select log number"
    )


    try:

        selected = logs[
            int(choice)-1
        ]


        read_log_file(
            selected
        )


    except (ValueError, IndexError):

        console.print(
            "[red]Invalid selection[/red]"
        )
