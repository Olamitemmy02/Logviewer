from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel


console = Console()


LOG_DIRECTORY = Path("logs")



def get_logs():

    """
    Find all log files.
    """

    if not LOG_DIRECTORY.exists():

        LOG_DIRECTORY.mkdir()

        return []


    return list(
        LOG_DIRECTORY.glob("*.log")
    )



def search_file(log_file, keyword):

    """
    Search inside one log file.
    """

    results = []


    try:

        with open(
            log_file,
            "r",
            errors="ignore"
        ) as file:


            for number, line in enumerate(
                file,
                start=1
            ):

                if keyword.lower() in line.lower():

                    results.append(
                        (
                            number,
                            line.strip()
                        )
                    )


    except Exception as error:

        console.print(
            f"[red]Error:[/red] {error}"
        )


    return results



def display_results(results, filename):

    """
    Display search results.
    """

    if not results:

        console.print(
            Panel(
                "No matching results found.",
                title="Search",
                border_style="red"
            )
        )

        return



    table = Table(
        title=f"Results: {filename}",
        border_style="cyan"
    )


    table.add_column(
        "Line",
        style="yellow"
    )


    table.add_column(
        "Content",
        style="white"
    )


    for line_number, content in results:

        table.add_row(
            str(line_number),
            content
        )


    console.print(table)



def search_all_logs(keyword):

    """
    Search every log file.
    """

    logs = get_logs()


    if not logs:

        console.print(
            "[red]No log files available[/red]"
        )

        return



    total = 0


    for log in logs:

        results = search_file(
            log,
            keyword
        )


        if results:

            display_results(
                results,
                log.name
            )

            total += len(results)



    console.print(
        f"\n[green]Found {total} matches[/green]"
    )



def search_menu():

    """
    Search interface.
    """


    keyword = Prompt.ask(
        "Enter search keyword"
    )


    if not keyword:

        console.print(
            "[red]Keyword cannot be empty[/red]"
        )

        return



    search_all_logs(
        keyword
    )
