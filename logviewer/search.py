from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from .discovery import discover_system_logs, discover_snort_logs


console = Console()


def get_search_sources():

    sources = []

    sources.extend(
        discover_system_logs()
    )

    sources.extend(
        discover_snort_logs()
    )

    return sorted(set(sources))


def search_file(path, keyword):

    matches = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                if keyword.lower() in line.lower():

                    matches.append(
                        (
                            line_number,
                            line.rstrip()
                        )
                    )

    except (PermissionError, OSError):
        return []

    return matches


def search_menu():

    keyword = Prompt.ask(
        "Enter search keyword"
    ).strip()

    if not keyword:

        console.print(
            "[red]Keyword cannot be empty[/red]"
        )

        return

    sources = get_search_sources()

    if not sources:

        console.print(
            "[yellow]No log sources found.[/yellow]"
        )

        return

    total = 0

    for source in sources:

        matches = search_file(
            source,
            keyword
        )

        if not matches:
            continue

        table = Table(
            title=f"Matches: {Path(source).name}"
        )

        table.add_column(
            "Line",
            style="yellow"
        )

        table.add_column(
            "Content"
        )

        for line_number, content in matches[-50:]:

            table.add_row(
                str(line_number),
                content
            )

        console.print(table)

        total += len(matches)

    if total == 0:

        console.print(
            f"[yellow]No matches found for: {keyword}[/yellow]"
        )

    else:

        console.print(
            f"\n[green]Total matches: {total}[/green]"
        )
