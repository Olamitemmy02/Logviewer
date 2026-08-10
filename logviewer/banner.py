from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich.progress import Progress

from pyfiglet import figlet_format

import time
import platform


console = Console()


def show_banner():

    # Large ASCII logo
    logo = figlet_format(
        "LOG VIEWER",
        font="slant"
    )


    banner_text = Text()

    banner_text.append(
        logo,
        style="bold cyan"
    )


    banner_text.append(
        "\n\n"
        "  Security Log Management Console\n",
        style="bold green"
    )


    banner_text.append(
        "  Defensive Monitoring Framework v1.0\n",
        style="bold yellow"
    )


    banner_text.append(
        "\n  Developed for Security Operations\n",
        style="bold magenta"
    )


    console.print(
        Panel(
            Align.center(banner_text),
            title="[bold red]LOG VIEWER[/bold red]",
            subtitle="[bold cyan]Cyber Security Toolkit[/bold cyan]",
            border_style="bright_blue",
            padding=(1, 4)
        )
    )



def loading():

    console.print(
        "\n[bold cyan]Starting Log Viewer Engine...[/bold cyan]\n"
    )


    modules = [
        "Core Engine",
        "Log Parser",
        "Search System",
        "Filter Engine",
        "Export Manager",
        "Statistics Module"
    ]


    with Progress() as progress:

        task = progress.add_task(
            "[cyan]Loading modules",
            total=len(modules)
        )


        for module in modules:

            time.sleep(0.4)

            progress.update(
                task,
                advance=1
            )

            console.print(
                f"[green]✓ {module} loaded[/green]"
            )


    console.print(
        "\n[bold green]✔ All Systems Operational[/bold green]\n"
    )



def system_status():

    table = Table(
        title="System Status",
        border_style="bright_blue"
    )


    table.add_column(
        "Component",
        style="cyan"
    )


    table.add_column(
        "Status",
        style="green"
    )


    table.add_row(
        "Operating System",
        platform.system()
    )


    table.add_row(
        "Python Version",
        platform.python_version()
    )


    table.add_row(
        "Log Engine",
        "ONLINE"
    )


    table.add_row(
        "Search Engine",
        "ONLINE"
    )


    table.add_row(
        "Export Engine",
        "ONLINE"
    )


    console.print(table)



def startup():

    show_banner()

    loading()

    system_status()
