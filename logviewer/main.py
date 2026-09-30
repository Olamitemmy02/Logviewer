import os

from rich.console import Console

from .banner import startup
from .menu import main_menu


console = Console()


def clear_terminal():
    """
    Clear the terminal screen before starting LogViewer.
    """

    os.system(
        "cls"
        if os.name == "nt"
        else "clear"
    )


def start():
    """
    Main application controller.

    Clears the terminal, starts the visual interface,
    and launches the LogViewer dashboard.

    Ctrl+C is handled here so KeyboardInterrupt does not
    produce a traceback for the user.
    """

    try:
        clear_terminal()
        startup()
        main_menu()

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]LogViewer stopped by user.[/yellow]"
        )

    finally:
        console.print(
            "[dim]Goodbye.[/dim]"
        )


if __name__ == "__main__":
    start()
