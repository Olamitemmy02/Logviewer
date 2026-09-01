
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from .discovery import discover_system_logs, discover_snort_logs


console = Console()


def _safe_read_lines(path, limit=200):
    """
    Read the last `limit` lines from a log file.

    Returns an empty list when the file cannot be read.
    """
    try:
        with Path(path).open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:
            lines = file.readlines()

        return lines[-limit:]

    except (OSError, PermissionError):
        return []


def _display_name(path):
    """Return a clean display path."""
    return str(Path(path))


def _build_log_list():
    """
    Build the complete list of discovered logs.

    System logs and Snort logs are combined while removing
    duplicates.
    """
    system_logs = discover_system_logs()
    snort_logs = discover_snort_logs()

    combined = []

    for path in system_logs + snort_logs:
        path = Path(path)

        if path not in combined:
            combined.append(path)

    return sorted(
        combined,
        key=lambda item: str(item).lower()
    )


def view_logs():
    """Display discovered system and Snort logs."""
    logs = _build_log_list()

    if not logs:
        console.print(
            Panel(
                "No readable log files were discovered under /var/log.",
                title="LOG VIEWER",
                border_style="yellow"
            )
        )
        return

    table = Table(
        title="Available Logs",
        border_style="cyan"
    )

    table.add_column(
        "ID",
        style="yellow",
        justify="center"
    )

    table.add_column(
        "Log File",
        style="green"
    )

    table.add_column(
        "Size",
        style="cyan",
        justify="right"
    )

    for index, path in enumerate(logs, start=1):

        try:
            size = path.stat().st_size

            if size < 1024:
                size_text = f"{size} B"
            elif size < 1024 * 1024:
                size_text = f"{size / 1024:.1f} KB"
            else:
                size_text = f"{size / (1024 * 1024):.1f} MB"

        except (OSError, PermissionError):
            size_text = "N/A"

        table.add_row(
            str(index),
            _display_name(path),
            size_text
        )

    console.print(table)

    choice = Prompt.ask(
        "Select log number",
        default="0"
    )

    if choice == "0":
        return

    try:
        selected = int(choice)
    except ValueError:
        console.print(
            "[red]Invalid log number.[/red]"
        )
        return

    if selected < 1 or selected > len(logs):
        console.print(
            "[red]Invalid log number.[/red]"
        )
        return

    selected_path = logs[selected - 1]

    _show_log(selected_path)


def _show_log(path):
    """Display the contents of a selected log."""
    path = Path(path)

    lines = _safe_read_lines(path)

    if not lines:
        console.print(
            Panel(
                f"No readable content found in:\n{path}",
                title="LOG VIEWER",
                border_style="yellow"
            )
        )
        return

    table = Table(
        title=str(path),
        border_style="cyan"
    )

    table.add_column(
        "Line",
        style="yellow",
        justify="right"
    )

    table.add_column(
        "Content",
        style="white"
    )

    start_line = max(1, sum(1 for _ in lines) - len(lines) + 1)

    for offset, line in enumerate(lines):
        table.add_row(
            str(start_line + offset),
            line.rstrip()
        )

    console.print(table)

