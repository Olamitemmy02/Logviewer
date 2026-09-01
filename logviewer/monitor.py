import time
from pathlib import Path
from collections import OrderedDict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt

from .discovery import discover_logs

console = Console()


class MultiLogMonitor:
    """
    Real-time monitor for multiple system log files.
    """

    def __init__(self, root="/var/log", interval=0.5):
        self.root = Path(root)
        self.interval = interval
        self.positions = {}
        self.active_files = set()
        self.events = []

    def discover(self):
        """
        Discover current logs under /var/log.
        """
        return discover_logs(self.root)

    def initialize_positions(self, files):
        """
        Start monitoring from the current end of each file.
        This prevents dumping existing historical logs immediately.
        """
        for path in files:
            if path in self.positions:
                continue

            try:
                self.positions[path] = path.stat().st_size
            except (OSError, PermissionError):
                self.positions[path] = 0

    def read_new_data(self, path):
        """
        Read only data appended since the previous check.
        """
        try:
            current_size = path.stat().st_size
        except (OSError, PermissionError):
            return []

        previous_size = self.positions.get(path, 0)

        # Log rotation/truncation.
        if current_size < previous_size:
            previous_size = 0

        if current_size == previous_size:
            return []

        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:

                file.seek(previous_size)

                data = file.read()

            self.positions[path] = current_size

        except (OSError, PermissionError):
            return []

        lines = data.splitlines()

        return [
            {
                "source": str(path),
                "message": line
            }
            for line in lines
            if line.strip()
        ]

    def collect_events(self):
        """
        Collect new events from every currently discovered log.
        """
        files = self.discover()

        self.initialize_positions(files)

        events = []

        for path in files:
            events.extend(self.read_new_data(path))

        return events

    def add_events(self, events):
        """
        Maintain a bounded event history.
        """
        for event in events:
            self.events.append(event)

        self.events = self.events[-25:]

    def build_display(self):
        """
        Build the live Rich interface.
        """
        table = Table(
            title="LIVE SYSTEM LOG MONITOR",
            expand=True
        )

        table.add_column(
            "Source",
            style="cyan",
            no_wrap=True
        )

        table.add_column(
            "Event",
            style="white"
        )

        if not self.events:
            table.add_row(
                "—",
                "Waiting for new log events..."
            )

        else:
            for event in self.events[-15:]:
                source = event["source"]

                if len(source) > 42:
                    source = "..." + source[-39:]

                message = event["message"]

                if len(message) > 100:
                    message = message[:97] + "..."

                table.add_row(
                    source,
                    message
                )

        return table

    def run(self):
        """
        Start monitoring all discovered logs.
        """
        initial_files = self.discover()

        if not initial_files:
            console.print(
                Panel(
                    "[yellow]No readable log files were discovered "
                    "under /var/log.[/yellow]"
                )
            )
            return

        self.initialize_positions(initial_files)

        console.print(
            Panel(
                f"[green]Monitoring {len(initial_files)} log files "
                f"under {self.root}[/green]\n\n"
                "[cyan]New log files will be discovered automatically.[/cyan]\n"
                "[yellow]Press Ctrl+C to stop.[/yellow]"
            )
        )

        try:
            with Live(
                self.build_display(),
                refresh_per_second=4,
                console=console
            ) as live:

                while True:
                    # Re-discover so newly created logs are included.
                    files = self.discover()

                    self.initialize_positions(files)

                    new_events = self.collect_events()

                    if new_events:
                        self.add_events(new_events)

                    live.update(self.build_display())

                    time.sleep(self.interval)

        except KeyboardInterrupt:
            console.print(
                "\n[yellow]Monitoring stopped.[/yellow]"
            )


def monitor_all_logs():
    """
    Public entry point used by the menu.
    """
    monitor = MultiLogMonitor(
        root="/var/log"
    )

    monitor.run()


def monitor_menu():
    """
    Live Monitor menu.
    """
    while True:
        table = Table(
            title="LIVE MONITOR",
            border_style="cyan"
        )

        table.add_column(
            "Option",
            style="yellow"
        )

        table.add_column(
            "Function",
            style="green"
        )

        table.add_row(
            "1",
            "Monitor All /var/log Files"
        )

        table.add_row(
            "2",
            "Show Discovered Log Count"
        )

        table.add_row(
            "0",
            "Back"
        )

        console.print(table)

        choice = Prompt.ask("Select option")

        if choice == "1":
            monitor_all_logs()

        elif choice == "2":
            logs = discover_logs("/var/log")

            console.print(
                Panel(
                    f"[green]Readable log files discovered: "
                    f"{len(logs)}[/green]"
                )
            )

        elif choice == "0":
            break

        else:
            console.print(
                "[red]Invalid option.[/red]"
            )
