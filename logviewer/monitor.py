from pathlib import Path
from time import sleep
from typing import Dict, List

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .discovery import discover_logs
from .analysis.events.service import EventService


console = Console()
event_service = EventService()


EXCLUDED_SUFFIXES = (
    ".backup",
    ".bak",
    ".old",
    ".orig",
    ".save",
)


def get_monitor_sources(root="/var/log") -> List[Path]:
    """
    Discover real log files that can be monitored.

    Backup and saved-copy files are excluded so the monitor
    does not display stale or test data.
    """
    sources = []

    for source in discover_logs(root):
        path = Path(source)

        if not path.is_file():
            continue

        if path.name.lower().endswith(EXCLUDED_SUFFIXES):
            continue

        sources.append(path)

    return sorted(
        set(sources),
        key=lambda path: str(path).lower(),
    )


class EventMonitor:
    """
    Live normalized-event monitor.

    The monitor tracks file positions and sends only newly
    appended lines through the shared EventService ingestion
    pipeline.
    """

    def __init__(
        self,
        root="/var/log",
        interval=0.5,
    ):
        self.root = Path(root)
        self.interval = interval

        self.positions: Dict[Path, int] = {}
        self.sources: List[Path] = []

    def discover(self) -> List[Path]:
        """
        Refresh the list of monitorable sources.
        """
        self.sources = get_monitor_sources(self.root)
        return self.sources

    def initialize_positions(self) -> None:
        """
        Start monitoring from the current end of each file.

        This prevents the live monitor from dumping historical
        events when monitoring begins.
        """
        for source in self.sources:
            try:
                self.positions[source] = source.stat().st_size
            except OSError:
                continue

    def read_new_data(self, source: Path):
        """
        Read newly appended data from one source.

        The new content is written to a temporary in-memory
        parser path and processed through the EventService.
        """
        try:
            current_size = source.stat().st_size
        except OSError:
            return []

        previous_position = self.positions.get(
            source,
            current_size,
        )

        # Handle truncation or log rotation.
        if current_size < previous_position:
            previous_position = 0

        if current_size == previous_position:
            self.positions[source] = current_size
            return []

        try:
            with source.open(
                "rb"
            ) as handle:
                handle.seek(previous_position)
                data = handle.read()

            self.positions[source] = current_size

        except (
            OSError,
            PermissionError,
        ):
            return []

        if not data:
            return []

        text = data.decode(
            "utf-8",
            errors="replace",
        )

        return self._parse_increment(
            source,
            text,
        )

    def _parse_increment(
        self,
        source: Path,
        text: str,
    ):
        """
        Parse newly appended text using the same parser registry
        used by historical ingestion.

        The increment is processed line-by-line so the monitor
        remains lightweight.
        """
        parser = event_service.ingestion.get_parser(source)

        if parser is None:
            return []

        events = []

        lines = text.splitlines()

        for line in lines:
            if not line.strip():
                continue

            try:
                event = parser.parse_line(
                    line,
                    source,
                )
            except Exception:
                event = None

            if event is None:
                continue

            event.source = str(source)

            if not event.raw:
                event.raw = {}

            event.raw.setdefault(
                "source_path",
                str(source),
            )

            events.append(event)

        return events

    def poll(self):
        """
        Poll all discovered sources for new events.
        """
        events = []

        self.discover()

        for source in self.sources:
            events.extend(
                self.read_new_data(source)
            )

        return event_service.sort_events(events)


def build_monitor_table(events):
    """
    Build a clean Rich table for live normalized events.
    """
    table = Table(
        title="LogViewer — Live Event Monitor",
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "Time",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Severity",
        style="yellow",
        no_wrap=True,
    )

    table.add_column(
        "Source",
        style="blue",
        no_wrap=True,
    )

    table.add_column(
        "Process",
        style="magenta",
        no_wrap=True,
    )

    table.add_column(
        "PID",
        style="green",
        no_wrap=True,
    )

    table.add_column(
        "Message",
        overflow="fold",
    )

    for event in events[-100:]:
        table.add_row(
            event.timestamp or "-",
            event.severity or "INFO",
            Path(event.source).name
            if event.source
            else "-",
            event.process or "-",
            str(event.pid)
            if event.pid is not None
            else "-",
            event.message or "-",
        )

    return table


def monitor_live(
    root="/var/log",
    interval=0.5,
):
    """
    Start the live normalized-event monitor.
    """
    monitor = EventMonitor(
        root=root,
        interval=interval,
    )

    sources = monitor.discover()

    if not sources:
        console.print(
            "[yellow]No monitorable log sources were found.[/yellow]"
        )
        return

    monitor.initialize_positions()

    console.print()
    console.print(
        f"[green]Monitoring {len(sources)} "
        f"real log source(s).[/green]"
    )

    console.print(
        "[dim]Waiting for new events... "
        "Press Ctrl+C to stop.[/dim]"
    )

    recent_events = []

    try:
        with Live(
            build_monitor_table(recent_events),
            console=console,
            refresh_per_second=4,
        ) as live:

            while True:
                events = monitor.poll()

                if events:
                    recent_events.extend(events)

                    if len(recent_events) > 100:
                        recent_events = recent_events[-100:]

                live.update(
                    build_monitor_table(
                        recent_events
                    )
                )

                sleep(interval)

    except KeyboardInterrupt:
        console.print()
        console.print(
            "[cyan]Live monitor stopped.[/cyan]"
        )


def monitor_all():
    """
    Compatibility wrapper for the existing menu.
    """
    monitor_live()


def show_discovered():
    """
    Display the currently discovered monitorable sources.
    """
    sources = get_monitor_sources()

    if not sources:
        console.print(
            "[yellow]No monitorable log sources were found.[/yellow]"
        )
        return

    table = Table(
        title="Monitorable Log Sources",
        border_style="cyan",
        expand=True,
    )

    table.add_column(
        "Source",
        style="blue",
    )

    table.add_column(
        "Size",
        style="green",
        justify="right",
    )

    for source in sources:
        try:
            size = source.stat().st_size
        except OSError:
            size = 0

        table.add_row(
            str(source),
            f"{size:,} B",
        )

    console.print(table)

    console.print()
    console.print(
        f"[dim]{len(sources)} monitorable source(s).[/dim]"
    )


def monitor_menu():
    """
    Interactive Live Monitor menu.
    """
    while True:
        table = Table(
            title="Live Monitor",
            border_style="cyan",
            expand=True,
        )

        table.add_column(
            "Option",
            style="yellow",
            no_wrap=True,
        )

        table.add_column(
            "Action",
            style="green",
        )

        table.add_row(
            "1",
            "Monitor All Logs",
        )

        table.add_row(
            "2",
            "Show Discovered Sources",
        )

        table.add_row(
            "0",
            "Back",
        )

        console.print(table)

        choice = console.input(
            "[bold]Select option: [/bold]"
        ).strip()

        if choice == "1":
            monitor_all()

        elif choice == "2":
            show_discovered()

        elif choice == "0":
            break

        else:
            console.print(
                "[red]Invalid option.[/red]"
            )
