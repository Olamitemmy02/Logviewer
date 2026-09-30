import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .analysis.events.service import EventService
from .config import load_config
from .discovery import discover_system_logs, discover_snort_logs


console = Console()
event_service = EventService()


BACKUP_SUFFIXES = (
    ".backup",
    ".bak",
    ".old",
    ".orig",
    ".save",
)


def get_export_sources():
    """
    Discover real system and Snort log sources.

    Backup files are excluded from exports.
    """
    sources = []

    sources.extend(discover_system_logs())
    sources.extend(discover_snort_logs())

    unique_sources = set()

    for source in sources:
        path = Path(source)

        if not path.is_file():
            continue

        if path.name.lower().endswith(BACKUP_SUFFIXES):
            continue

        unique_sources.add(path)

    return sorted(
        unique_sources,
        key=lambda path: str(path).lower(),
    )


def load_export_events():
    """
    Load normalized events from all discovered sources.
    """
    sources = get_export_sources()

    events = []

    for source in sources:
        events.extend(
            event_service.from_file(source)
        )

    return (
        event_service.sort_events(events),
        sources,
    )


def event_to_dict(event):
    """
    Convert a normalized Event into a JSON/CSV-safe dictionary.
    """
    return {
        "timestamp": event.timestamp,
        "source": event.source,
        "severity": event.severity,
        "message": event.message,
        "event_type": event.event_type,
        "parse_status": event.parse_status,
        "parser": event.parser,
        "host": event.host,
        "user": event.user,
        "protocol": event.protocol,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "domain": event.domain,
        "url": event.url,
        "process": event.process,
        "pid": event.pid,
        "parent_pid": event.parent_pid,
        "command": event.command,
        "file_path": event.file_path,
        "hash_value": event.hash_value,
        "signature": event.signature,
        "gid": event.gid,
        "sid": event.sid,
        "revision": event.revision,
        "priority": event.priority,
        "action": event.action,
    }


def export_to_json(
    events: Iterable,
    output_path: Path,
):
    """
    Export normalized events as structured JSON.
    """
    records = [
        event_to_dict(event)
        for event in events
    ]

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            records,
            handle,
            indent=4,
            ensure_ascii=False,
        )


def export_to_csv(
    events: Iterable,
    output_path: Path,
):
    """
    Export normalized events as CSV.
    """
    records = [
        event_to_dict(event)
        for event in events
    ]

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not records:
        output_path.write_text(
            "",
            encoding="utf-8",
        )
        return

    fieldnames = list(
        records[0].keys()
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(records)


def export_to_txt(
    events: Iterable,
    output_path: Path,
):
    """
    Export normalized events into a human-readable report.
    """
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for event in events:
            handle.write(
                "=" * 80
                + "\n"
            )

            handle.write(
                f"Timestamp:    {event.timestamp or '-'}\n"
            )

            handle.write(
                f"Source:       {event.source or '-'}\n"
            )

            handle.write(
                f"Severity:     {event.severity or '-'}\n"
            )

            handle.write(
                f"Event Type:   {event.event_type or '-'}\n"
            )

            handle.write(
                f"Parser:       {event.parser or '-'}\n"
            )

            handle.write(
                f"Parse Status: {event.parse_status or '-'}\n"
            )

            handle.write(
                f"Host:         {event.host or '-'}\n"
            )

            handle.write(
                f"User:         {event.user or '-'}\n"
            )

            handle.write(
                f"Process:      {event.process or '-'}\n"
            )

            handle.write(
                f"PID:          {event.pid or '-'}\n"
            )

            handle.write(
                f"Parent PID:   {event.parent_pid or '-'}\n"
            )

            handle.write(
                f"Command:      {event.command or '-'}\n"
            )

            handle.write(
                f"Source IP:    {event.source_endpoint}\n"
            )

            handle.write(
                f"Destination:  {event.destination_endpoint}\n"
            )

            handle.write(
                f"Domain:       {event.domain or '-'}\n"
            )

            handle.write(
                f"URL:          {event.url or '-'}\n"
            )

            handle.write(
                f"File:         {event.file_path or '-'}\n"
            )

            handle.write(
                f"Hash:         {event.hash_value or '-'}\n"
            )

            handle.write(
                f"Signature:    {event.signature or '-'}\n"
            )

            handle.write(
                f"GID:          {event.gid or '-'}\n"
            )

            handle.write(
                f"SID:          {event.sid or '-'}\n"
            )

            handle.write(
                f"Revision:     {event.revision or '-'}\n"
            )

            handle.write(
                f"Priority:     {event.priority or '-'}\n"
            )

            handle.write(
                f"Action:       {event.action or '-'}\n"
            )

            handle.write(
                f"Message:      {event.message or '-'}\n"
            )

            handle.write("\n")


def get_export_directory():
    """
    Resolve the configured export directory.
    """
    config = load_config()

    directory = config.get(
        "export_directory",
        "exports",
    )

    return Path(directory)


def build_output_path(
    directory: Path,
    extension: str,
):
    """
    Build a timestamped export filename.
    """
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    return directory / (
        f"logviewer_export_{timestamp}.{extension}"
    )


def display_export_summary(
    events,
    sources,
    output_path,
):
    """
    Display a concise export summary.
    """
    table = Table(
        title="Export Complete",
        border_style="green",
    )

    table.add_column(
        "Item",
        style="cyan",
    )

    table.add_column(
        "Value",
        style="green",
    )

    table.add_row(
        "Sources",
        str(len(sources)),
    )

    table.add_row(
        "Events",
        str(len(events)),
    )

    table.add_row(
        "Output",
        str(output_path),
    )

    console.print(table)


def export_menu():
    """
    Interactive normalized-event export interface.
    """
    console.print()
    console.print(
        "[bold cyan]LogViewer — Export Reports[/bold cyan]"
    )

    console.print(
        "[dim]Exports are generated from normalized "
        "events collected from real system sources.[/dim]"
    )

    console.print()

    events, sources = load_export_events()

    if not sources:
        console.print(
            "[yellow]No log sources were discovered.[/yellow]"
        )
        return

    if not events:
        console.print(
            "[yellow]No parsed events are available "
            "for export.[/yellow]"
        )
        return

    directory = get_export_directory()

    table = Table(
        title="Export Formats",
        border_style="cyan",
    )

    table.add_column(
        "Option",
        style="yellow",
        no_wrap=True,
    )

    table.add_column(
        "Format",
        style="cyan",
    )

    table.add_column(
        "Purpose",
        style="green",
    )

    table.add_row(
        "1",
        "JSON",
        "Structured data for analysis and automation",
    )

    table.add_row(
        "2",
        "CSV",
        "Spreadsheet and data-analysis compatible",
    )

    table.add_row(
        "3",
        "TXT",
        "Human-readable investigation report",
    )

    table.add_row(
        "0",
        "Back",
        "Return to the main menu",
    )

    console.print(table)

    choice = Prompt.ask(
        "Select export format",
        choices=[
            "1",
            "2",
            "3",
            "0",
        ],
    )

    if choice == "0":
        return

    if choice == "1":
        output_path = build_output_path(
            directory,
            "json",
        )

        export_to_json(
            events,
            output_path,
        )

    elif choice == "2":
        output_path = build_output_path(
            directory,
            "csv",
        )

        export_to_csv(
            events,
            output_path,
        )

    else:
        output_path = build_output_path(
            directory,
            "txt",
        )

        export_to_txt(
            events,
            output_path,
        )

    display_export_summary(
        events,
        sources,
        output_path,
    )


def exporter_menu():
    """
    Public entry point used by the existing main menu.

    Keeps compatibility with menu.py while the exporter
    implementation uses the normalized event pipeline.
    """
    export_menu()
