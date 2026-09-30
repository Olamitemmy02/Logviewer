"""
Rich display functions for Core Security Analysis.
"""

from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table

from .analyzer import (
    SecurityAnalyzer,
    SecurityObservation,
)

from .loader import (
    STATUS_ANALYZED,
    STATUS_EMPTY,
    STATUS_PERMISSION_DENIED,
    STATUS_READ_ERROR,
    STATUS_UNAVAILABLE,
    STATUS_UNSUPPORTED,
    SOURCE_KIND_BACKUP,
    SOURCE_KIND_COMPRESSED_ROTATION,
    SOURCE_KIND_FILESYSTEM,
    SOURCE_KIND_JOURNAL,
    SOURCE_KIND_ROTATED,
    SOURCE_KIND_SNORT,
    SourceStatus,
)


console = Console()

PAGE_SIZE = 20

SecurityRefreshCallback = Callable[
    [],
    Tuple[
        List[SecurityObservation],
        List[SourceStatus],
        int,
    ],
]


def _severity_style(severity: str) -> str:
    severity = (severity or "INFO").upper()

    if severity == "WARNING":
        return "bold red"

    if severity == "NOTICE":
        return "bold yellow"

    if severity == "INFO":
        return "bold cyan"

    return "white"


def _strength_style(strength: str) -> str:
    strength = (strength or "contextual").lower()

    if strength == "strong":
        return "bold green"

    if strength == "moderate":
        return "yellow"

    return "dim"


def _source_status_style(status: str) -> str:
    status = (status or "").upper()

    if status == STATUS_ANALYZED:
        return "bold green"

    if status == STATUS_EMPTY:
        return "bold yellow"

    if status == STATUS_UNAVAILABLE:
        return "dim"

    if status == STATUS_PERMISSION_DENIED:
        return "bold red"

    if status == STATUS_READ_ERROR:
        return "bold red"

    if status == STATUS_UNSUPPORTED:
        return "dim red"

    return "white"


def _source_status_symbol(status: str) -> str:
    status = (status or "").upper()

    if status == STATUS_ANALYZED:
        return "[green]●[/green]"

    if status == STATUS_EMPTY:
        return "[yellow]○[/yellow]"

    if status == STATUS_UNAVAILABLE:
        return "[dim]–[/dim]"

    if status == STATUS_PERMISSION_DENIED:
        return "[red]×[/red]"

    if status == STATUS_READ_ERROR:
        return "[red]![/red]"

    if status == STATUS_UNSUPPORTED:
        return "[dim red]?[/dim red]"

    return "[white]•[/white]"


def _source_status_description(
    source: SourceStatus,
) -> str:
    """
    Explain the current ingestion state of a source.
    """

    status = source.status or STATUS_UNAVAILABLE

    if status == STATUS_ANALYZED:
        return (
            "The source was successfully read and produced "
            "security events."
        )

    if status == STATUS_EMPTY:
        return (
            "The source was available and readable, but no "
            "events were produced from its current contents."
        )

    if status == STATUS_PERMISSION_DENIED:
        return (
            "The source could not be completely read because "
            "access was denied."
        )

    if status == STATUS_READ_ERROR:
        return (
            "The source was available, but an error occurred "
            "while reading or parsing it."
        )

    if status == STATUS_UNAVAILABLE:
        return (
            "The source is not currently available to the "
            "security-analysis ingestion layer."
        )

    if status == STATUS_UNSUPPORTED:
        return (
            "The source was discovered, but no supported "
            "security-event parser is available for it."
        )

    return (
        "The source has an unrecognized ingestion state."
    )


def _is_rotated_path(path: str) -> bool:
    """
    Determine whether a physical path appears to be a rotated
    log file.

    Examples:
        auth.log.1
        auth.log.2.gz
        error.log.10
    """

    name = Path(path).name.lower()

    if name.endswith(".gz"):
        name = name[:-3]

    parts = name.split(".")

    return (
        len(parts) >= 2
        and parts[-1].isdigit()
    )


def _is_compressed_rotation(path: str) -> bool:
    """
    Determine whether a physical path is a compressed rotated log.
    """

    return (
        Path(path).name.lower().endswith(".gz")
        and _is_rotated_path(path)
    )


def _is_backup_path(path: str) -> bool:
    """
    Determine whether a physical path appears to be a backup artifact.
    """

    name = Path(path).name.lower()

    return any(
        name.endswith(suffix)
        for suffix in {
            ".backup",
            ".bak",
            ".old",
            ".orig",
            ".save",
        }
    )


def _display_path_kind(
    path: str,
    source: Optional[SourceStatus] = None,
) -> str:
    """
    Describe the physical role of a source path.
    """

    if source is not None:

        if source.source_kind == SOURCE_KIND_JOURNAL:
            return "Journal-managed"

        if source.source_kind == SOURCE_KIND_SNORT:
            return "Snort-managed"

    if _is_backup_path(path):
        return "Backup"

    if _is_compressed_rotation(path):
        return "Compressed Rotation"

    if _is_rotated_path(path):
        return "Rotated"

    return "Active / Primary"


def _source_kind_label(
    source: SourceStatus,
) -> str:
    """
    Return a human-readable source-management category.
    """

    kind = source.source_kind

    labels = {
        SOURCE_KIND_FILESYSTEM: "Filesystem",
        SOURCE_KIND_JOURNAL: "Journal-managed",
        SOURCE_KIND_SNORT: "Snort-managed",
        SOURCE_KIND_BACKUP: "Backup artifact",
        SOURCE_KIND_ROTATED: "Rotated log",
        SOURCE_KIND_COMPRESSED_ROTATION: (
            "Compressed rotation"
        ),
    }

    return labels.get(
        kind,
        "Filesystem",
    )


def display_source_health(
    sources: List[SourceStatus],
    total_events: Optional[int] = None,
) -> None:
    """
    Display aggregate source ingestion health and event coverage.

    Values are calculated directly from the real source statuses
    produced by the Security Analysis loader.
    """

    console.print()

    health = Table(
        title="Source Health",
        border_style="cyan",
    )

    health.add_column(
        "Status",
        style="bold cyan",
    )

    health.add_column(
        "Sources",
        justify="right",
        style="yellow",
    )

    status_rows = [
        (
            STATUS_ANALYZED,
            "bold green",
        ),
        (
            STATUS_EMPTY,
            "bold yellow",
        ),
        (
            STATUS_PERMISSION_DENIED,
            "bold red",
        ),
        (
            STATUS_READ_ERROR,
            "bold red",
        ),
        (
            STATUS_UNAVAILABLE,
            "dim",
        ),
        (
            STATUS_UNSUPPORTED,
            "dim red",
        ),
    ]

    for status, style in status_rows:

        count = sum(
            source.status == status
            for source in sources
        )

        health.add_row(
            f"[{style}]{status}[/]",
            f"{count:,}",
        )

    console.print(health)

    physical_paths = sum(
        len(source.paths)
        for source in sources
    )

    sources_with_events = sum(
        source.events > 0
        for source in sources
    )

    sources_with_errors = sum(
        source.status
        in {
            STATUS_PERMISSION_DENIED,
            STATUS_READ_ERROR,
        }
        for source in sources
    )

    sources_with_paths = sum(
        bool(source.paths)
        for source in sources
    )

    coverage = Table(
        title="Event Coverage",
        border_style="cyan",
    )

    coverage.add_column(
        "Metric",
        style="bold cyan",
    )

    coverage.add_column(
        "Value",
        justify="right",
        style="bold white",
    )

    coverage.add_row(
        "Events loaded",
        f"{(total_events or 0):,}",
    )

    coverage.add_row(
        "Logical sources",
        f"{len(sources):,}",
    )

    coverage.add_row(
        "Sources with events",
        f"{sources_with_events:,}",
    )

    coverage.add_row(
        "Sources with errors",
        f"{sources_with_errors:,}",
    )

    coverage.add_row(
        "Sources with physical files",
        f"{sources_with_paths:,}",
    )

    coverage.add_row(
        "Physical files",
        f"{physical_paths:,}",
    )

    console.print(coverage)


def display_source_status(
    sources: List[SourceStatus],
) -> None:
    """
    Display the current ingestion status of logical security sources.

    Dedicated journal and Snort sources are represented by their
    dedicated readers rather than their underlying physical files.
    """

    console.print()

    table = Table(
        title="Source Status",
        border_style="cyan",
    )

    table.add_column(
        "",
        width=3,
    )

    table.add_column(
        "Source",
        style="green",
        min_width=24,
    )

    table.add_column(
        "Status",
        min_width=20,
    )

    table.add_column(
        "Events",
        justify="right",
        style="yellow",
        width=10,
    )

    table.add_column(
        "Parser",
        style="dim",
        max_width=28,
    )

    visible_sources = [
        source
        for source in sources
        if source.status != STATUS_UNSUPPORTED
        or source.parser
        or source.events
    ]

    visible_sources.sort(
        key=lambda source: (
            source.status == STATUS_UNAVAILABLE,
            source.name.casefold(),
        )
    )

    if not visible_sources:

        table.add_row(
            "",
            "No security sources discovered",
            "[dim]UNAVAILABLE[/dim]",
            "0",
            "-",
        )

        console.print(table)
        return

    for source in visible_sources:

        status = source.status or STATUS_UNAVAILABLE

        table.add_row(
            _source_status_symbol(status),
            source.name,
            (
                f"[{_source_status_style(status)}]"
                f"{status}"
                "[/]"
            ),
            f"{source.events:,}",
            source.parser or "-",
        )

    console.print(table)

    unsupported_count = sum(
        source.status == STATUS_UNSUPPORTED
        for source in sources
    )

    if unsupported_count:

        console.print(
            f"[dim]Additional unsupported filesystem sources: "
            f"{unsupported_count}[/dim]"
        )

    errors = [
        source
        for source in sources
        if source.status in {
            STATUS_PERMISSION_DENIED,
            STATUS_READ_ERROR,
        }
        and source.error
    ]

    if errors:

        error_table = Table(
            title="Source Errors",
            border_style="red",
        )

        error_table.add_column(
            "Source",
            style="red",
        )

        error_table.add_column(
            "Status",
            style="bold red",
        )

        error_table.add_column(
            "Details",
            style="white",
        )

        for source in errors:

            error_table.add_row(
                source.name,
                source.status,
                source.error or "-",
            )

        console.print(error_table)


def display_source_diagnostics(
    source: SourceStatus,
) -> None:
    """
    Display detailed ingestion diagnostics for one source.
    """

    status = source.status or STATUS_UNAVAILABLE

    console.print()

    title = (
        f"Source Diagnostics — {source.name}"
    )

    details = Table(
        title=title,
        border_style="cyan",
        show_header=False,
    )

    details.add_column(
        "Field",
        style="bold cyan",
        width=24,
    )

    details.add_column(
        "Value",
        style="white",
    )

    details.add_row(
        "Source",
        source.name,
    )

    details.add_row(
        "Source kind",
        _source_kind_label(source),
    )

    details.add_row(
        "Status",
        (
            f"{_source_status_symbol(status)} "
            f"[{_source_status_style(status)}]"
            f"{status}"
            "[/]"
        ),
    )

    details.add_row(
        "Events loaded",
        f"{source.events:,}",
    )

    details.add_row(
        "Parser",
        source.parser or "-",
    )

    details.add_row(
        "Physical files",
        f"{len(source.paths):,}",
    )

    details.add_row(
        "State explanation",
        _source_status_description(source),
    )

    if source.description:

        details.add_row(
            "Source description",
            source.description,
        )

    if source.error:

        details.add_row(
            "Error",
            source.error,
        )

    console.print(details)

    if source.paths:

        paths_table = Table(
            title="Physical Source Files",
            border_style="green",
        )

        paths_table.add_column(
            "#",
            style="yellow",
            width=5,
        )

        paths_table.add_column(
            "Path",
            style="white",
        )

        paths_table.add_column(
            "Type",
            style="cyan",
            width=24,
        )

        for index, path in enumerate(
            source.paths,
            start=1,
        ):

            paths_table.add_row(
                str(index),
                path,
                _display_path_kind(
                    path,
                    source=source,
                ),
            )

        console.print(paths_table)

    else:

        console.print(
            Panel(
                "No physical filesystem path was reported for "
                "this logical source. This is expected for "
                "sources such as systemd journal when ingestion "
                "is performed through a dedicated reader.",
                title="Physical Files",
                border_style="dim",
            )
        )

    if status == STATUS_ANALYZED:

        console.print(
            Panel(
                "Ingestion completed successfully. "
                "The source produced real events for Security Analysis.",
                title="Ingestion Result",
                border_style="green",
            )
        )

    elif status == STATUS_EMPTY:

        console.print(
            Panel(
                "The source was available to LogViewer, but "
                "its current contents produced no events.",
                title="Ingestion Result",
                border_style="yellow",
            )
        )

    elif status == STATUS_UNSUPPORTED:

        console.print(
            Panel(
                "The source was discovered but is not currently "
                "handled by a supported security-event parser.",
                title="Ingestion Result",
                border_style="yellow",
            )
        )

    elif status in {
        STATUS_PERMISSION_DENIED,
        STATUS_READ_ERROR,
    }:

        console.print(
            Panel(
                source.error
                or "The source could not be completely ingested.",
                title="Ingestion Error",
                border_style="red",
            )
        )

    else:

        console.print(
            Panel(
                "The source is currently unavailable to the "
                "security-analysis ingestion layer.",
                title="Ingestion Result",
                border_style="dim",
            )
        )


def _source_diagnostics_menu(
    sources: List[SourceStatus],
) -> None:
    """
    Interactive source-diagnostics browser.
    """

    visible_sources = [
        source
        for source in sources
        if source.status != STATUS_UNSUPPORTED
        or source.parser
        or source.events
        or source.error
    ]

    visible_sources.sort(
        key=lambda source: source.name.casefold()
    )

    if not visible_sources:

        console.print(
            Panel(
                "No security sources are available for diagnostics.",
                title="Source Diagnostics",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default="",
        )

        return

    while True:

        console.clear()

        table = Table(
            title="Source Diagnostics",
            border_style="cyan",
        )

        table.add_column(
            "#",
            style="yellow",
            width=6,
        )

        table.add_column(
            "Source",
            style="green",
        )

        table.add_column(
            "Kind",
            style="cyan",
            width=22,
        )

        table.add_column(
            "Status",
            min_width=20,
        )

        table.add_column(
            "Events",
            justify="right",
            style="yellow",
            width=12,
        )

        table.add_column(
            "Parser",
            style="dim",
        )

        for index, source in enumerate(
            visible_sources,
            start=1,
        ):

            status = (
                source.status
                or STATUS_UNAVAILABLE
            )

            table.add_row(
                str(index),
                source.name,
                _source_kind_label(source),
                (
                    f"{_source_status_symbol(status)} "
                    f"[{_source_status_style(status)}]"
                    f"{status}"
                    "[/]"
                ),
                f"{source.events:,}",
                source.parser or "-",
            )

        console.print(table)

        selection = Prompt.ask(
            "\nEnter source number or R to return",
            default="r",
        ).strip().lower()

        if selection == "r":
            return

        if not selection.isdigit():

            console.print(
                "[red]Enter a valid source number.[/red]"
            )

            Prompt.ask(
                "\nPress Enter to continue",
                default="",
            )

            continue

        number = int(selection)

        if number < 1 or number > len(visible_sources):

            console.print(
                "[red]Invalid source selection.[/red]"
            )

            Prompt.ask(
                "\nPress Enter to continue",
                default="",
            )

            continue

        console.clear()

        display_source_diagnostics(
            visible_sources[number - 1]
        )

        Prompt.ask(
            "\nPress Enter to return to source diagnostics",
            default="",
        )


def display_security_summary(
    observations: List[SecurityObservation],
    sources: Optional[List[SourceStatus]] = None,
    total_events: Optional[int] = None,
) -> None:
    """
    Display a compact security-analysis summary.
    """

    console.print()

    summary = Table(
        title="Security Analysis",
        border_style="cyan",
        show_header=False,
    )

    summary.add_column(
        "Metric",
        style="bold cyan",
    )

    summary.add_column(
        "Value",
        style="bold white",
    )

    total = len(observations)

    if sources is not None:

        source_count = sum(
            source.status == STATUS_ANALYZED
            for source in sources
        )

    else:

        source_count = len(
            {
                observation.source
                for observation in observations
                if observation.source
            }
        )

    event_count = (
        total_events
        if total_events is not None
        else total
    )

    warnings = sum(
        1
        for observation in observations
        if observation.severity.upper() == "WARNING"
    )

    notices = sum(
        1
        for observation in observations
        if observation.severity.upper() == "NOTICE"
    )

    informational = sum(
        1
        for observation in observations
        if observation.severity.upper() == "INFO"
    )

    strong = sum(
        1
        for observation in observations
        if observation.evidence_strength.lower() == "strong"
    )

    moderate = sum(
        1
        for observation in observations
        if observation.evidence_strength.lower() == "moderate"
    )

    contextual = sum(
        1
        for observation in observations
        if observation.evidence_strength.lower() == "contextual"
    )

    summary.add_row(
        "Events analyzed",
        f"{event_count:,}",
    )

    summary.add_row(
        "Observations",
        f"{total:,}",
    )

    summary.add_row(
        "Sources analyzed",
        f"{source_count:,}",
    )

    summary.add_row(
        "Warnings",
        f"{warnings:,}",
    )

    summary.add_row(
        "Notices",
        f"{notices:,}",
    )

    summary.add_row(
        "Informational",
        f"{informational:,}",
    )

    summary.add_row(
        "Strong evidence",
        f"{strong:,}",
    )

    summary.add_row(
        "Moderate evidence",
        f"{moderate:,}",
    )

    summary.add_row(
        "Contextual evidence",
        f"{contextual:,}",
    )

    console.print(summary)

    if not observations:
        return

    category_counts = Counter(
        observation.category
        for observation in observations
    )

    category_table = Table(
        title="Observation Categories",
        border_style="cyan",
    )

    category_table.add_column(
        "Category",
        style="green",
    )

    category_table.add_column(
        "Count",
        justify="right",
        style="yellow",
    )

    for category, count in sorted(
        category_counts.items(),
        key=lambda item: (-item[1], item[0]),
    ):

        category_table.add_row(
            category,
            str(count),
        )

    console.print(category_table)


def display_security_observations(
    observations: List[SecurityObservation],
    page: int = 1,
) -> int:
    """
    Display paginated security observations.

    Returns the total number of pages.
    """

    if not observations:

        console.print(
            Panel(
                "No security observations matched the current view.",
                title="No Observations",
                border_style="yellow",
            )
        )

        return 0

    total_pages = max(
        1,
        (len(observations) + PAGE_SIZE - 1)
        // PAGE_SIZE,
    )

    page = max(
        1,
        min(page, total_pages),
    )

    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE

    current = observations[start:end]

    table = Table(
        title=(
            f"Security Observations "
            f"(Page {page}/{total_pages})"
        ),
        border_style="cyan",
    )

    table.add_column("#", style="yellow", width=5)
    table.add_column("Time", style="dim", max_width=22)
    table.add_column("Category", style="green", max_width=20)
    table.add_column("Observation", style="white", max_width=34)
    table.add_column("Severity", max_width=12)
    table.add_column("Evidence", max_width=12)
    table.add_column("Source", style="cyan", max_width=22)

    for index, observation in enumerate(
        current,
        start=start + 1,
    ):

        severity = observation.severity.upper()
        strength = observation.evidence_strength.lower()

        table.add_row(
            str(index),
            observation.timestamp or "-",
            observation.category,
            observation.title,
            f"[{_severity_style(severity)}]{severity}[/]",
            f"[{_strength_style(strength)}]"
            f"{strength.title()}[/]",
            observation.source or "-",
        )

    console.print(table)

    console.print(
        f"\n[dim]Showing {start + 1}-"
        f"{min(end, len(observations))} of "
        f"{len(observations)} observations.[/dim]"
    )

    return total_pages


def display_security_observation_detail(
    observation: SecurityObservation,
) -> None:
    """
    Display complete information about one observation.
    """

    severity = observation.severity.upper()
    strength = observation.evidence_strength.lower()

    details = Table(
        title="Observation Details",
        border_style="cyan",
        show_header=False,
    )

    details.add_column(
        "Field",
        style="bold cyan",
        width=20,
    )

    details.add_column(
        "Value",
        style="white",
    )

    details.add_row("Rule", observation.rule_id)
    details.add_row("Category", observation.category)
    details.add_row("Title", observation.title)

    details.add_row(
        "Severity",
        f"[{_severity_style(severity)}]{severity}[/]",
    )

    details.add_row(
        "Evidence strength",
        f"[{_strength_style(strength)}]"
        f"{strength.title()}[/]",
    )

    details.add_row(
        "Timestamp",
        observation.timestamp or "-",
    )

    details.add_row(
        "Source",
        observation.source or "-",
    )

    details.add_row(
        "Event type",
        observation.event_type or "-",
    )

    details.add_row(
        "Parser",
        observation.parser or "-",
    )

    details.add_row(
        "Description",
        observation.description,
    )

    console.print(details)

    evidence_table = Table(
        title="Evidence",
        border_style="green",
    )

    evidence_table.add_column(
        "#",
        style="yellow",
        width=5,
    )

    evidence_table.add_column(
        "Observed Evidence",
        style="white",
    )

    if observation.evidence:

        for index, evidence in enumerate(
            observation.evidence,
            start=1,
        ):

            evidence_table.add_row(
                str(index),
                evidence,
            )

    else:

        evidence_table.add_row(
            "-",
            "[dim]No structured evidence fields "
            "were available.[/dim]",
        )

    console.print(evidence_table)

    console.print(
        "\n[dim]Note: Severity and evidence strength describe "
        "this observation within Core Security Analysis. "
        "They do not determine whether activity is malicious.[/dim]"
    )


def _observation_list_for_selection(
    observations: List[SecurityObservation],
    sources: Optional[List[SourceStatus]] = None,
    total_events: Optional[int] = None,
) -> None:
    """
    Show observations through pagination and allow selection
    of an individual observation.
    """

    if not observations:

        console.print(
            Panel(
                "There are no observations available for inspection.",
                title="No Observations",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default="",
        )

        return

    page = 1

    while True:

        console.clear()

        display_security_summary(
            observations,
            sources=sources,
            total_events=total_events,
        )

        console.print()

        total_pages = display_security_observations(
            observations,
            page=page,
        )

        if total_pages == 0:
            return

        navigation = Prompt.ask(
            "\n[N]ext  [P]revious  [S]elect  [R]eturn",
            choices=[
                "n",
                "p",
                "s",
                "r",
            ],
            default="s",
        ).lower()

        if navigation == "n":

            if page < total_pages:
                page += 1

            else:

                console.print(
                    "[yellow]Already on the last page.[/yellow]"
                )

        elif navigation == "p":

            if page > 1:
                page -= 1

            else:

                console.print(
                    "[yellow]Already on the first page.[/yellow]"
                )

        elif navigation == "s":

            start = (page - 1) * PAGE_SIZE
            end = min(
                start + PAGE_SIZE,
                len(observations),
            )

            console.print(
                f"\n[dim]Select an observation "
                f"from {start + 1} to {end}.[/dim]"
            )

            number = IntPrompt.ask(
                "Observation number",
                default=start + 1,
            )

            if number < 1 or number > len(observations):

                console.print(
                    "[red]Invalid observation number.[/red]"
                )

                Prompt.ask(
                    "\nPress Enter to continue",
                    default="",
                )

                continue

            display_security_observation_detail(
                observations[number - 1]
            )

            Prompt.ask(
                "\nPress Enter to return to observations",
                default="",
            )

        else:

            break


def _unique_values(
    observations: List[SecurityObservation],
    attribute: str,
) -> List[str]:
    """
    Return sorted unique values for a SecurityObservation attribute.
    """

    values = {
        str(getattr(observation, attribute))
        for observation in observations
        if getattr(observation, attribute, None)
    }

    return sorted(
        values,
        key=str.casefold,
    )


def _choose_filter_value(
    label: str,
    values: List[str],
) -> Optional[str]:
    """
    Display selectable values for a filter.

    Option 0 means no filter for the selected field.
    """

    if not values:

        console.print(
            f"[yellow]No {label.lower()} values are available.[/yellow]"
        )

        Prompt.ask(
            "\nPress Enter to continue",
            default="",
        )

        return None

    table = Table(
        title=f"{label} Filter",
        border_style="cyan",
    )

    table.add_column(
        "#",
        style="yellow",
        width=6,
    )

    table.add_column(
        label,
        style="green",
    )

    table.add_row(
        "0",
        "All",
    )

    for index, value in enumerate(
        values,
        start=1,
    ):

        table.add_row(
            str(index),
            value,
        )

    console.print(table)

    selection = IntPrompt.ask(
        f"Select {label.lower()}",
        default=0,
    )

    if selection == 0:
        return None

    if selection < 0 or selection > len(values):

        console.print(
            "[red]Invalid filter selection.[/red]"
        )

        Prompt.ask(
            "\nPress Enter to continue",
            default="",
        )

        return None

    return values[selection - 1]


def _security_filter_menu(
    observations: List[SecurityObservation],
    current_filters: Optional[
        Dict[str, Optional[str]]
    ] = None,
) -> Optional[Dict[str, Optional[str]]]:
    """
    Interactive Security Analysis filter builder.

    Filters use AND semantics.

    Returning None means the analyst cancelled filtering.
    """

    filters: Dict[str, Optional[str]] = {
        "severity": None,
        "category": None,
        "source": None,
        "rule_id": None,
        "event_type": None,
        "evidence_strength": None,
        "text": None,
    }

    if current_filters:
        filters.update(current_filters)

    while True:

        console.clear()

        current = SecurityAnalyzer.filter_observations(
            observations,
            **filters,
        )

        table = Table(
            title="Security Observation Filters",
            border_style="cyan",
        )

        table.add_column(
            "Filter",
            style="bold cyan",
            width=22,
        )

        table.add_column(
            "Value",
            style="white",
        )

        active = False

        for key, value in filters.items():

            if value:

                active = True

                table.add_row(
                    key.replace("_", " ").title(),
                    value,
                )

        if not active:

            table.add_row(
                "Active filters",
                "None",
            )

        table.add_row(
            "Matching observations",
            str(len(current)),
        )

        console.print(table)

        menu = Table(
            title="Filter Options",
            border_style="cyan",
        )

        menu.add_column(
            "Option",
            style="yellow",
            width=8,
        )

        menu.add_column(
            "Filter",
            style="green",
        )

        menu.add_row("1", "Severity")
        menu.add_row("2", "Category")
        menu.add_row("3", "Source")
        menu.add_row("4", "Rule ID")
        menu.add_row("5", "Event type")
        menu.add_row("6", "Evidence strength")
        menu.add_row("7", "Text search")
        menu.add_row("8", "Clear all filters")
        menu.add_row("9", "Apply filters")
        menu.add_row("0", "Cancel")

        console.print(menu)

        choice = Prompt.ask(
            "Select an option",
            choices=[
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "0",
            ],
        )

        if choice == "0":
            return None

        if choice == "1":

            filters["severity"] = _choose_filter_value(
                "Severity",
                _unique_values(
                    observations,
                    "severity",
                ),
            )

        elif choice == "2":

            filters["category"] = _choose_filter_value(
                "Category",
                _unique_values(
                    observations,
                    "category",
                ),
            )

        elif choice == "3":

            filters["source"] = _choose_filter_value(
                "Source",
                _unique_values(
                    observations,
                    "source",
                ),
            )

        elif choice == "4":

            filters["rule_id"] = _choose_filter_value(
                "Rule ID",
                _unique_values(
                    observations,
                    "rule_id",
                ),
            )

        elif choice == "5":

            filters["event_type"] = _choose_filter_value(
                "Event Type",
                _unique_values(
                    observations,
                    "event_type",
                ),
            )

        elif choice == "6":

            filters["evidence_strength"] = _choose_filter_value(
                "Evidence Strength",
                _unique_values(
                    observations,
                    "evidence_strength",
                ),
            )

        elif choice == "7":

            console.print(
                "\n[dim]Searches across observation metadata "
                "and preserved evidence.[/dim]"
            )

            value = Prompt.ask(
                "Search text",
                default=filters["text"] or "",
            ).strip()

            filters["text"] = value or None

        elif choice == "8":

            for key in filters:
                filters[key] = None

            console.print(
                "[green]All filters cleared.[/green]"
            )

            Prompt.ask(
                "\nPress Enter to continue",
                default="",
            )

        elif choice == "9":

            return filters


def _filtered_observation_view(
    observations: List[SecurityObservation],
    filters: Dict[str, Optional[str]],
    sources: Optional[List[SourceStatus]] = None,
    total_events: Optional[int] = None,
) -> None:
    """
    Display and navigate a filtered observation set.

    The original observation list is never modified.
    """

    filtered = SecurityAnalyzer.filter_observations(
        observations,
        **filters,
    )

    while True:

        console.clear()

        display_security_summary(
            filtered,
            sources=sources,
            total_events=total_events,
        )

        active_filter_count = sum(
            1
            for value in filters.values()
            if value
        )

        console.print(
            Panel(
                f"Showing {len(filtered)} of "
                f"{len(observations)} observations"
                f" • {active_filter_count} active filter(s)",
                title="Filtered View",
                border_style="yellow",
            )
        )

        console.print()

        menu = Table(
            title="Filtered Security Analysis",
            border_style="cyan",
        )

        menu.add_column(
            "Option",
            style="yellow",
            width=8,
        )

        menu.add_column(
            "Function",
            style="green",
        )

        menu.add_row(
            "1",
            "Show filtered observations",
        )

        menu.add_row(
            "2",
            "Show filtered observation details",
        )

        menu.add_row(
            "3",
            "Change filters",
        )

        menu.add_row(
            "4",
            "Clear filters",
        )

        menu.add_row(
            "0",
            "Return",
        )

        console.print(menu)

        choice = Prompt.ask(
            "Select an option",
            choices=[
                "1",
                "2",
                "3",
                "4",
                "0",
            ],
        )

        if choice == "0":
            return

        if choice == "1":

            page = 1

            while True:

                console.clear()

                display_security_summary(
                    filtered,
                    sources=sources,
                    total_events=total_events,
                )

                total_pages = display_security_observations(
                    filtered,
                    page=page,
                )

                if total_pages == 0:

                    Prompt.ask(
                        "\nPress Enter to return",
                        default="",
                    )

                    break

                if total_pages == 1:

                    Prompt.ask(
                        "\nPress Enter to return",
                        default="",
                    )

                    break

                navigation = Prompt.ask(
                    "\n[N]ext  [P]revious  [R]eturn",
                    choices=[
                        "n",
                        "p",
                        "r",
                    ],
                    default="r",
                ).lower()

                if navigation == "n":

                    if page < total_pages:
                        page += 1

                elif navigation == "p":

                    if page > 1:
                        page -= 1

                else:

                    break

        elif choice == "2":

            _observation_list_for_selection(
                filtered,
                sources=sources,
                total_events=total_events,
            )

        elif choice == "3":

            updated_filters = _security_filter_menu(
                observations,
                current_filters=filters,
            )

            if updated_filters is not None:

                filters = updated_filters

                filtered = SecurityAnalyzer.filter_observations(
                    observations,
                    **filters,
                )

        elif choice == "4":

            for key in filters:
                filters[key] = None

            filtered = list(observations)

            console.print(
                "[green]All filters cleared. "
                "Showing all observations.[/green]"
            )

            Prompt.ask(
                "\nPress Enter to continue",
                default="",
            )


def security_analysis_dashboard(
    observations: List[SecurityObservation],
    sources: Optional[List[SourceStatus]] = None,
    total_events: Optional[int] = None,
    refresh_callback: Optional[
        SecurityRefreshCallback
    ] = None,
) -> None:
    """
    Interactive Security Analysis dashboard.

    If refresh_callback is supplied, selecting the refresh option
    performs a complete security-analysis reload rather than merely
    redisplaying the existing source status.
    """

    while True:

        console.clear()

        display_security_summary(
            observations,
            sources=sources,
            total_events=total_events,
        )

        if sources is not None:

            display_source_health(
                sources,
                total_events=total_events,
            )

            display_source_status(
                sources
            )

        console.print()

        menu = Table(
            title="Security Analysis Menu",
            border_style="cyan",
        )

        menu.add_column(
            "Option",
            style="yellow",
            width=8,
        )

        menu.add_column(
            "Function",
            style="green",
        )

        menu.add_row(
            "1",
            "Show observations",
        )

        menu.add_row(
            "2",
            "Show observation details",
        )

        menu.add_row(
            "3",
            "Filter observations",
        )

        if sources is not None:

            menu.add_row(
                "4",
                "Refresh security analysis",
            )

            menu.add_row(
                "5",
                "Source diagnostics",
            )

        menu.add_row(
            "0",
            "Return",
        )

        choices = [
            "1",
            "2",
            "3",
        ]

        if sources is not None:

            choices.extend(
                [
                    "4",
                    "5",
                ]
            )

        choices.append("0")

        console.print(menu)

        choice = Prompt.ask(
            "Select an option",
            choices=choices,
        )

        if choice == "0":
            return

        if choice == "1":

            page = 1

            while True:

                console.clear()

                display_security_summary(
                    observations,
                    sources=sources,
                    total_events=total_events,
                )

                total_pages = display_security_observations(
                    observations,
                    page=page,
                )

                if total_pages <= 1:

                    Prompt.ask(
                        "\nPress Enter to return",
                        default="",
                    )

                    break

                navigation = Prompt.ask(
                    "\n[N]ext  [P]revious  [R]eturn",
                    choices=[
                        "n",
                        "p",
                        "r",
                    ],
                    default="r",
                ).lower()

                if navigation == "n":

                    if page < total_pages:
                        page += 1

                elif navigation == "p":

                    if page > 1:
                        page -= 1

                else:

                    break

        elif choice == "2":

            _observation_list_for_selection(
                observations,
                sources=sources,
                total_events=total_events,
            )

        elif choice == "3":

            filters = _security_filter_menu(
                observations
            )

            if filters is not None:

                _filtered_observation_view(
                    observations,
                    filters,
                    sources=sources,
                    total_events=total_events,
                )

        elif choice == "4" and sources is not None:

            if refresh_callback is None:

                console.print(
                    "\n[yellow]Refresh is not available "
                    "for this dashboard instance.[/yellow]"
                )

                Prompt.ask(
                    "\nPress Enter to return",
                    default="",
                )

                continue

            console.print(
                "\n[cyan]Refreshing security sources...[/cyan]"
            )

            try:

                (
                    refreshed_observations,
                    refreshed_sources,
                    refreshed_total_events,
                ) = refresh_callback()

                observations = refreshed_observations
                sources = refreshed_sources
                total_events = refreshed_total_events

                console.print(
                    "\n[green]Security analysis refreshed successfully.[/green]"
                )

                console.print(
                    f"[dim]Events analyzed: "
                    f"{total_events:,} | "
                    f"Observations: "
                    f"{len(observations):,}[/dim]"
                )

                Prompt.ask(
                    "\nPress Enter to continue",
                    default="",
                )

            except PermissionError:

                console.print(
                    "\n[red]Permission denied while refreshing "
                    "security event sources.[/red]"
                )

                Prompt.ask(
                    "\nPress Enter to continue",
                    default="",
                )

            except Exception as exc:

                console.print(
                    "\n[red]Security analysis refresh failed.[/red]"
                )

                console.print(
                    f"[dim]Reason: {exc}[/dim]"
                )

                Prompt.ask(
                    "\nPress Enter to continue",
                    default="",
                )

        elif choice == "5" and sources is not None:

            _source_diagnostics_menu(
                sources
            )
