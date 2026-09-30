from typing import List, Optional

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from logviewer.analysis.correlation.engine import (
    CorrelationEngine,
    CorrelationFinding,
)

from logviewer.analysis.correlation.display import (
    display_correlation_detail,
    display_correlation_findings,
    display_correlation_menu,
    display_correlation_summary,
    display_search_results,
)

from logviewer.analysis.correlation.filters import (
    CorrelationFilter,
    available_event_types,
    available_ioc_types,
    available_relationships,
    available_severities,
    available_sources,
)

from logviewer.analysis.correlation.investigation import (
    InvestigationContext,
)

from logviewer.analysis.correlation.investigation_display import (
    investigation_workspace,
)

from logviewer.analysis.events.service import EventService
from logviewer.discovery import discover_logs


console = Console()


PAGE_SIZE = 20
TIME_WINDOW_SECONDS = 300


def load_core_events():
    """
    Load real events available to LogViewer Core.

    Sources currently include:

        - discovered filesystem logs
        - Snort events
        - systemd journal events

    All sources are passed through EventService so correlation
    operates on normalized Event objects.
    """

    service = EventService()

    events = []

    logs = discover_logs(
        "/var/log"
    )

    events.extend(
        service.from_files(
            logs
        )
    )

    events.extend(
        service.snort_events()
    )

    events.extend(
        service.journal_events(
            limit=5000
        )
    )

    return service.sort_events(
        events
    )


def build_findings():
    """
    Load current Core events and build correlation findings.
    """

    events = load_core_events()

    engine = CorrelationEngine(
        window_seconds=TIME_WINDOW_SECONDS
    )

    findings = engine.correlate_events(
        events
    )

    return events, findings


def filter_relationship(
    findings: List[CorrelationFinding],
    relationship: str,
) -> List[CorrelationFinding]:
    """
    Return findings matching one relationship type.
    """

    return [
        finding
        for finding in findings
        if finding.relationship == relationship
    ]


def search_findings(
    findings: List[CorrelationFinding],
    query: str,
) -> List[CorrelationFinding]:
    """
    Search findings by IOC value, IOC type, source,
    event type, relationship, description, or evidence context.
    """

    query = query.strip().lower()

    if not query:
        return []

    correlation_filter = CorrelationFilter(
        query=query
    )

    return correlation_filter.apply(
        findings
    )


def _current_page_bounds(
    page: int,
    total_items: int,
) -> tuple[int, int]:
    """
    Return the zero-based start and exclusive end indexes
    for the currently displayed page.
    """

    start = (
        page - 1
    ) * PAGE_SIZE

    end = min(
        start + PAGE_SIZE,
        total_items,
    )

    return start, end


def _get_page_finding(
    findings: List[CorrelationFinding],
    page: int,
    number: int,
) -> Optional[CorrelationFinding]:
    """
    Resolve a finding number shown on the current page.

    The user enters the number displayed by the current page.
    For example, if page 2 displays findings 21-40, entering
    21 selects the first finding on that page.
    """

    if not number:
        return None

    start, end = _current_page_bounds(
        page,
        len(findings),
    )

    first_number = start + 1
    last_number = end

    if not (
        first_number <= number <= last_number
    ):
        return None

    return findings[
        number - 1
    ]


def show_paginated_findings(
    findings: List[CorrelationFinding],
    title: str,
    investigation: InvestigationContext,
) -> None:
    """
    Display findings in pages and allow the analyst
    to inspect individual findings or add them to
    the current investigation.

    Finding numbers correspond to the numbers displayed
    on the current page.
    """

    if not findings:
        display_correlation_findings(
            findings,
            page=1,
            page_size=PAGE_SIZE,
            title=title,
        )

        Prompt.ask(
            "\nPress Enter to return"
        )

        return

    page = 1

    while True:
        total_pages = max(
            1,
            (
                len(findings)
                + PAGE_SIZE
                - 1
            )
            // PAGE_SIZE,
        )

        page = max(
            1,
            min(
                page,
                total_pages,
            ),
        )

        display_correlation_findings(
            findings,
            page=page,
            page_size=PAGE_SIZE,
            title=title,
        )

        start, end = _current_page_bounds(
            page,
            len(findings),
        )

        choice = Prompt.ask(
            "\n[N]ext  [P]revious  "
            "[V]iew  [A]dd  [B]ack",
            default="B",
        ).strip().lower()

        if choice in {
            "b",
            "back",
            "",
        }:
            return

        if choice in {
            "n",
            "next",
        }:
            if page < total_pages:
                page += 1
            else:
                console.print(
                    "[yellow]Already on the last page.[/yellow]"
                )

            continue

        if choice in {
            "p",
            "prev",
            "previous",
        }:
            if page > 1:
                page -= 1
            else:
                console.print(
                    "[yellow]Already on the first page.[/yellow]"
                )

            continue

        if choice in {
            "v",
            "view",
        }:
            view_finding(
                findings,
                page,
            )
            continue

        if choice in {
            "a",
            "add",
        }:
            add_finding_to_investigation(
                findings,
                investigation,
                page,
            )
            continue

        if choice.isdigit():
            number = int(choice)

            finding = _get_page_finding(
                findings,
                page,
                number,
            )

            if finding is not None:
                display_correlation_detail(
                    finding
                )

                Prompt.ask(
                    "\nPress Enter to return"
                )

                continue

            console.print(
                f"[red]Enter a finding number "
                f"shown on the current page "
                f"({start + 1}-{end}).[/red]"
            )

            continue

        console.print(
            "[red]Invalid selection.[/red]"
        )


def view_finding(
    findings: List[CorrelationFinding],
    page: int,
) -> None:
    """
    Ask for a finding number from the current page
    and display its details.
    """

    start, end = _current_page_bounds(
        page,
        len(findings),
    )

    choice = Prompt.ask(
        f"\nEnter finding number "
        f"shown on this page ({start + 1}-{end})",
        default="",
    ).strip()

    if not choice:
        return

    if not choice.isdigit():
        console.print(
            "[red]Please enter a valid finding number.[/red]"
        )
        return

    number = int(choice)

    finding = _get_page_finding(
        findings,
        page,
        number,
    )

    if finding is None:
        console.print(
            f"[red]Finding number must be between "
            f"{start + 1} and {end} on this page.[/red]"
        )
        return

    display_correlation_detail(
        finding
    )

    Prompt.ask(
        "\nPress Enter to return"
    )


def add_finding_to_investigation(
    findings: List[CorrelationFinding],
    investigation: InvestigationContext,
    page: int,
) -> None:
    """
    Add a real correlation finding from the current page
    to the investigation context.
    """

    start, end = _current_page_bounds(
        page,
        len(findings),
    )

    choice = Prompt.ask(
        f"\nEnter finding number to add "
        f"({start + 1}-{end})",
        default="",
    ).strip()

    if not choice:
        return

    if not choice.isdigit():
        console.print(
            "[red]Please enter a valid finding number.[/red]"
        )
        return

    number = int(choice)

    finding = _get_page_finding(
        findings,
        page,
        number,
    )

    if finding is None:
        console.print(
            f"[red]Finding number must be between "
            f"{start + 1} and {end} on this page.[/red]"
        )
        return

    if investigation.add_finding(
        finding
    ):
        console.print(
            "\n[green]Finding added to investigation.[/green]"
        )

        console.print(
            f"[dim]"
            f"{finding.ioc_type.upper()}: "
            f"{finding.value}"
            f"[/dim]"
        )

        console.print(
            f"[dim]"
            f"Relationship: {finding.relationship} | "
            f"Events: {finding.event_count} | "
            f"Sources: {finding.source_count} | "
            f"Evidence: {finding.evidence_count}"
            f"[/dim]"
        )

    else:
        console.print(
            "\n[yellow]Finding is already "
            "in the investigation.[/yellow]"
        )


def _display_filter_options(
    title: str,
    values: List[str],
) -> Optional[str]:
    """
    Display available filter values and return the
    analyst's selected value.

    Returns None when the analyst cancels.
    """

    console.print()

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )

    table.add_column(
        "#",
        justify="right",
        width=6,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    for index, value in enumerate(
        values,
        start=1,
    ):
        table.add_row(
            str(index),
            str(value),
        )

    table.add_row(
        "0",
        "Any / Cancel",
    )

    console.print(
        table
    )

    choice = Prompt.ask(
        "\nSelect",
        default="0",
    ).strip()

    if choice == "0":
        return None

    if not choice.isdigit():
        console.print(
            "[red]Invalid selection.[/red]"
        )
        return None

    index = int(choice)

    if not (
        1 <= index <= len(values)
    ):
        console.print(
            "[red]Invalid selection.[/red]"
        )
        return None

    return values[
        index - 1
    ]


def _prompt_integer(
    prompt: str,
    minimum: int = 0,
) -> Optional[int]:
    """
    Prompt for an optional integer.
    Empty input means no constraint.
    """

    value = Prompt.ask(
        prompt,
        default="",
    ).strip()

    if not value:
        return None

    try:
        number = int(value)
    except ValueError:
        console.print(
            "[red]Please enter a valid integer.[/red]"
        )
        return None

    if number < minimum:
        console.print(
            f"[red]Value must be at least "
            f"{minimum}.[/red]"
        )
        return None

    return number


def _prompt_float(
    prompt: str,
    minimum: float = 0.0,
) -> Optional[float]:
    """
    Prompt for an optional floating-point value.
    Empty input means no constraint.
    """

    value = Prompt.ask(
        prompt,
        default="",
    ).strip()

    if not value:
        return None

    try:
        number = float(value)
    except ValueError:
        console.print(
            "[red]Please enter a valid number.[/red]"
        )
        return None

    if number < minimum:
        console.print(
            f"[red]Value must be at least "
            f"{minimum}.[/red]"
        )
        return None

    return number


def _run_investigation_filters(
    findings: List[CorrelationFinding],
    investigation: InvestigationContext,
) -> None:
    """
    Run the interactive investigation filter workflow.

    The current investigation context is preserved while
    filtered findings are being viewed.
    """

    if not findings:
        console.print(
            "[yellow]There are no findings available "
            "for filtering.[/yellow]"
        )

        Prompt.ask(
            "\nPress Enter to return"
        )

        return

    filtered = findings

    active_filters = {}

    while True:
        console.print()

        table = Table(
            title="Investigation Filters",
            show_header=True,
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Option",
            justify="center",
            width=8,
        )

        table.add_column(
            "Filter",
            width=28,
        )

        table.add_column(
            "Current",
            overflow="fold",
        )

        table.add_row(
            "1",
            "IOC Type",
            active_filters.get(
                "ioc_type",
                "Any",
            ),
        )

        table.add_row(
            "2",
            "Relationship",
            active_filters.get(
                "relationship",
                "Any",
            ),
        )

        table.add_row(
            "3",
            "Source",
            active_filters.get(
                "source",
                "Any",
            ),
        )

        table.add_row(
            "4",
            "Event Type",
            active_filters.get(
                "event_type",
                "Any",
            ),
        )

        table.add_row(
            "5",
            "Severity",
            active_filters.get(
                "severity",
                "Any",
            ),
        )

        table.add_row(
            "6",
            "Keyword / Context",
            active_filters.get(
                "query",
                "Any",
            ),
        )

        table.add_row(
            "7",
            "Minimum Events",
            active_filters.get(
                "min_events",
                "Any",
            ),
        )

        table.add_row(
            "8",
            "Maximum Events",
            active_filters.get(
                "max_events",
                "Any",
            ),
        )

        table.add_row(
            "9",
            "Minimum Sources",
            active_filters.get(
                "min_sources",
                "Any",
            ),
        )

        table.add_row(
            "T",
            "Time Span",
            active_filters.get(
                "time_span",
                "Any",
            ),
        )

        table.add_row(
            "A",
            "Apply / Browse",
            f"{len(filtered):,} matching",
        )

        table.add_row(
            "C",
            "Clear filters",
            "-",
        )

        table.add_row(
            "0",
            "Back",
            "-",
        )

        console.print(
            table
        )

        choice = Prompt.ask(
            "\nSelect filter",
            default="0",
        ).strip().upper()

        if choice == "0":
            return

        if choice == "1":
            value = _display_filter_options(
                "Available IOC Types",
                available_ioc_types(
                    findings
                ),
            )

            if value is not None:
                active_filters[
                    "ioc_type"
                ] = value
            else:
                active_filters.pop(
                    "ioc_type",
                    None,
                )

        elif choice == "2":
            value = _display_filter_options(
                "Available Relationships",
                available_relationships(
                    findings
                ),
            )

            if value is not None:
                active_filters[
                    "relationship"
                ] = value
            else:
                active_filters.pop(
                    "relationship",
                    None,
                )

        elif choice == "3":
            value = _display_filter_options(
                "Available Sources",
                available_sources(
                    findings
                ),
            )

            if value is not None:
                active_filters[
                    "source"
                ] = value
            else:
                active_filters.pop(
                    "source",
                    None,
                )

        elif choice == "4":
            value = _display_filter_options(
                "Available Event Types",
                available_event_types(
                    findings
                ),
            )

            if value is not None:
                active_filters[
                    "event_type"
                ] = value
            else:
                active_filters.pop(
                    "event_type",
                    None,
                )

        elif choice == "5":
            value = _display_filter_options(
                "Available Severities",
                available_severities(
                    findings
                ),
            )

            if value is not None:
                active_filters[
                    "severity"
                ] = value
            else:
                active_filters.pop(
                    "severity",
                    None,
                )

        elif choice == "6":
            query = Prompt.ask(
                "\nKeyword / IOC / context",
                default="",
            ).strip()

            if query:
                active_filters[
                    "query"
                ] = query
            else:
                active_filters.pop(
                    "query",
                    None,
                )

        elif choice == "7":
            value = _prompt_integer(
                "\nMinimum event count",
                minimum=0,
            )

            if value is not None:
                active_filters[
                    "min_events"
                ] = value
            else:
                active_filters.pop(
                    "min_events",
                    None,
                )

        elif choice == "8":
            value = _prompt_integer(
                "\nMaximum event count",
                minimum=0,
            )

            if value is not None:
                active_filters[
                    "max_events"
                ] = value
            else:
                active_filters.pop(
                    "max_events",
                    None,
                )

        elif choice == "9":
            value = _prompt_integer(
                "\nMinimum source count",
                minimum=0,
            )

            if value is not None:
                active_filters[
                    "min_sources"
                ] = value
            else:
                active_filters.pop(
                    "min_sources",
                    None,
                )

        elif choice == "T":
            console.print(
                "\nLeave both values blank for no time constraint."
            )

            minimum = _prompt_float(
                "Minimum time span in seconds",
                minimum=0.0,
            )

            maximum = _prompt_float(
                "Maximum time span in seconds",
                minimum=0.0,
            )

            if (
                minimum is None
                and maximum is None
            ):
                active_filters.pop(
                    "min_time_span",
                    None,
                )

                active_filters.pop(
                    "max_time_span",
                    None,
                )

                active_filters.pop(
                    "time_span",
                    None,
                )

            else:
                if minimum is not None:
                    active_filters[
                        "min_time_span"
                    ] = minimum
                else:
                    active_filters.pop(
                        "min_time_span",
                        None,
                    )

                if maximum is not None:
                    active_filters[
                        "max_time_span"
                    ] = maximum
                else:
                    active_filters.pop(
                        "max_time_span",
                        None,
                    )

                minimum_text = (
                    str(minimum)
                    if minimum is not None
                    else "-"
                )

                maximum_text = (
                    str(maximum)
                    if maximum is not None
                    else "-"
                )

                active_filters[
                    "time_span"
                ] = (
                    f"{minimum_text}–"
                    f"{maximum_text} seconds"
                )

        elif choice == "A":
            correlation_filter = CorrelationFilter(
                ioc_type=active_filters.get(
                    "ioc_type"
                ),
                relationship=active_filters.get(
                    "relationship"
                ),
                source=active_filters.get(
                    "source"
                ),
                event_type=active_filters.get(
                    "event_type"
                ),
                severity=active_filters.get(
                    "severity"
                ),
                query=active_filters.get(
                    "query"
                ),
                min_events=active_filters.get(
                    "min_events"
                ),
                max_events=active_filters.get(
                    "max_events"
                ),
                min_sources=active_filters.get(
                    "min_sources"
                ),
                min_time_span=active_filters.get(
                    "min_time_span"
                ),
                max_time_span=active_filters.get(
                    "max_time_span"
                ),
            )

            filtered = correlation_filter.apply(
                findings
            )

            console.print(
                f"\n[cyan]Filter result:[/cyan] "
                f"{len(filtered):,} of "
                f"{len(findings):,} findings"
            )

            if active_filters:
                console.print(
                    "[dim]Active filters:[/dim]"
                )

                for key, value in active_filters.items():
                    if key in {
                        "min_time_span",
                        "max_time_span",
                    }:
                        continue

                    console.print(
                        f"  [dim]{key}: "
                        f"{value}[/dim]"
                    )

            show_paginated_findings(
                filtered,
                "Filtered Correlation Findings",
                investigation,
            )

        elif choice == "C":
            active_filters.clear()
            filtered = findings

            console.print(
                "\n[green]All investigation filters cleared.[/green]"
            )

        else:
            console.print(
                "[red]Invalid selection.[/red]"
            )


def security_correlation_dashboard():
    """
    Run the Core Security Correlation dashboard.
    """

    investigation = InvestigationContext()

    console.print()

    console.print(
        "[bold cyan]SECURITY CORRELATION[/bold cyan]"
    )

    console.print(
        "[dim]Analyzing normalized events and identifying "
        "evidence-backed IOC relationships.[/dim]\n"
    )

    try:
        events, findings = build_findings()

    except Exception as exc:
        console.print(
            "[red]Unable to load events for correlation.[/red]"
        )

        console.print(
            f"[dim]{exc}[/dim]"
        )

        Prompt.ask(
            "\nPress Enter to return"
        )

        return

    display_correlation_summary(
        findings=findings,
        event_count=len(events),
    )

    while True:
        display_correlation_menu()

        choice = Prompt.ask(
            "\nSelect view",
            default="0",
        ).strip().upper()

        if choice == "0":
            return

        if choice == "1":
            filtered = filter_relationship(
                findings,
                "cross_source_temporal",
            )

            show_paginated_findings(
                filtered,
                "Cross-source + Temporal Findings",
                investigation,
            )

            continue

        if choice == "2":
            filtered = filter_relationship(
                findings,
                "cross_source",
            )

            show_paginated_findings(
                filtered,
                "Cross-source Findings",
                investigation,
            )

            continue

        if choice == "3":
            filtered = filter_relationship(
                findings,
                "repeated",
            )

            show_paginated_findings(
                filtered,
                "Repeated Findings",
                investigation,
            )

            continue

        if choice == "4":
            filtered = filter_relationship(
                findings,
                "observed",
            )

            show_paginated_findings(
                filtered,
                "Observed Findings",
                investigation,
            )

            continue

        if choice == "5":
            query = Prompt.ask(
                "\nEnter IOC, IOC type, "
                "source, or keyword",
                default="",
            ).strip()

            if not query:
                continue

            results = search_findings(
                findings,
                query,
            )

            display_search_results(
                results,
                query,
            )

            if results:
                view = Prompt.ask(
                    "\nEnter finding number to inspect "
                    "or press Enter to return",
                    default="",
                ).strip()

                if view.isdigit():
                    number = int(view)

                    if 1 <= number <= len(results):
                        display_correlation_detail(
                            results[
                                number - 1
                            ]
                        )

                        Prompt.ask(
                            "\nPress Enter to return"
                        )

            continue

        if choice == "6":
            show_paginated_findings(
                findings,
                "All Security Correlation Findings",
                investigation,
            )

            continue

        if choice == "7":
            _run_investigation_filters(
                findings,
                investigation,
            )

            continue

        if choice == "8":
            console.print(
                "\n[cyan]Refreshing correlation analysis...[/cyan]\n"
            )

            try:
                events, findings = build_findings()

            except Exception as exc:
                console.print(
                    "[red]Unable to refresh correlation analysis.[/red]"
                )

                console.print(
                    f"[dim]{exc}[/dim]"
                )

                Prompt.ask(
                    "\nPress Enter to continue"
                )

                continue

            display_correlation_summary(
                findings=findings,
                event_count=len(events),
            )

            console.print(
                "[green]Correlation analysis refreshed successfully.[/green]"
            )

            continue

        if choice == "I":
            console.print(
                "\n[cyan]Investigation Workspace[/cyan]\n"
            )

            investigation = investigation_workspace(
                investigation=investigation,
            )

            continue

        console.print(
            "[red]Invalid selection.[/red]"
        )
