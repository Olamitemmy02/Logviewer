from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule

from .pro.investigation.workspace import run_investigation_workspace
from .logger import write_log


console = Console()


def _load_security_analysis_data():
    """
    Load fresh security sources and generate fresh observations.

    This function is intentionally kept outside the display layer so
    ingestion and analysis remain separate from UI rendering.
    """

    from .analysis.security import (
        SecurityAnalyzer,
        load_security_analysis,
    )

    load_result = load_security_analysis()

    analyzer = SecurityAnalyzer()

    observations = analyzer.analyze_events(
        load_result.events
    )

    return (
        observations,
        load_result.sources,
        load_result.total_events,
    )


def _print_application_header():
    """
    Render the main LogViewer application header.
    """

    title = Text()

    title.append(
        "LOG",
        style="bold cyan"
    )

    title.append(
        "VIEWER",
        style="bold white"
    )

    subtitle = Text(
        "Linux Security Log Analysis & Threat Investigation",
        style="bold cyan"
    )

    description = Text(
        "Evidence-driven analysis of available host events, "
        "security observations and investigation data.",
        style="dim white"
    )

    header = Panel(
        Align.center(
            Text.assemble(
                title,
                "\n",
                subtitle,
                "\n\n",
                description,
            )
        ),
        border_style="cyan",
        padding=(1, 3),
    )

    console.print()
    console.print(header)
    console.print()


def _print_menu_status():
    """
    Render a compact application context/status area.

    These values describe the application rather than claiming
    real-time system health or security status.
    """

    core_status = Panel(
        Text.assemble(
            ("CORE\n", "bold cyan"),
            ("Log collection and analysis", "white"),
        ),
        border_style="cyan",
        padding=(0, 2),
    )

    pro_status = Panel(
        Text.assemble(
            ("PRO\n", "bold magenta"),
            ("Structured investigations", "white"),
        ),
        border_style="magenta",
        padding=(0, 2),
    )

    application_status = Panel(
        Text.assemble(
            ("APPLICATION\n", "bold green"),
            ("Configuration and information", "white"),
        ),
        border_style="green",
        padding=(0, 2),
    )

    console.print(
        Columns(
            [
                core_status,
                pro_status,
                application_status,
            ],
            equal=True,
            expand=True,
        )
    )

    console.print()


def _build_core_menu():
    """
    Build the LogViewer Core navigation table.
    """

    table = Table(
        title="[bold cyan]LOGVIEWER CORE[/bold cyan]",
        caption="[dim]Everyday log collection, inspection and security analysis[/dim]",
        border_style="cyan",
        expand=True,
        padding=(0, 1),
        show_lines=False,
    )

    table.add_column(
        "Option",
        style="bold cyan",
        justify="center",
        width=7,
    )

    table.add_column(
        "Function",
        style="bold white",
        width=24,
    )

    table.add_column(
        "Description",
        style="dim white",
    )

    table.add_row(
        "1",
        "View Logs",
        "Inspect available system log events.",
    )

    table.add_row(
        "2",
        "Search Logs",
        "Search event data using defined criteria.",
    )

    table.add_row(
        "3",
        "Live Monitor",
        "Monitor supported log activity as it is received.",
    )

    table.add_row(
        "4",
        "Statistics",
        "Review event and log-source statistics.",
    )

    table.add_row(
        "5",
        "Export Reports",
        "Export supported analysis and investigation information.",
    )

    table.add_row(
        "6",
        "Settings",
        "Configure supported LogViewer application settings.",
    )

    table.add_row(
        "7",
        "Filters",
        "Narrow displayed events using available filters.",
    )

    table.add_row(
        "8",
        "Snort Alert Summary",
        "Review Snort alerts when installed alert data is available.",
    )

    table.add_row(
        "9",
        "Log Sources",
        "Discover and inspect readable host log sources.",
    )

    table.add_row(
        "10",
        "Security Correlation",
        "Identify relationships between related security events.",
    )

    table.add_row(
        "11",
        "Security Analysis",
        "Generate security observations from available events.",
    )

    return table


def _build_pro_menu():
    """
    Build the LogViewer Pro navigation table.
    """

    table = Table(
        title="[bold magenta]LOGVIEWER PRO[/bold magenta]",
        caption="[dim]Structured investigation and evidence analysis capabilities[/dim]",
        border_style="magenta",
        expand=True,
        padding=(0, 1),
        show_lines=False,
    )

    table.add_column(
        "Option",
        style="bold magenta",
        justify="center",
        width=7,
    )

    table.add_column(
        "Investigation Function",
        style="bold white",
        width=32,
    )

    table.add_column(
        "Description",
        style="dim white",
    )

    table.add_row(
        "12",
        "Pro Investigation",
        "Work with structured investigation records and stored analytical results.",
    )

    table.add_row(
        "13",
        "Investigation Timeline",
        "Review investigation activity chronologically.",
    )

    table.add_row(
        "14",
        "Investigation Findings",
        "Review structured findings and their supporting investigation context.",
    )

    return table


def _build_application_menu():
    """
    Build the application-level navigation table.
    """

    table = Table(
        title="[bold green]APPLICATION[/bold green]",
        caption="[dim]License management and application information[/dim]",
        border_style="green",
        expand=True,
        padding=(0, 1),
        show_lines=False,
    )

    table.add_column(
        "Option",
        style="bold green",
        justify="center",
        width=7,
    )

    table.add_column(
        "Function",
        style="bold white",
        width=24,
    )

    table.add_column(
        "Description",
        style="dim white",
    )

    table.add_row(
        "15",
        "License Management",
        "Activate, inspect or deactivate a LogViewer Pro license.",
    )

    table.add_row(
        "16",
        "About",
        "Learn about LogViewer, its architecture, capabilities and scope.",
    )

    table.add_row(
        "0",
        "Exit",
        "Close the LogViewer application.",
    )

    return table


def _show_license_management():
    """
    Open the LogViewer license-management interface.

    LicenseConsole owns the activation, status and deactivation
    workflow. This menu only provides application-level navigation
    into that workflow.
    """

    from .licensing.console import LicenseConsole

    console.print()

    try:
        license_console = LicenseConsole(
            console=console,
        )

        license_console.menu()

    except Exception as exc:
        console.print(
            Panel(
                "[red]The license-management interface "
                "could not be opened.[/red]\n\n"
                f"[dim]Reason: {exc}[/dim]",
                title="LICENSE MANAGEMENT",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )


def _show_about():
    """
    Display truthful and comprehensive information about LogViewer.

    Core and Pro capabilities are presented separately so the
    application interface accurately reflects the product structure.
    """

    console.print()

    about_text = Text()

    about_text.append(
        "LOGVIEWER\n",
        style="bold cyan"
    )

    about_text.append(
        "Linux Security Log Analysis and Threat Investigation Platform\n\n",
        style="bold white"
    )

    about_text.append(
        "LogViewer is a Python-based terminal application for working "
        "with security-relevant log data and events collected from "
        "Linux systems.\n\n",
        style="white"
    )

    about_text.append(
        "The platform provides a Core layer for collecting, viewing, "
        "searching, filtering and analyzing available system logs, "
        "along with additional Pro investigation capabilities for "
        "structured evidence analysis and investigation workflows.",
        style="white"
    )

    console.print(
        Panel(
            about_text,
            title="[bold cyan]ABOUT LOGVIEWER[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    console.print()

    core_capabilities = Table(
        title="[bold cyan]LOGVIEWER CORE[/bold cyan]",
        border_style="cyan",
        expand=True,
    )

    core_capabilities.add_column(
        "Capability",
        style="bold cyan"
    )

    core_capabilities.add_column(
        "Description",
        style="white"
    )

    core_capabilities.add_row(
        "Log Discovery",
        "Discovers readable log sources available on the Linux host."
    )

    core_capabilities.add_row(
        "Log Collection",
        "Loads available system log data into LogViewer's event-processing pipeline."
    )

    core_capabilities.add_row(
        "Log Viewing",
        "Displays collected events for inspection and investigation."
    )

    core_capabilities.add_row(
        "Search",
        "Searches available log events using user-defined criteria."
    )

    core_capabilities.add_row(
        "Filtering",
        "Narrows event data using supported log and security filters."
    )

    core_capabilities.add_row(
        "Statistics",
        "Provides summaries of event activity and discovered log sources."
    )

    core_capabilities.add_row(
        "IOC Extraction",
        "Extracts supported indicators such as IP addresses, domains, URLs and hashes from event data."
    )

    core_capabilities.add_row(
        "Snort Integration",
        "Reads and summarizes Snort alert data when Snort alert sources are available on the host."
    )

    core_capabilities.add_row(
        "Security Correlation",
        "Identifies relationships between related security events and evidence."
    )

    core_capabilities.add_row(
        "Security Analysis",
        "Generates security observations from available security-relevant events."
    )

    core_capabilities.add_row(
        "Report Export",
        "Exports supported LogViewer analysis and investigation information."
    )

    console.print(core_capabilities)

    console.print()

    pro_capabilities = Table(
        title="[bold magenta]LOGVIEWER PRO[/bold magenta]",
        border_style="magenta",
        expand=True,
    )

    pro_capabilities.add_column(
        "Capability",
        style="bold magenta"
    )

    pro_capabilities.add_column(
        "Description",
        style="white"
    )

    pro_capabilities.add_row(
        "Investigations",
        "Provides structured investigation objects that combine events, evidence and analytical results."
    )

    pro_capabilities.add_row(
        "Evidence Relationships",
        "Organizes relationships between events, evidence, indicators and correlated activity."
    )

    pro_capabilities.add_row(
        "MITRE Mapping",
        "Associates investigation evidence with supported MITRE ATT&CK technique mappings."
    )

    pro_capabilities.add_row(
        "Threat Scoring",
        "Calculates an investigation threat score and supporting score details."
    )

    pro_capabilities.add_row(
        "False-Positive Analysis",
        "Records contextual information that can help analysts assess potential benign explanations."
    )

    pro_capabilities.add_row(
        "Process Relationships",
        "Represents available process relationships as an investigation process tree."
    )

    pro_capabilities.add_row(
        "Attack Chain",
        "Organizes related investigation activity into chronological attack-chain steps when supported by available evidence."
    )

    pro_capabilities.add_row(
        "Investigation Timeline",
        "Presents investigation events, correlations, mappings and related analytical activity chronologically."
    )

    pro_capabilities.add_row(
        "Investigation Findings",
        "Generates structured findings from investigation events, correlations and MITRE mappings with supporting context."
    )

    pro_capabilities.add_row(
        "Investigation Persistence",
        "Stores structured investigation results so they can be reviewed after analysis."
    )

    console.print(pro_capabilities)

    console.print()

    data_sources = Table(
        title="[bold cyan]DATA AND ANALYSIS MODEL[/bold cyan]",
        border_style="cyan",
        expand=True,
    )

    data_sources.add_column(
        "Area",
        style="bold cyan"
    )

    data_sources.add_column(
        "Description",
        style="white"
    )

    data_sources.add_row(
        "Host Logs",
        "Uses readable log sources available on the local Linux system."
    )

    data_sources.add_row(
        "System Events",
        "Processes normalized events produced from supported log sources."
    )

    data_sources.add_row(
        "Security Evidence",
        "Uses event content, extracted indicators and relationships as analytical evidence."
    )

    data_sources.add_row(
        "Analysis",
        "Correlation and security analysis operate on available event data rather than fabricated demonstration events."
    )

    data_sources.add_row(
        "Investigation",
        "Pro investigation features combine available evidence into structured investigation records."
    )

    console.print(data_sources)

    console.print()

    architecture = Table(
        title="[bold cyan]PLATFORM STRUCTURE[/bold cyan]",
        border_style="cyan",
        expand=True,
    )

    architecture.add_column(
        "Layer",
        style="bold cyan"
    )

    architecture.add_column(
        "Purpose",
        style="white"
    )

    architecture.add_row(
        "Ingestion",
        "Discover and read supported log sources."
    )

    architecture.add_row(
        "Normalization",
        "Represent different log formats as common event data."
    )

    architecture.add_row(
        "IOC Analysis",
        "Extract supported indicators from event content."
    )

    architecture.add_row(
        "Correlation",
        "Identify relationships between related events and evidence."
    )

    architecture.add_row(
        "Security Analysis",
        "Generate security observations from available events."
    )

    architecture.add_row(
        "Investigation",
        "Combine evidence and analytical results into structured Pro investigations."
    )

    architecture.add_row(
        "Presentation",
        "Expose analysis and investigation results through the Rich terminal interface."
    )

    console.print(architecture)

    console.print()

    project_info = Table(
        title="[bold cyan]PROJECT INFORMATION[/bold cyan]",
        border_style="cyan",
        expand=True,
    )

    project_info.add_column(
        "Property",
        style="bold cyan"
    )

    project_info.add_column(
        "Value",
        style="white"
    )

    project_info.add_row(
        "Project",
        "LogViewer"
    )

    project_info.add_row(
        "Purpose",
        "Linux security log analysis and threat investigation"
    )

    project_info.add_row(
        "Implementation",
        "Python"
    )

    project_info.add_row(
        "Interface",
        "Rich terminal user interface"
    )

    project_info.add_row(
        "Primary Data",
        "Security-relevant Linux log and event data"
    )

    project_info.add_row(
        "Architecture",
        "Core analysis with separately gated Pro investigation capabilities"
    )

    console.print(project_info)

    console.print()

    console.print(
        Panel(
            "[bold cyan]LogViewer is designed for practical "
            "log analysis, security investigation, research, "
            "administration and cybersecurity learning.[/bold cyan]\n\n"
            "[dim]Results depend on the log sources available to "
            "the host and the evidence contained in those sources. "
            "Analytical findings should therefore be interpreted "
            "within their available evidence and context.[/dim]",
            title="[bold cyan]PROJECT SCOPE[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    Prompt.ask(
        "\nPress Enter to return",
        default=""
    )


def _show_pro_investigation():
    """
    Open the LogViewer Pro investigation interface.
    """

    from .licensing.feature_gate import (
        FeatureAccessError,
        FeatureGate,
    )

    from .pro.investigation.service import (
        InvestigationService,
    )

    console.print(
        "\n[bold magenta]LOGVIEWER PRO INVESTIGATION[/bold magenta]\n"
    )

    try:
        feature_gate = FeatureGate()

        feature_gate.require(
            "investigation"
        )

        service = InvestigationService(
            feature_gate=feature_gate
        )

        console.print(
            Panel(
                "[bold white]Structured Pro investigations[/bold white]\n\n"
                "Work with investigation records that combine "
                "events, evidence and analytical results.\n\n"
                "[dim]Detailed investigation capabilities are provided "
                "through the Pro investigation service.[/dim]",
                title="[bold magenta]PRO INVESTIGATION[/bold magenta]",
                border_style="magenta",
            )
        )

        investigations = service.list()

        if not investigations:
            console.print(
                Panel(
                    "[yellow]No stored investigations are currently available.[/yellow]\n\n"
                    "[dim]Create or process a Pro Investigation before "
                    "reviewing stored investigation records.[/dim]",
                    title="INVESTIGATION STORE",
                    border_style="yellow",
                )
            )

            Prompt.ask(
                "\nPress Enter to return",
                default=""
            )

            return

        table = Table(
            title="[bold magenta]STORED INVESTIGATIONS[/bold magenta]",
            border_style="magenta",
            expand=True,
        )

        table.add_column(
            "#",
            style="bold magenta",
            justify="center",
        )

        table.add_column(
            "Investigation",
            style="bold white",
        )

        table.add_column(
            "Status",
            style="cyan",
        )

        table.add_column(
            "Severity",
            style="yellow",
        )

        table.add_column(
            "Findings",
            style="green",
            justify="right",
        )

        for index, investigation in enumerate(
            investigations,
            start=1,
        ):
            summary = investigation.summary()

            table.add_row(
                str(index),
                str(
                    getattr(
                        investigation,
                        "title",
                        None,
                    )
                    or getattr(
                        investigation,
                        "investigation_id",
                        None,
                    )
                    or "Untitled Investigation"
                ),
                str(
                    getattr(
                        investigation,
                        "status",
                        None,
                    )
                    or "unknown"
                ),
                str(
                    getattr(
                        investigation,
                        "severity",
                        None,
                    )
                    or "unknown"
                ),
                str(
                    summary.get(
                        "finding_count",
                        len(
                            getattr(
                                investigation,
                                "findings",
                                []
                            )
                        ),
                    )
                ),
            )

        console.print(table)

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except FeatureAccessError:
        console.print(
            Panel(
                "[yellow]The Pro Investigation feature "
                "is not enabled for the current license.[/yellow]\n\n"
                "[dim]LogViewer Core remains available. "
                "A valid Pro license is required for this feature.[/dim]",
                title="PRO FEATURE",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except PermissionError:
        console.print(
            Panel(
                "[red]Permission denied while accessing "
                "the investigation store.[/red]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except Exception as exc:
        console.print(
            Panel(
                "[red]The Pro Investigation interface "
                "could not be opened.[/red]\n\n"
                f"[dim]Reason: {exc}[/dim]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )


def _show_pro_investigation_timeline():
    """
    Open the LogViewer Pro investigation timeline.
    """

    from .licensing.feature_gate import (
        FeatureAccessError,
        FeatureGate,
    )

    from .pro.investigation.display import (
        timeline_investigation_menu,
    )

    from .pro.investigation.service import (
        InvestigationService,
    )

    console.print(
        "\n[bold magenta]PRO INVESTIGATION TIMELINE[/bold magenta]\n"
    )

    try:
        feature_gate = FeatureGate()

        feature_gate.require(
            "investigation"
        )

        service = InvestigationService(
            feature_gate=feature_gate
        )

        investigations = service.list()

        timeline_investigation_menu(
            investigations,
            service,
        )

    except FeatureAccessError:
        console.print(
            Panel(
                "[yellow]The Pro Investigation feature "
                "is not enabled for the current license.[/yellow]\n\n"
                "[dim]The timeline is part of the LogViewer Pro "
                "investigation workflow.[/dim]",
                title="PRO FEATURE",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except PermissionError:
        console.print(
            Panel(
                "[red]Permission denied while accessing "
                "the investigation store.[/red]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except Exception as exc:
        console.print(
            Panel(
                "[red]The Pro Investigation Timeline "
                "could not be opened.[/red]\n\n"
                f"[dim]Reason: {exc}[/dim]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )


def _show_pro_investigation_findings():
    """
    Open the LogViewer Pro investigation findings interface.

    InvestigationService.list() returns summary dictionaries.
    The selected investigation is therefore resolved through
    InvestigationService.get() before it is passed to findings_menu().
    """

    from .licensing.feature_gate import (
        FeatureAccessError,
        FeatureGate,
    )

    from .pro.investigation.display import (
        findings_menu,
    )

    from .pro.investigation.service import (
        InvestigationService,
    )

    console.print(
        "\n[bold magenta]PRO INVESTIGATION FINDINGS[/bold magenta]\n"
    )

    try:
        feature_gate = FeatureGate()

        feature_gate.require(
            "investigation"
        )

        service = InvestigationService(
            feature_gate=feature_gate
        )

        investigations = service.list()

        if not investigations:
            console.print(
                Panel(
                    "[yellow]No stored investigations are available.[/yellow]\n\n"
                    "[dim]Create a Pro Investigation first so that "
                    "evidence-driven findings can be generated.[/dim]",
                    title="PRO INVESTIGATION",
                    border_style="yellow",
                )
            )

            Prompt.ask(
                "\nPress Enter to return",
                default=""
            )

            return

        table = Table(
            title="[bold magenta]STORED INVESTIGATIONS[/bold magenta]",
            border_style="magenta",
            expand=True,
        )

        table.add_column(
            "#",
            style="bold magenta",
            justify="center",
        )

        table.add_column(
            "Investigation",
            style="bold white",
        )

        table.add_column(
            "Status",
            style="cyan",
        )

        table.add_column(
            "Severity",
            style="yellow",
        )

        table.add_column(
            "Findings",
            style="green",
            justify="right",
        )

        for index, investigation in enumerate(
            investigations,
            start=1,
        ):
            if isinstance(investigation, dict):
                investigation_id = (
                    investigation.get("investigation_id")
                    or investigation.get("id")
                )

                title = (
                    investigation.get("title")
                    or investigation_id
                    or "Untitled Investigation"
                )

                status = (
                    investigation.get("status")
                    or "unknown"
                )

                severity = (
                    investigation.get("severity")
                    or "unknown"
                )

                finding_count = investigation.get(
                    "finding_count",
                    len(investigation.get("findings", []))
                    if isinstance(
                        investigation.get("findings", []),
                        list,
                    )
                    else 0,
                )

            else:
                investigation_id = getattr(
                    investigation,
                    "investigation_id",
                    None,
                )

                title = (
                    getattr(
                        investigation,
                        "title",
                        None,
                    )
                    or investigation_id
                    or "Untitled Investigation"
                )

                status = (
                    getattr(
                        investigation,
                        "status",
                        None,
                    )
                    or "unknown"
                )

                severity = (
                    getattr(
                        investigation,
                        "severity",
                        None,
                    )
                    or "unknown"
                )

                finding_count = len(
                    getattr(
                        investigation,
                        "findings",
                        [],
                    )
                )

            table.add_row(
                str(index),
                str(title),
                str(status),
                str(severity),
                str(finding_count),
            )

        console.print(table)

        console.print()

        raw_choice = Prompt.ask(
            "Select investigation number or press Enter to return",
            default="",
        ).strip()

        if not raw_choice:
            return

        try:
            selected_index = int(raw_choice)

        except ValueError:
            console.print(
                "[red]Invalid investigation selection.[/red]"
            )

            Prompt.ask(
                "\nPress Enter to return",
                default=""
            )

            return

        if selected_index < 1 or selected_index > len(
            investigations
        ):
            console.print(
                "[red]Invalid investigation selection.[/red]"
            )

            Prompt.ask(
                "\nPress Enter to return",
                default=""
            )

            return

        selected = investigations[
            selected_index - 1
        ]

        if isinstance(selected, dict):
            investigation_id = (
                selected.get("investigation_id")
                or selected.get("id")
            )
        else:
            investigation_id = getattr(
                selected,
                "investigation_id",
                None,
            )

        if not investigation_id:
            raise ValueError(
                "The selected investigation does not contain a valid ID."
            )

        investigation = service.get(
            str(investigation_id)
        )

        if investigation is None:
            raise ValueError(
                f"Investigation '{investigation_id}' could not be loaded."
            )

        findings_menu(
            investigation
        )

    except FeatureAccessError:
        console.print(
            Panel(
                "[yellow]The Pro Investigation feature "
                "is not enabled for the current license.[/yellow]\n\n"
                "[dim]Findings are part of the LogViewer Pro "
                "investigation workflow.[/dim]",
                title="PRO FEATURE",
                border_style="yellow",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except PermissionError:
        console.print(
            Panel(
                "[red]Permission denied while accessing "
                "the investigation store.[/red]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )

    except Exception as exc:
        import traceback

        console.print(
            Panel(
                "[red]The Pro Investigation Findings "
                "could not be opened.[/red]\n\n"
                f"[dim]Reason: {exc}[/dim]",
                title="PRO INVESTIGATION",
                border_style="red",
            )
        )

        console.print("\n[bold red]TRACEBACK[/bold red]")
        console.print(traceback.format_exc())

        Prompt.ask(
            "\nPress Enter to return",
            default=""
        )


def main_menu():

    write_log(
        "system",
        "INFO",
        "Application started"
    )

    while True:

        _print_application_header()
        _print_menu_status()

        console.print(
            _build_core_menu()
        )

        console.print()

        console.print(
            _build_pro_menu()
        )

        console.print()

        console.print(
            _build_application_menu()
        )

        console.print()

        console.print(
            Rule(
                "[bold cyan]LOGVIEWER[/bold cyan]  "
                "[dim]Select an option to continue[/dim]",
                style="cyan",
            )
        )

        choice = Prompt.ask(
            "Select option"
        ).strip()

        if choice == "0":

            console.print()

            console.print(
                Panel(
                    "[bold cyan]LogViewer session closed.[/bold cyan]\n"
                    "[dim]Thank you for using LogViewer.[/dim]",
                    border_style="cyan",
                    padding=(1, 3),
                )
            )

            break

        elif choice == "1":

            from .viewer import view_logs

            view_logs()

        elif choice == "2":

            from .search import search_menu

            search_menu()

        elif choice == "3":

            from .monitor import monitor_menu

            monitor_menu()

        elif choice == "4":

            from .statistics import statistics_dashboard

            statistics_dashboard()

        elif choice == "5":

            from .exporter import exporter_menu

            exporter_menu()

        elif choice == "6":

            from .settings import settings_menu

            settings_menu()

        elif choice == "7":

            from .filters import filter_menu

            filter_menu()

        elif choice == "8":

            from .snort_summary import show_snort_summary

            show_snort_summary()

        elif choice == "9":

            from .discovery import (
                discover_logs,
                get_log_statistics
            )

            stats = get_log_statistics(
                "/var/log"
            )

            logs = stats["logs"]

            console.print(
                "\n[bold cyan]LOG SOURCES[/bold cyan]\n"
            )

            console.print(
                "[green]Root:[/green] /var/log"
            )

            console.print(
                f"[green]Readable logs:[/green] "
                f"{len(logs)}\n"
            )

            source_table = Table(
                title="Discovered System Logs"
            )

            source_table.add_column(
                "#",
                style="yellow"
            )

            source_table.add_column(
                "Log File",
                style="green"
            )

            for index, path in enumerate(
                logs,
                start=1
            ):
                source_table.add_row(
                    str(index),
                    str(path)
                )

            if logs:
                console.print(
                    source_table
                )

            else:
                console.print(
                    "[yellow]No readable logs found.[/yellow]"
                )

        elif choice == "10":

            from .analysis.correlation.dashboard import (
                security_correlation_dashboard
            )

            security_correlation_dashboard()

        elif choice == "11":

            from .analysis.security.display import (
                security_analysis_dashboard
            )

            console.print(
                "\n[bold cyan]SECURITY ANALYSIS[/bold cyan]\n"
            )

            console.print(
                "[dim]Analyzing available system security events...[/dim]\n"
            )

            try:

                (
                    observations,
                    sources,
                    total_events,
                ) = _load_security_analysis_data()

                security_analysis_dashboard(
                    observations,
                    sources=sources,
                    total_events=total_events,
                    refresh_callback=_load_security_analysis_data,
                )

            except PermissionError:

                console.print(
                    "\n[red]Security Analysis could not be completed.[/red]"
                )

                console.print(
                    "[yellow]Check access to the required "
                    "system logs and journal.[/yellow]"
                )

                Prompt.ask(
                    "\nPress Enter to return",
                    default=""
                )

            except Exception as exc:

                console.print(
                    "\n[red]Security Analysis could not be completed.[/red]"
                )

                console.print(
                    f"[dim]Reason: {exc}[/dim]"
                )

                Prompt.ask(
                    "\nPress Enter to return",
                    default=""
                )

        elif choice == "12":

            try:
                from .pro.investigation.service import (
                    InvestigationService,
                )

                service = InvestigationService()

                run_investigation_workspace(
                    service,
                    console,
                )

            except Exception as exc:

                console.print(
                    Panel(
                        "[red]Unable to open the Pro Investigation "
                        "Workspace.[/red]\n\n"
                        f"[dim]{exc}[/dim]",
                        title="Pro Investigation Error",
                        border_style="red",
                    )
                )

                Prompt.ask(
                    "Press Enter to return",
                    default=""
                )

        elif choice == "13":

            _show_pro_investigation_timeline()

        elif choice == "14":

            _show_pro_investigation_findings()

        elif choice == "15":

            _show_license_management()

        elif choice == "16":

            _show_about()

        else:

            console.print(
                Panel(
                    "[red]Invalid option.[/red]\n"
                    "[dim]Please select one of the options shown above.[/dim]",
                    title="INPUT",
                    border_style="red",
                )
            )


__all__ = [
    "main_menu",
]
