from typing import Optional

from .investigation import InvestigationContext
from .investigation_export import InvestigationExporter
from .investigation_store import InvestigationStore
from .engine import CorrelationFinding
from .timeline_display import (
    investigation_timeline_dashboard,
)


def _pause() -> None:
    input("\nPress Enter to continue...")


def _read_choice(prompt: str) -> str:
    return input(prompt).strip().upper()


def _display_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def display_investigation_summary(
    investigation: InvestigationContext,
) -> None:
    _display_header("INVESTIGATION SUMMARY")

    summary = investigation.summary()

    print(f"Name          : {summary['name']}")
    print(f"Findings      : {summary['findings']}")
    print(f"Evidence      : {summary['evidence']}")
    print(f"Events        : {summary['events']}")
    print(f"IOCs          : {summary['iocs']}")
    print(f"Sources       : {summary['sources']}")
    print(
        f"Timeline      : "
        f"{summary['timeline_entries']}"
    )
    print(
        f"Relationships : "
        f"{summary['relationship_edges']}"
    )
    print(f"Notes         : {summary['notes']}")

    relationships = summary.get(
        "relationships",
        {},
    )

    if relationships:
        print("\nRelationships:")

        for relationship, count in sorted(
            relationships.items()
        ):
            print(
                f"  {relationship}: {count}"
            )


def display_investigation_findings(
    investigation: InvestigationContext,
) -> None:
    _display_header("INVESTIGATION FINDINGS")

    if not investigation.findings:
        print("No findings have been added.")
        return

    for index, finding in enumerate(
        investigation.findings,
        start=1,
    ):
        print(
            f"\n[{index}] "
            f"{finding.ioc_type.upper()}: "
            f"{finding.value}"
        )

        print(
            f"    Relationship : "
            f"{finding.relationship}"
        )

        print(
            f"    Events       : "
            f"{finding.event_count}"
        )

        print(
            f"    Sources      : "
            f"{finding.source_count}"
        )

        print(
            f"    Evidence     : "
            f"{finding.evidence_count}"
        )

        print(
            f"    Relationships: "
            f"{len(finding.relationship_edges)}"
        )

        if finding.first_seen:
            print(
                f"    First seen   : "
                f"{finding.first_seen}"
            )

        if finding.last_seen:
            print(
                f"    Last seen    : "
                f"{finding.last_seen}"
            )

        print(
            f"    Description  : "
            f"{finding.description}"
        )


def display_investigation_iocs(
    investigation: InvestigationContext,
) -> None:
    _display_header("INVESTIGATION IOCs")

    iocs = investigation.iocs()

    if not iocs:
        print("No IOCs have been added.")
        return

    for index, value in enumerate(
        iocs,
        start=1,
    ):
        print(
            f"{index:>3}. {value}"
        )


def display_investigation_sources(
    investigation: InvestigationContext,
) -> None:
    _display_header("INVESTIGATION SOURCES")

    sources = investigation.source_names()

    if not sources:
        print("No sources have been recorded.")
        return

    for index, source in enumerate(
        sources,
        start=1,
    ):
        print(
            f"{index:>3}. {source}"
        )


def display_investigation_notes(
    investigation: InvestigationContext,
) -> None:
    _display_header("ANALYST NOTES")

    if not investigation.notes:
        print("No analyst notes have been added.")
        return

    for index, note in enumerate(
        investigation.notes,
        start=1,
    ):
        print(
            f"\n[{index}] {note}"
        )


def display_investigation_timeline(
    investigation: InvestigationContext,
) -> None:
    """
    Display the timeline derived from the current investigation.
    """

    timeline = investigation.timeline

    investigation_timeline_dashboard(
        timeline
    )


def display_investigation_validation(
    investigation: InvestigationContext,
) -> None:
    """
    Display a read-only investigation integrity report.
    """

    _display_header(
        "INVESTIGATION INTEGRITY"
    )

    result = investigation.validate()

    status = (
        "VALID"
        if result.valid
        else "INVALID"
    )

    print(
        f"Status                 : {status}"
    )

    print(
        f"Findings checked       : "
        f"{result.findings_checked}"
    )

    print(
        f"Evidence checked       : "
        f"{result.evidence_checked}"
    )

    print(
        f"Relationship edges     : "
        f"{result.relationship_edges_checked}"
    )

    print(
        f"Timeline entries       : "
        f"{result.timeline_entries_checked}"
    )

    print(
        f"Errors                 : "
        f"{result.error_count}"
    )

    print(
        f"Warnings               : "
        f"{result.warning_count}"
    )

    if result.errors:
        print("\nERRORS")
        print("-" * 72)

        for index, error in enumerate(
            result.errors,
            start=1,
        ):
            print(
                f"{index:>3}. {error}"
            )

    if result.warnings:
        print("\nWARNINGS")
        print("-" * 72)

        for index, warning in enumerate(
            result.warnings,
            start=1,
        ):
            print(
                f"{index:>3}. {warning}"
            )

    if not result.errors and not result.warnings:
        print(
            "\nNo integrity issues were detected."
        )

    print(
        "\nValidation is read-only. "
        "No investigation data was modified."
    )


def display_investigation_finding(
    finding: CorrelationFinding,
) -> None:
    _display_header("CORRELATION FINDING")

    print(
        f"IOC Type       : "
        f"{finding.ioc_type}"
    )

    print(
        f"Value          : "
        f"{finding.value}"
    )

    print(
        f"Relationship   : "
        f"{finding.relationship}"
    )

    print(
        f"Events         : "
        f"{finding.event_count}"
    )

    print(
        f"Sources        : "
        f"{finding.source_count}"
    )

    print(
        f"Evidence       : "
        f"{finding.evidence_count}"
    )

    print(
        f"Relationships  : "
        f"{len(finding.relationship_edges)}"
    )

    print(
        f"First Seen     : "
        f"{finding.first_seen or '-'}"
    )

    print(
        f"Last Seen      : "
        f"{finding.last_seen or '-'}"
    )

    if finding.time_span_seconds is not None:
        print(
            f"Time Span      : "
            f"{finding.time_span_seconds:.1f} seconds"
        )

    if (
        finding.closest_cross_source_gap_seconds
        is not None
    ):
        print(
            f"Closest Cross-Source Gap: "
            f"{finding.closest_cross_source_gap_seconds:.1f} seconds"
        )

    print(
        f"\nDescription:\n"
        f"{finding.description}"
    )

    if finding.sources:
        print("\nSources:")

        for source in finding.sources:
            print(
                f"  - {source}"
            )

    if finding.event_types:
        print("\nEvent Types:")

        for event_type in finding.event_types:
            print(
                f"  - {event_type}"
            )

    if finding.relationship_edges:
        print("\nEvidence Relationships:")

        for index, edge in enumerate(
            finding.relationship_edges,
            start=1,
        ):
            print(
                f"\n  Relationship {index}"
            )

            print(
                f"    Type       : "
                f"{edge.relationship_type}"
            )

            print(
                f"    Source     : "
                f"{edge.source or '-'}"
            )

            print(
                f"    Target     : "
                f"{edge.target or '-'}"
            )

            print(
                f"    Time Gap   : "
                f"{edge.time_gap_seconds:.1f}s"
                if edge.time_gap_seconds
                is not None
                else
                "    Time Gap   : -"
            )

            print(
                f"    Source ID  : "
                f"{edge.source_event_id or '-'}"
            )

            print(
                f"    Target ID  : "
                f"{edge.target_event_id or '-'}"
            )

            if edge.description:
                print(
                    f"    Description: "
                    f"{edge.description}"
                )

    if finding.evidence:
        print("\nEvidence:")

        for index, evidence in enumerate(
            finding.evidence,
            start=1,
        ):
            print(
                f"\n  Evidence {index}"
            )

            print(
                f"    Type       : "
                f"{evidence.evidence_type}"
            )

            print(
                f"    Value      : "
                f"{evidence.value}"
            )

            print(
                f"    Source     : "
                f"{evidence.source or '-'}"
            )

            print(
                f"    Timestamp  : "
                f"{evidence.timestamp or '-'}"
            )

            print(
                f"    Event ID   : "
                f"{evidence.event_id or '-'}"
            )

            print(
                f"    Confidence : "
                f"{evidence.confidence:.2f}"
            )

            if evidence.description:
                print(
                    f"    Description: "
                    f"{evidence.description}"
                )


def _select_finding(
    investigation: InvestigationContext,
) -> Optional[CorrelationFinding]:

    if not investigation.findings:
        print(
            "\nNo findings are currently "
            "in the investigation."
        )
        return None

    display_investigation_findings(
        investigation
    )

    while True:
        value = input(
            "\nEnter finding number "
            "(0 to cancel): "
        ).strip()

        if value == "0":
            return None

        try:
            index = int(value)
        except ValueError:
            print(
                "Invalid selection. "
                "Enter a number."
            )
            continue

        if 1 <= index <= len(
            investigation.findings
        ):
            return investigation.findings[
                index - 1
            ]

        print(
            "Invalid finding number."
        )


def _new_investigation(
    investigation: InvestigationContext,
) -> InvestigationContext:

    print(
        "\nCreating a new investigation "
        "will clear the current workspace."
    )

    confirmation = _read_choice(
        "Continue? [Y/N]: "
    )

    if confirmation != "Y":
        return investigation

    name = input(
        "Investigation name: "
    ).strip()

    if not name:
        name = "Untitled Investigation"

    return InvestigationContext(
        name=name
    )


def _add_note(
    investigation: InvestigationContext,
) -> None:

    print("\nEnter analyst note.")
    print(
        "Press Enter on an empty line "
        "to cancel."
    )

    note = input(
        "\nNote: "
    ).strip()

    if not note:
        print("No note added.")
        return

    if investigation.add_note(note):
        print(
            "\nAnalyst note added."
        )


def _remove_note(
    investigation: InvestigationContext,
) -> None:

    if not investigation.notes:
        print(
            "\nThere are no analyst notes."
        )
        return

    display_investigation_notes(
        investigation
    )

    value = input(
        "\nEnter note number "
        "(0 to cancel): "
    ).strip()

    if value == "0":
        return

    try:
        index = int(value)
    except ValueError:
        print(
            "Invalid note number."
        )
        return

    if investigation.remove_note(
        index - 1
    ):
        print(
            "\nAnalyst note removed."
        )
    else:
        print(
            "\nInvalid note number."
        )


def _remove_finding(
    investigation: InvestigationContext,
) -> None:

    finding = _select_finding(
        investigation
    )

    if finding is None:
        return

    if investigation.remove_finding(
        finding
    ):
        print(
            "\nFinding removed from "
            "the investigation."
        )


def _save_investigation(
    investigation: InvestigationContext,
    store: InvestigationStore,
) -> None:

    try:
        path = store.save(
            investigation
        )

        print(
            "\nInvestigation saved."
        )

        print(
            f"Location: {path}"
        )

    except Exception as exc:
        print(
            "\nUnable to save investigation."
        )

        print(
            f"Reason: {exc}"
        )


def _load_investigation(
    store: InvestigationStore,
) -> Optional[InvestigationContext]:

    names = store.list_investigations()

    if not names:
        print(
            "\nNo saved investigations "
            "were found."
        )
        return None

    _display_header(
        "SAVED INVESTIGATIONS"
    )

    for index, name in enumerate(
        names,
        start=1,
    ):
        print(
            f"{index:>3}. {name}"
        )

    value = input(
        "\nEnter investigation number "
        "(0 to cancel): "
    ).strip()

    if value == "0":
        return None

    try:
        index = int(value)
    except ValueError:
        print(
            "Invalid selection."
        )
        return None

    if not (
        1 <= index <= len(names)
    ):
        print(
            "Invalid investigation number."
        )
        return None

    name = names[index - 1]

    try:
        investigation = store.load(
            name
        )

        print(
            "\nInvestigation loaded:"
        )

        print(
            f"Name: {investigation.name}"
        )

        return investigation

    except Exception as exc:
        print(
            "\nUnable to load investigation."
        )

        print(
            f"Reason: {exc}"
        )

        return None


def _delete_saved_investigation(
    store: InvestigationStore,
) -> None:

    names = store.list_investigations()

    if not names:
        print(
            "\nNo saved investigations "
            "were found."
        )
        return

    _display_header(
        "DELETE SAVED INVESTIGATION"
    )

    for index, name in enumerate(
        names,
        start=1,
    ):
        print(
            f"{index:>3}. {name}"
        )

    value = input(
        "\nEnter investigation number "
        "(0 to cancel): "
    ).strip()

    if value == "0":
        return

    try:
        index = int(value)
    except ValueError:
        print(
            "Invalid selection."
        )
        return

    if not (
        1 <= index <= len(names)
    ):
        print(
            "Invalid investigation number."
        )
        return

    name = names[index - 1]

    confirmation = _read_choice(
        f"Delete '{name}'? [Y/N]: "
    )

    if confirmation != "Y":
        print(
            "\nDeletion cancelled."
        )
        return

    try:
        if store.delete(name):
            print(
                "\nSaved investigation deleted."
            )
        else:
            print(
                "\nInvestigation was not found."
            )

    except Exception as exc:
        print(
            "\nUnable to delete investigation."
        )

        print(
            f"Reason: {exc}"
        )


def _export_investigation(
    investigation: InvestigationContext,
    exporter: InvestigationExporter,
) -> None:

    if (
        investigation.finding_count == 0
        and not investigation.notes
    ):
        print(
            "\nThe investigation is empty."
        )
        print(
            "Add findings or analyst notes "
            "before exporting."
        )
        return

    _display_header(
        "EXPORT INVESTIGATION"
    )

    print("1. JSON")
    print("2. CSV")
    print("3. TXT")
    print("0. Cancel")

    choice = _read_choice(
        "\nSelect export format: "
    )

    try:
        if choice == "1":
            path = exporter.export_json(
                investigation
            )

        elif choice == "2":
            path = exporter.export_csv(
                investigation
            )

        elif choice == "3":
            path = exporter.export_txt(
                investigation
            )

        elif choice == "0":
            return

        else:
            print(
                "\nInvalid export selection."
            )
            return

        print(
            "\nInvestigation exported successfully."
        )

        print(
            f"Location: {path}"
        )

    except Exception as exc:
        print(
            "\nExport failed."
        )

        print(
            f"Reason: {exc}"
        )


def investigation_workspace(
    investigation: Optional[
        InvestigationContext
    ] = None,
    store: Optional[
        InvestigationStore
    ] = None,
    exporter: Optional[
        InvestigationExporter
    ] = None,
) -> InvestigationContext:
    """
    Interactive Investigation Workspace.

    Returns the current InvestigationContext when
    the analyst exits the workspace.
    """

    if investigation is None:
        investigation = InvestigationContext()

    if store is None:
        store = InvestigationStore()

    if exporter is None:
        exporter = InvestigationExporter()

    while True:
        _display_header(
            "INVESTIGATION WORKSPACE"
        )

        print(
            f"Investigation: "
            f"{investigation.name}"
        )

        print(
            f"Findings: "
            f"{investigation.finding_count} | "
            f"Evidence: "
            f"{investigation.evidence_count} | "
            f"Timeline: "
            f"{len(investigation.timeline)} | "
            f"Notes: "
            f"{len(investigation.notes)}"
        )

        print()
        print("1. View investigation")
        print("2. Add finding")
        print("3. Remove finding")
        print("4. Add analyst note")
        print("5. Remove analyst note")
        print("6. New investigation")
        print("7. Save investigation")
        print("8. Load investigation")
        print("9. List investigations")
        print("T. View investigation timeline")
        print("V. Validate investigation integrity")
        print("E. Export investigation")
        print("D. Delete saved investigation")
        print("C. Clear investigation")
        print("0. Back")

        choice = _read_choice(
            "\nSelect an option: "
        )

        if choice == "1":
            display_investigation_summary(
                investigation
            )

            display_investigation_findings(
                investigation
            )

            display_investigation_iocs(
                investigation
            )

            display_investigation_sources(
                investigation
            )

            display_investigation_notes(
                investigation
            )

            _pause()

        elif choice == "2":
            print(
                "\nAdding findings directly "
                "from this menu requires "
                "a correlation result."
            )

            print(
                "Use the correlation result "
                "selection and [A]dd action "
                "to place findings here."
            )

            _pause()

        elif choice == "3":
            _remove_finding(
                investigation
            )
            _pause()

        elif choice == "4":
            _add_note(
                investigation
            )
            _pause()

        elif choice == "5":
            _remove_note(
                investigation
            )
            _pause()

        elif choice == "6":
            investigation = _new_investigation(
                investigation
            )
            _pause()

        elif choice == "7":
            _save_investigation(
                investigation,
                store,
            )
            _pause()

        elif choice == "8":
            loaded = _load_investigation(
                store
            )

            if loaded is not None:
                investigation = loaded

            _pause()

        elif choice == "9":
            names = store.list_investigations()

            _display_header(
                "SAVED INVESTIGATIONS"
            )

            if not names:
                print(
                    "No saved investigations."
                )
            else:
                for index, name in enumerate(
                    names,
                    start=1,
                ):
                    print(
                        f"{index:>3}. {name}"
                    )

            _pause()

        elif choice == "T":
            display_investigation_timeline(
                investigation
            )
            _pause()

        elif choice == "V":
            display_investigation_validation(
                investigation
            )
            _pause()

        elif choice == "E":
            _export_investigation(
                investigation,
                exporter,
            )
            _pause()

        elif choice == "D":
            _delete_saved_investigation(
                store
            )
            _pause()

        elif choice == "C":
            confirmation = _read_choice(
                "\nClear the current "
                "investigation? [Y/N]: "
            )

            if confirmation == "Y":
                investigation.clear()
                print(
                    "\nInvestigation cleared."
                )

            _pause()

        elif choice == "0":
            return investigation

        else:
            print(
                "\nInvalid selection."
            )
            _pause()
