"""
Analyst-facing investigation timeline display.

This module renders evidence-backed timeline information in the
terminal UI.

It does not assign threat scores, determine maliciousness, attribute
activity, or reconstruct attack chains.
"""

from typing import Iterable, Optional

from .timeline import (
    InvestigationTimeline,
    TimelineEntry,
)


def investigation_timeline_dashboard(
    timeline: InvestigationTimeline,
) -> None:
    """
    Display an investigation timeline.

    The display is intentionally evidence-focused. It shows what was
    observed, where it was observed, and the documented relationships
    between observations.
    """

    _print_header()

    if not timeline.entries:
        print()
        print(
            "No timestamped investigation evidence is available."
        )
        print()
        return

    print()
    print(
        f"Timeline entries: {len(timeline.entries)}"
    )
    print()

    for index, entry in enumerate(
        timeline.entries,
        start=1,
    ):
        _print_entry(
            index,
            entry,
        )

    print()
    print(
        "End of investigation timeline."
    )
    print()


def _print_header() -> None:
    """
    Print the timeline section header.
    """

    print()
    print("=" * 78)
    print("INVESTIGATION TIMELINE")
    print("=" * 78)


def _print_entry(
    index: int,
    entry: TimelineEntry,
) -> None:
    """
    Render one timeline entry.
    """

    timestamp = (
        entry.timestamp
        or "UNKNOWN TIME"
    )

    source = (
        entry.source
        or "UNKNOWN SOURCE"
    )

    print(
        f"[{index}] {timestamp}"
    )
    print(
        f"    Source: {source}"
    )

    if entry.event_id:
        print(
            f"    Event ID: {entry.event_id}"
        )

    print(
        f"    IOC: "
        f"{entry.ioc_type} = "
        f"{entry.ioc_value}"
    )

    if entry.event_type:
        print(
            f"    Event type: "
            f"{entry.event_type}"
        )

    if entry.description:
        print(
            f"    Evidence: "
            f"{entry.description}"
        )

    if entry.gap_from_previous_seconds is not None:
        print(
            f"    Gap from previous: "
            f"{_format_duration(entry.gap_from_previous_seconds)}"
        )

    if entry.relationship_types:
        print(
            "    Relationships: "
            + ", ".join(
                entry.relationship_types
            )
        )

    if entry.related_event_ids:
        print(
            f"    Related events: "
            f"{len(entry.related_event_ids)}"
        )

        for related_event_id in (
            entry.related_event_ids[:5]
        ):
            print(
                f"        - {related_event_id}"
            )

        if len(
            entry.related_event_ids
        ) > 5:
            print(
                f"        ... and "
                f"{len(entry.related_event_ids) - 5} more"
            )

    print(
        "    " + "-" * 70
    )


def _format_duration(
    seconds: Optional[float],
) -> str:
    """
    Format a duration for analyst readability.
    """

    if seconds is None:
        return "-"

    seconds = max(
        0.0,
        float(seconds),
    )

    if seconds < 1:
        return f"{seconds:.3f}s"

    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(
        seconds // 60
    )

    remaining_seconds = (
        seconds
        - (minutes * 60)
    )

    if minutes < 60:
        return (
            f"{minutes}m "
            f"{remaining_seconds:.1f}s"
        )

    hours = int(
        minutes // 60
    )

    remaining_minutes = (
        minutes
        - (hours * 60)
    )

    return (
        f"{hours}h "
        f"{remaining_minutes}m "
        f"{remaining_seconds:.1f}s"
    )
