from typing import Dict, List, Optional

from logviewer.events import Event
from logviewer.analysis.normalization import event_text
from logviewer.analysis.ioc.extractor import extract_iocs


def extract_event_iocs(
    event: Event,
    text: Optional[str] = None,
) -> Dict[str, List[str]]:
    """
    Extract IOCs from a normalized LogViewer event.

    The event is converted into a common searchable representation
    before IOC extraction is performed.

    An already-built searchable text representation may be supplied
    to avoid rebuilding the event text when the caller already has it.
    """
    searchable_text = (
        event_text(event)
        if text is None
        else text
    )

    return extract_iocs(searchable_text)
