from typing import Iterable, List, Optional

from logviewer.events import Event
from logviewer.licensing.feature_gate import FeatureGate

from logviewer.pro.investigation.engine import (
    InvestigationEngine,
)
from logviewer.pro.investigation.model import (
    Investigation,
)
from logviewer.pro.investigation.store import (
    InvestigationStore,
)


INVESTIGATION_FEATURE = "investigation"


class InvestigationService:
    """
    High-level LogViewer Pro investigation service.

    Provides:
        - investigation creation
        - persistence
        - retrieval
        - listing
        - deletion
        - status management
        - severity management
    """

    def __init__(
        self,
        feature_gate: Optional[FeatureGate] = None,
        store: Optional[InvestigationStore] = None,
    ):
        self.feature_gate = (
            feature_gate or FeatureGate()
        )

        self.engine = InvestigationEngine(
            feature_gate=self.feature_gate
        )

        self.store = (
            store or InvestigationStore()
        )

    def create(
        self,
        investigation_id: str,
        events: Iterable[Event],
        title: str = "Security Investigation",
    ) -> Investigation:
        """Create and persist a new investigation."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        investigation = (
            self.engine.create_investigation(
                investigation_id=investigation_id,
                events=events,
                title=title,
            )
        )

        self.store.save(
            investigation
        )

        return investigation

    def get(
        self,
        investigation_id: str,
    ) -> Optional[Investigation]:
        """Retrieve an investigation."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        return self.store.load(
            investigation_id
        )

    def list(self) -> List[dict]:
        """List stored investigations."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        return self.store.list_investigations()

    def update_status(
        self,
        investigation_id: str,
        status: str,
    ) -> Investigation:
        """Update investigation status."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        investigation = self._require(
            investigation_id
        )

        investigation.set_status(
            status
        )

        self.store.save(
            investigation
        )

        return investigation

    def update_severity(
        self,
        investigation_id: str,
        severity: str,
    ) -> Investigation:
        """Update investigation severity."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        investigation = self._require(
            investigation_id
        )

        investigation.set_severity(
            severity
        )

        self.store.save(
            investigation
        )

        return investigation

    def delete(
        self,
        investigation_id: str,
    ) -> bool:
        """Delete an investigation."""
        self.feature_gate.require(
            INVESTIGATION_FEATURE
        )

        return self.store.delete(
            investigation_id
        )

    def _require(
        self,
        investigation_id: str,
    ) -> Investigation:
        investigation = self.store.load(
            investigation_id
        )

        if investigation is None:
            raise ValueError(
                "Investigation not found: "
                f"{investigation_id}"
            )

        return investigation
