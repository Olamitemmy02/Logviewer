from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Evidence:
    """
    Represents a piece of security evidence associated
    with an event or investigation.

    Evidence preserves both the IOC that caused the evidence
    to be created and useful context from the original event.
    """

    evidence_type: str
    value: str

    source: Optional[str] = None
    timestamp: Optional[str] = None

    confidence: float = 1.0

    description: Optional[str] = None

    event_id: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "description": self.description,
            "event_id": self.event_id,
            "metadata": self.metadata,
        }

    def get_context(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """
        Safely retrieve contextual information associated
        with the original event.
        """

        return self.metadata.get(
            key,
            default,
        )
