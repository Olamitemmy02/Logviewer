"""
Core Security Analysis engine.

Converts normalized LogViewer events into evidence-backed observations.

This module deliberately does NOT:
    - assign threat scores
    - declare events malicious
    - attribute activity to an attacker
    - map activity to MITRE ATT&CK
    - reconstruct attack chains

Those capabilities belong to the future Pro investigation layer.

Filtering is performed on already-created observations and does not alter
the original observation objects or the underlying evidence.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from logviewer.events import Event

from .rules import matching_rule_ids


@dataclass
class SecurityObservation:
    """
    A security-relevant observation derived from an Event.

    Severity represents the importance of the observed activity inside the
    Core analysis system. It is NOT a maliciousness or threat score.
    """

    rule_id: str
    category: str
    title: str
    description: str
    timestamp: str
    source: str

    severity: str = "INFO"

    evidence: List[str] = field(
        default_factory=list
    )

    event_type: Optional[str] = None
    parser: Optional[str] = None

    evidence_strength: str = "moderate"

    def as_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "evidence": self.evidence,
            "event_type": self.event_type,
            "parser": self.parser,
            "evidence_strength": self.evidence_strength,
        }


class SecurityAnalyzer:
    """
    Analyze normalized LogViewer events.

    The analyzer produces observations only when a rule finds meaningful
    evidence.
    """

    RULE_METADATA = {
        "AUTH_FAILURE": {
            "category": "Authentication",
            "title": "Authentication Failure",
            "severity": "WARNING",
            "description": (
                "An authentication failure was observed in the event."
            ),
        },
        "AUTH_ACTIVITY": {
            "category": "Authentication",
            "title": "Authentication Activity",
            "severity": "INFO",
            "description": (
                "Authentication or session activity was observed."
            ),
        },
        "PRIVILEGE_ACTIVITY": {
            "category": "Privilege",
            "title": "Privilege Activity",
            "severity": "NOTICE",
            "description": (
                "Privilege-related activity was observed."
            ),
        },
        "COMMAND_ACTIVITY": {
            "category": "Execution",
            "title": "Process or Command Activity",
            "severity": "NOTICE",
            "description": (
                "An explicit process or command execution event was observed."
            ),
        },
        "NETWORK_ACTIVITY": {
            "category": "Network",
            "title": "Network Activity",
            "severity": "INFO",
            "description": (
                "Meaningful network or connection activity was observed."
            ),
        },
        "FILE_ACTIVITY": {
            "category": "File Activity",
            "title": "File Activity",
            "severity": "NOTICE",
            "description": (
                "A file operation or explicit file-change event was observed."
            ),
        },
        "SENSITIVE_PATH": {
            "category": "Sensitive Resource",
            "title": "Sensitive Resource Reference",
            "severity": "NOTICE",
            "description": (
                "A security-sensitive filesystem path was referenced."
            ),
        },
        "SECURITY_CONTROL": {
            "category": "Security Control",
            "title": "Security Control Activity",
            "severity": "INFO",
            "description": (
                "Observable activity involving a security control was detected."
            ),
        },
        "PARSING_FALLBACK": {
            "category": "Data Quality",
            "title": "Unparsed Event",
            "severity": "NOTICE",
            "description": (
                "The event could not be parsed into the normalized structure."
            ),
        },
        "PARTIAL_PARSE": {
            "category": "Data Quality",
            "title": "Partially Parsed Event",
            "severity": "NOTICE",
            "description": (
                "Only part of the event could be parsed into structured fields."
            ),
        },
    }

    def analyze_event(
        self,
        event: Event,
    ) -> List[SecurityObservation]:

        observations: List[SecurityObservation] = []

        for rule_id in matching_rule_ids(event):

            metadata = self.RULE_METADATA.get(rule_id)

            if metadata is None:
                continue

            observations.append(
                SecurityObservation(
                    rule_id=rule_id,
                    category=metadata["category"],
                    title=metadata["title"],
                    description=metadata["description"],
                    timestamp=event.timestamp or "-",
                    source=event.source or "unknown",
                    severity=metadata["severity"],
                    evidence=self._build_evidence(event),
                    event_type=event.event_type,
                    parser=event.parser,
                    evidence_strength=self._determine_evidence_strength(
                        event,
                        rule_id,
                    ),
                )
            )

        return observations

    def analyze_events(
        self,
        events: Iterable[Event],
    ) -> List[SecurityObservation]:

        observations: List[SecurityObservation] = []

        for event in events:
            observations.extend(
                self.analyze_event(event)
            )

        return observations

    @staticmethod
    def filter_observations(
        observations: Iterable[SecurityObservation],
        *,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        source: Optional[str] = None,
        rule_id: Optional[str] = None,
        event_type: Optional[str] = None,
        evidence_strength: Optional[str] = None,
        text: Optional[str] = None,
    ) -> List[SecurityObservation]:
        """
        Filter security observations without modifying the original list.

        Filters are combined using AND semantics.

        Parameters:
            observations:
                Existing SecurityObservation objects.

            severity:
                Match observation severity, case-insensitively.

            category:
                Match observation category, case-insensitively.

            source:
                Match observation source, case-insensitively.

            rule_id:
                Match the originating security rule ID.

            event_type:
                Match the normalized event type.

            evidence_strength:
                Match strong, moderate, or contextual evidence.

            text:
                Case-insensitive search across:
                    - rule ID
                    - category
                    - title
                    - description
                    - timestamp
                    - source
                    - event type
                    - parser
                    - evidence strength
                    - evidence fields

        Returns:
            A new list containing only observations matching all supplied
            filters.
        """

        def normalize(value: Optional[str]) -> str:
            return (value or "").strip().casefold()

        normalized_severity = normalize(severity)
        normalized_category = normalize(category)
        normalized_source = normalize(source)
        normalized_rule_id = normalize(rule_id)
        normalized_event_type = normalize(event_type)
        normalized_strength = normalize(evidence_strength)
        normalized_text = normalize(text)

        filtered: List[SecurityObservation] = []

        for observation in observations:

            if (
                normalized_severity
                and normalize(observation.severity)
                != normalized_severity
            ):
                continue

            if (
                normalized_category
                and normalize(observation.category)
                != normalized_category
            ):
                continue

            if (
                normalized_source
                and normalize(observation.source)
                != normalized_source
            ):
                continue

            if (
                normalized_rule_id
                and normalize(observation.rule_id)
                != normalized_rule_id
            ):
                continue

            if (
                normalized_event_type
                and normalize(observation.event_type)
                != normalized_event_type
            ):
                continue

            if (
                normalized_strength
                and normalize(observation.evidence_strength)
                != normalized_strength
            ):
                continue

            if normalized_text:

                searchable_values = [
                    observation.rule_id,
                    observation.category,
                    observation.title,
                    observation.description,
                    observation.timestamp,
                    observation.source,
                    observation.event_type,
                    observation.parser,
                    observation.severity,
                    observation.evidence_strength,
                    *observation.evidence,
                ]

                searchable_text = " ".join(
                    normalize(value)
                    for value in searchable_values
                    if value
                )

                if normalized_text not in searchable_text:
                    continue

            filtered.append(observation)

        return filtered

    @staticmethod
    def _build_evidence(
        event: Event,
    ) -> List[str]:

        evidence: List[str] = []

        if event.message:
            evidence.append(
                f"Message: {event.message}"
            )

        if event.event_type:
            evidence.append(
                f"Event type: {event.event_type}"
            )

        if event.process:
            process_value = event.process

            if event.pid is not None:
                process_value = (
                    f"{process_value} (PID {event.pid})"
                )

            evidence.append(
                f"Process: {process_value}"
            )

        if event.command:
            evidence.append(
                f"Command: {event.command}"
            )

        if event.file_path:
            evidence.append(
                f"File: {event.file_path}"
            )

        if event.action:
            evidence.append(
                f"Action: {event.action}"
            )

        if event.src_ip:
            source = event.src_ip

            if event.src_port is not None:
                source = (
                    f"{source}:{event.src_port}"
                )

            evidence.append(
                f"Source: {source}"
            )

        if event.dst_ip:
            destination = event.dst_ip

            if event.dst_port is not None:
                destination = (
                    f"{destination}:{event.dst_port}"
                )

            evidence.append(
                f"Destination: {destination}"
            )

        if event.protocol:
            evidence.append(
                f"Protocol: {event.protocol}"
            )

        if event.domain:
            evidence.append(
                f"Domain: {event.domain}"
            )

        if event.url:
            evidence.append(
                f"URL: {event.url}"
            )

        if event.user:
            evidence.append(
                f"User: {event.user}"
            )

        if event.host:
            evidence.append(
                f"Host: {event.host}"
            )

        if event.signature:
            evidence.append(
                f"Signature: {event.signature}"
            )

        if event.sid is not None:
            evidence.append(
                f"SID: {event.sid}"
            )

        if event.gid is not None:
            evidence.append(
                f"GID: {event.gid}"
            )

        if event.priority is not None:
            evidence.append(
                f"Priority: {event.priority}"
            )

        return evidence

    @staticmethod
    def _determine_evidence_strength(
        event: Event,
        rule_id: str,
    ) -> str:
        """
        Evidence strength is calculated from fields relevant to the
        particular rule.

        Generic metadata such as:
            - host
            - parser
            - event type

        does not increase evidence strength by itself.
        """

        if rule_id == "AUTH_FAILURE":

            if (
                event.message
                and (
                    event.user
                    or event.src_ip
                    or event.process
                )
            ):
                return "strong"

            if event.message:
                return "moderate"

            return "contextual"

        if rule_id == "AUTH_ACTIVITY":

            relevant = sum(
                bool(value)
                for value in (
                    event.user,
                    event.src_ip,
                    event.process,
                )
            )

            if relevant >= 2:
                return "strong"

            if relevant >= 1 or event.message:
                return "moderate"

            return "contextual"

        if rule_id == "PRIVILEGE_ACTIVITY":

            relevant = sum(
                bool(value)
                for value in (
                    event.command,
                    event.process,
                    event.user,
                    event.action,
                    event.message,
                )
            )

            if relevant >= 2:
                return "strong"

            if relevant == 1:
                return "moderate"

            return "contextual"

        if rule_id == "COMMAND_ACTIVITY":

            if event.command:
                return "strong"

            if event.action and event.process:
                return "strong"

            if event.action or event.process:
                return "moderate"

            if event.message:
                return "moderate"

            return "contextual"

        if rule_id == "NETWORK_ACTIVITY":

            relevant = sum(
                value is not None
                and bool(value)
                for value in (
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                )
            )

            if relevant >= 2:
                return "strong"

            if relevant == 1 or event.message:
                return "moderate"

            return "contextual"

        if rule_id == "FILE_ACTIVITY":

            if event.file_path and event.action:
                return "strong"

            if event.file_path or event.action:
                return "moderate"

            if event.message:
                return "moderate"

            return "contextual"

        if rule_id == "SENSITIVE_PATH":

            if event.file_path:
                return "strong"

            if event.message:
                return "moderate"

            return "contextual"

        if rule_id == "SECURITY_CONTROL":

            if event.signature:
                return "strong"

            if event.action:
                return "strong"

            if event.message:
                return "moderate"

            return "contextual"

        if rule_id in {
            "PARSING_FALLBACK",
            "PARTIAL_PARSE",
        }:

            if event.message:
                return "moderate"

            return "contextual"

        return "contextual"
