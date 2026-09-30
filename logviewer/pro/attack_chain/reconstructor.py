"""
Attack Chain Reconstruction for LogViewer Pro.

Reconstructs a chronological, evidence-backed sequence of security-relevant
events and associates observed events with available MITRE ATT&CK mappings.

Important:
    - Chronology is based on event timestamps.
    - MITRE mappings are observations/candidates, not proof of successful
      technique execution.
    - Missing telemetry is represented as gaps rather than invented events.
    - Process parent/child relationships are used only when the available
      process metadata supports them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from logviewer.events import Event


ATTACK_CHAIN_FEATURE = "attack_chain"


@dataclass
class AttackChainStep:
    """One chronological step in an observed attack chain."""

    index: int
    timestamp: str
    stage: str
    event_type: str
    description: str
    source: str

    technique_ids: List[str] = field(default_factory=list)
    technique_names: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)

    process: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None

    evidence_references: List[str] = field(default_factory=list)

    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "stage": self.stage,
            "event_type": self.event_type,
            "description": self.description,
            "source": self.source,
            "technique_ids": list(self.technique_ids),
            "technique_names": list(self.technique_names),
            "tactics": list(self.tactics),
            "process": self.process,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "evidence_references": list(self.evidence_references),
            "confidence": self.confidence,
            "notes": list(self.notes),
        }


@dataclass
class AttackChainLink:
    """Relationship between two reconstructed attack-chain steps."""

    from_index: int
    to_index: int
    relationship: str
    confidence: float
    rationale: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "from_index": self.from_index,
            "to_index": self.to_index,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass
class AttackChain:
    """Complete reconstructed attack chain."""

    steps: List[AttackChainStep] = field(default_factory=list)
    links: List[AttackChainLink] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    gaps: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "steps": [step.as_dict() for step in self.steps],
            "links": [link.as_dict() for link in self.links],
            "summary": dict(self.summary),
            "gaps": list(self.gaps),
        }


class AttackChainReconstructor:
    """
    Reconstruct an observed attack chain from Investigation data.

    The implementation deliberately avoids inventing attacker actions.
    It connects only evidence that exists in the Investigation.
    """

    _STAGE_PRIORITY = (
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    )

    _STAGE_ALIASES = {
        "initial access": "initial_access",
        "initial_access": "initial_access",
        "execution": "execution",
        "persistence": "persistence",
        "privilege escalation": "privilege_escalation",
        "privilege_escalation": "privilege_escalation",
        "defense evasion": "defense_evasion",
        "defense_evasion": "defense_evasion",
        "credential access": "credential_access",
        "credential_access": "credential_access",
        "discovery": "discovery",
        "lateral movement": "lateral_movement",
        "lateral_movement": "lateral_movement",
        "collection": "collection",
        "command and control": "command_and_control",
        "command_and_control": "command_and_control",
        "exfiltration": "exfiltration",
        "impact": "impact",
    }

    def __init__(self, feature_gate: Any) -> None:
        self.feature_gate = feature_gate

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reconstruct(self, investigation: Any) -> Dict[str, Any]:
        """
        Reconstruct an attack chain from an Investigation.

        Returns a serializable dictionary suitable for storing directly
        on the Investigation object.
        """

        self._require_feature()

        events = list(getattr(investigation, "events", []) or [])
        mappings = list(getattr(investigation, "mitre_mappings", []) or [])
        evidence = list(getattr(investigation, "evidence", []) or [])

        if not events:
            chain = AttackChain(
                summary={
                    "step_count": 0,
                    "link_count": 0,
                    "technique_count": 0,
                    "techniques": [],
                    "tactic_count": 0,
                    "tactics": [],
                    "evidence_count": 0,
                    "process_relationship_count": 0,
                    "confidence": 0.0,
                },
                gaps=["No events were available for attack-chain reconstruction."],
            )
            return chain.as_dict()

        sorted_events = self._sort_events(events)

        mapping_index = self._build_mapping_index(mappings)
        evidence_index = self._build_evidence_index(evidence)

        steps: List[AttackChainStep] = []

        for index, event in enumerate(sorted_events):
            step = self._build_step(
                index=index,
                event=event,
                mapping_index=mapping_index,
                evidence_index=evidence_index,
            )
            steps.append(step)

        links = self._build_links(steps)

        gaps = self._identify_gaps(
            events=sorted_events,
            mappings=mappings,
            steps=steps,
        )

        technique_ids = sorted(
            {
                technique_id
                for step in steps
                for technique_id in step.technique_ids
                if technique_id
            }
        )

        technique_names = sorted(
            {
                technique_name
                for step in steps
                for technique_name in step.technique_names
                if technique_name
            }
        )

        tactics = sorted(
            {
                tactic
                for step in steps
                for tactic in step.tactics
                if tactic
            }
        )

        confidence_values = [
            step.confidence
            for step in steps
            if self._is_number(step.confidence)
        ]

        process_relationship_count = sum(
            1 for link in links if link.relationship == "process_parent"
        )

        overall_confidence = (
            round(sum(confidence_values) / len(confidence_values), 3)
            if confidence_values
            else 0.0
        )

        summary = {
            "step_count": len(steps),
            "link_count": len(links),

            # Explicit count fields are part of the public result contract.
            "technique_count": len(technique_ids),
            "techniques": technique_ids,
            "technique_name_count": len(technique_names),
            "technique_names": technique_names,

            "tactic_count": len(tactics),
            "tactics": tactics,

            "evidence_count": len(evidence),
            "process_relationship_count": process_relationship_count,
            "confidence": overall_confidence,
        }

        chain = AttackChain(
            steps=steps,
            links=links,
            summary=summary,
            gaps=gaps,
        )

        return chain.as_dict()

    def reconstruct_and_store(self, investigation: Any) -> Dict[str, Any]:
        """Reconstruct the chain and store it on the Investigation."""

        result = self.reconstruct(investigation)

        setter = getattr(investigation, "set_attack_chain", None)

        if callable(setter):
            setter(result)
        else:
            investigation.attack_chain = result

            touch = getattr(investigation, "touch", None)
            if callable(touch):
                touch()

        return result

    # ------------------------------------------------------------------
    # Feature gating
    # ------------------------------------------------------------------

    def _require_feature(self) -> None:
        """Require the attack-chain Pro feature."""

        checker = getattr(self.feature_gate, "check", None)

        if not callable(checker):
            raise RuntimeError(
                "Feature gate does not provide a check() method."
            )

        allowed = checker(ATTACK_CHAIN_FEATURE)

        if not allowed:
            raise PermissionError(
                "The attack_chain feature requires a valid Pro license."
            )

    # ------------------------------------------------------------------
    # Step construction
    # ------------------------------------------------------------------

    def _build_step(
        self,
        index: int,
        event: Event,
        mapping_index: Dict[Tuple[str, str], List[Dict[str, Any]]],
        evidence_index: Dict[Tuple[str, str], List[str]],
    ) -> AttackChainStep:
        event_key = self._event_key(event)

        mappings = mapping_index.get(event_key, [])

        technique_ids: List[str] = []
        technique_names: List[str] = []
        tactics: List[str] = []

        for mapping in mappings:
            technique_id = self._string_value(
                mapping.get("technique_id")
            )
            technique_name = self._string_value(
                mapping.get("technique_name")
            )
            tactic = self._string_value(mapping.get("tactic"))

            if technique_id and technique_id not in technique_ids:
                technique_ids.append(technique_id)

            if technique_name and technique_name not in technique_names:
                technique_names.append(technique_name)

            if tactic and tactic not in tactics:
                tactics.append(tactic)

        stage = self._stage_for(
            event=event,
            tactics=tactics,
        )

        description = self._description(event)

        process = self._string_value(getattr(event, "process", None))
        pid = self._int_value(getattr(event, "pid", None))
        parent_pid = self._int_value(
            getattr(event, "parent_pid", None)
        )

        evidence_references = list(
            evidence_index.get(event_key, [])
        )

        notes: List[str] = []

        if mappings:
            notes.append(
                "MITRE association is an observed candidate mapping, "
                "not proof of successful technique execution."
            )
        else:
            notes.append(
                "No MITRE mapping was associated with this event."
            )

        if not evidence_references:
            notes.append(
                "No explicit evidence reference was associated "
                "with this event."
            )

        confidence = self._step_confidence(
            event=event,
            mappings=mappings,
            evidence_references=evidence_references,
        )

        return AttackChainStep(
            index=index,
            timestamp=self._string_value(
                getattr(event, "timestamp", "")
            ),
            stage=stage,
            event_type=self._string_value(
                getattr(event, "event_type", None)
            ) or "unknown",
            description=description,
            source=self._string_value(
                getattr(event, "source", None)
            ) or "unknown",
            technique_ids=technique_ids,
            technique_names=technique_names,
            tactics=tactics,
            process=process,
            pid=pid,
            parent_pid=parent_pid,
            evidence_references=evidence_references,
            confidence=confidence,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Links
    # ------------------------------------------------------------------

    def _build_links(
        self,
        steps: List[AttackChainStep],
    ) -> List[AttackChainLink]:
        links: List[AttackChainLink] = []

        if len(steps) < 2:
            return links

        # Chronological relationships.
        for previous, current in zip(steps, steps[1:]):
            links.append(
                AttackChainLink(
                    from_index=previous.index,
                    to_index=current.index,
                    relationship="chronological",
                    confidence=0.5,
                    rationale=(
                        "The events occurred in chronological order "
                        "within the available telemetry."
                    ),
                )
            )

        # Process parent/child relationships.
        pid_to_step: Dict[int, AttackChainStep] = {}

        for step in steps:
            if step.pid is not None:
                pid_to_step[step.pid] = step

        existing_process_links = {
            (link.from_index, link.to_index)
            for link in links
            if link.relationship == "process_parent"
        }

        for child in steps:
            if child.parent_pid is None:
                continue

            parent = pid_to_step.get(child.parent_pid)

            if parent is None:
                continue

            if parent.index == child.index:
                continue

            pair = (parent.index, child.index)

            if pair in existing_process_links:
                continue

            links.append(
                AttackChainLink(
                    from_index=parent.index,
                    to_index=child.index,
                    relationship="process_parent",
                    confidence=0.95,
                    rationale=(
                        f"Child PID {child.pid} references parent PID "
                        f"{child.parent_pid}, creating an observed "
                        "process relationship."
                    ),
                )
            )

            existing_process_links.add(pair)

        links.sort(
            key=lambda link: (
                link.from_index,
                link.to_index,
                link.relationship,
            )
        )

        return links

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_mapping_index(
        mappings: Iterable[Any],
    ) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
        """
        Index MITRE mappings by timestamp/source.

        The method accepts both dictionaries and objects exposing
        as_dict().
        """

        index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

        for mapping in mappings:
            if hasattr(mapping, "as_dict"):
                mapping_data = mapping.as_dict()
            elif isinstance(mapping, dict):
                mapping_data = dict(mapping)
            else:
                mapping_data = {
                    "technique_id": getattr(
                        mapping,
                        "technique_id",
                        None,
                    ),
                    "technique_name": getattr(
                        mapping,
                        "technique_name",
                        None,
                    ),
                    "tactic": getattr(
                        mapping,
                        "tactic",
                        None,
                    ),
                    "confidence": getattr(
                        mapping,
                        "confidence",
                        None,
                    ),
                    "matched_events": getattr(
                        mapping,
                        "matched_events",
                        [],
                    ),
                    "rationale": getattr(
                        mapping,
                        "rationale",
                        "",
                    ),
                }

            confidence = mapping_data.get("confidence")

            if AttackChainReconstructor._is_number(confidence):
                mapping_data["confidence"] = float(confidence)

            matched_events = mapping_data.get(
                "matched_events",
                [],
            )

            if isinstance(matched_events, dict):
                matched_events = [matched_events]

            if not isinstance(matched_events, list):
                matched_events = []

            for matched_event in matched_events:
                if not isinstance(matched_event, dict):
                    continue

                timestamp = AttackChainReconstructor._string_value(
                    matched_event.get("timestamp")
                )

                source = AttackChainReconstructor._string_value(
                    matched_event.get("source")
                )

                if not timestamp:
                    continue

                key = (timestamp, source)

                index.setdefault(key, []).append(mapping_data)

        return index

    @staticmethod
    def _build_evidence_index(
        evidence: Iterable[Any],
    ) -> Dict[Tuple[str, str], List[str]]:
        """Index evidence references by timestamp/source."""

        index: Dict[Tuple[str, str], List[str]] = {}

        for item_number, item in enumerate(evidence):
            if hasattr(item, "as_dict"):
                data = item.as_dict()
            elif isinstance(item, dict):
                data = dict(item)
            else:
                data = {
                    "timestamp": getattr(
                        item,
                        "timestamp",
                        None,
                    ),
                    "source": getattr(
                        item,
                        "source",
                        None,
                    ),
                    "evidence_id": getattr(
                        item,
                        "evidence_id",
                        None,
                    ),
                    "id": getattr(
                        item,
                        "id",
                        None,
                    ),
                }

            timestamp = AttackChainReconstructor._string_value(
                data.get("timestamp")
            )

            source = AttackChainReconstructor._string_value(
                data.get("source")
            )

            if not timestamp:
                continue

            reference = (
                AttackChainReconstructor._string_value(
                    data.get("evidence_id")
                )
                or AttackChainReconstructor._string_value(
                    data.get("id")
                )
                or f"evidence-{item_number + 1}"
            )

            key = (timestamp, source)

            index.setdefault(key, []).append(reference)

        return index

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_key(event: Event) -> Tuple[str, str]:
        return (
            AttackChainReconstructor._string_value(
                getattr(event, "timestamp", "")
            ),
            AttackChainReconstructor._string_value(
                getattr(event, "source", "")
            ),
        )

    @staticmethod
    def _step_confidence(
        event: Event,
        mappings: List[Dict[str, Any]],
        evidence_references: List[str],
    ) -> float:
        """
        Calculate a conservative step confidence.

        This is confidence that the reconstruction is supported by the
        available telemetry, not confidence that an attack succeeded.
        """

        score = 0.35

        if mappings:
            score += 0.25

        if evidence_references:
            score += 0.20

        if getattr(event, "event_type", None):
            score += 0.05

        if getattr(event, "source", None):
            score += 0.05

        if (
            getattr(event, "pid", None) is not None
            and getattr(event, "parent_pid", None) is not None
        ):
            score += 0.10

        return round(min(score, 1.0), 3)

    @classmethod
    def _stage_for(
        cls,
        event: Event,
        tactics: List[str],
    ) -> str:
        """Determine a descriptive attack-chain stage."""

        normalized_tactics = []

        for tactic in tactics:
            normalized = cls._STAGE_ALIASES.get(
                tactic.strip().lower()
            )

            if normalized:
                normalized_tactics.append(normalized)

        for stage in cls._STAGE_PRIORITY:
            if stage in normalized_tactics:
                return stage

        event_type = cls._string_value(
            getattr(event, "event_type", None)
        ).lower()

        message = cls._string_value(
            getattr(event, "message", None)
        ).lower()

        combined = f"{event_type} {message}"

        if any(
            token in combined
            for token in (
                "login",
                "authentication",
                "auth",
                "ssh",
            )
        ):
            return "initial_access"

        if any(
            token in combined
            for token in (
                "exec",
                "command",
                "shell",
                "process",
            )
        ):
            return "execution"

        if any(
            token in combined
            for token in (
                "sudo",
                "privilege",
                "root",
            )
        ):
            return "privilege_escalation"

        if any(
            token in combined
            for token in (
                "scan",
                "discover",
                "enumerat",
                "network",
            )
        ):
            return "discovery"

        if any(
            token in combined
            for token in (
                "download",
                "wget",
                "curl",
                "http",
                "https",
            )
        ):
            return "command_and_control"

        return "observed_activity"

    @staticmethod
    def _description(event: Event) -> str:
        message = AttackChainReconstructor._string_value(
            getattr(event, "message", None)
        )

        if message:
            return message

        event_type = AttackChainReconstructor._string_value(
            getattr(event, "event_type", None)
        )

        source = AttackChainReconstructor._string_value(
            getattr(event, "source", None)
        )

        if event_type and source:
            return f"{event_type} event observed from {source}."

        if event_type:
            return f"{event_type} event observed."

        return "Security-relevant event observed."

    @classmethod
    def _sort_events(
        cls,
        events: Iterable[Event],
    ) -> List[Event]:
        """
        Sort events chronologically.

        A numeric timestamp key is used so aware and naive timestamps do
        not cause Python datetime comparison errors.
        """

        indexed = list(enumerate(events))

        indexed.sort(
            key=lambda pair: (
                cls._timestamp_sort_key(
                    getattr(pair[1], "timestamp", "")
                ),
                pair[0],
            )
        )

        return [event for _, event in indexed]

    @classmethod
    def _timestamp_sort_key(cls, value: Any) -> float:
        """
        Convert timestamps into a comparable numeric value.

        Unknown timestamps sort after known timestamps.
        """

        timestamp = cls._string_value(value)

        if not timestamp:
            return float("inf")

        parsed = cls._parse_timestamp(timestamp)

        if parsed is None:
            return float("inf")

        try:
            if parsed.tzinfo is not None:
                return parsed.timestamp()

            # Naive timestamps are treated as UTC for ordering purposes.
            return parsed.replace().timestamp()
        except (OverflowError, OSError, ValueError):
            return float("inf")

    @staticmethod
    def _parse_timestamp(
        value: str,
    ) -> Optional[datetime]:
        value = value.strip()

        if not value:
            return None

        candidates = [
            value,
            value.replace("Z", "+00:00"),
        ]

        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]

        for candidate in candidates:
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                pass

        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                pass

        return None

    # ------------------------------------------------------------------
    # Gap detection
    # ------------------------------------------------------------------

    @staticmethod
    def _identify_gaps(
        events: List[Event],
        mappings: List[Any],
        steps: List[AttackChainStep],
    ) -> List[str]:
        gaps: List[str] = []

        if events and not mappings:
            gaps.append(
                "No MITRE ATT&CK mappings were available; "
                "the chain is based on event chronology and metadata."
            )

        if steps and all(
            not step.technique_ids
            for step in steps
        ):
            gaps.append(
                "No reconstructed step has an associated ATT&CK "
                "technique."
            )

        if steps and all(
            step.pid is None
            for step in steps
        ):
            gaps.append(
                "No process identifiers were available, so process "
                "parent/child relationships could not be reconstructed."
            )

        if any(
            not AttackChainReconstructor._parse_timestamp(
                AttackChainReconstructor._string_value(
                    getattr(event, "timestamp", "")
                )
            )
            for event in events
        ):
            gaps.append(
                "One or more event timestamps could not be parsed "
                "reliably."
            )

        return gaps

    # ------------------------------------------------------------------
    # Primitive helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _string_value(value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value.strip()

        return str(value).strip()

    @staticmethod
    def _int_value(value: Any) -> Optional[int]:
        if value is None or value == "":
            return None

        if isinstance(value, bool):
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_number(value: Any) -> bool:
        if isinstance(value, bool):
            return False

        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False


# ----------------------------------------------------------------------
# Standalone self-test
# ----------------------------------------------------------------------

if __name__ == "__main__":
    class FakeGate:
        def check(self, feature: str) -> bool:
            return feature == ATTACK_CHAIN_FEATURE

    reconstructor = AttackChainReconstructor(
        feature_gate=FakeGate()
    )

    events = [
        Event(
            timestamp="2026-09-20T10:00:00",
            source="auth.log",
            severity="WARNING",
            event_type="authentication",
            message="SSH authentication attempt observed",
            user="dave",
            pid=100,
        ),
        Event(
            timestamp="2026-09-20T10:01:00",
            source="auth.log",
            severity="WARNING",
            event_type="command",
            message="sudo command observed",
            process="sudo",
            pid=200,
            parent_pid=100,
        ),
        Event(
            timestamp="2026-09-20T10:02:00",
            source="syslog",
            severity="INFO",
            event_type="process",
            message="Command execution observed",
            process="bash",
            pid=300,
            parent_pid=200,
        ),
    ]

    class FakeInvestigation:
        def __init__(self) -> None:
            self.events = events

            self.mitre_mappings = [
                {
                    "technique_id": "T1021.004",
                    "technique_name": "SSH",
                    "tactic": "Initial Access",
                    "confidence": 0.8,
                    "matched_events": [
                        {
                            "timestamp": events[0].timestamp,
                            "source": events[0].source,
                        }
                    ],
                    "rationale": "SSH activity observed.",
                },
                {
                    "technique_id": "T1548.003",
                    "technique_name": "Sudo and Sudo Caching",
                    "tactic": "Privilege Escalation",
                    "confidence": 0.9,
                    "matched_events": [
                        {
                            "timestamp": events[1].timestamp,
                            "source": events[1].source,
                        }
                    ],
                    "rationale": "Sudo activity observed.",
                },
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "confidence": 0.85,
                    "matched_events": [
                        {
                            "timestamp": events[2].timestamp,
                            "source": events[2].source,
                        }
                    ],
                    "rationale": "Command execution observed.",
                },
            ]

            self.evidence = [
                {
                    "evidence_id": "EV-001",
                    "timestamp": events[0].timestamp,
                    "source": events[0].source,
                },
                {
                    "evidence_id": "EV-002",
                    "timestamp": events[1].timestamp,
                    "source": events[1].source,
                },
                {
                    "evidence_id": "EV-003",
                    "timestamp": events[2].timestamp,
                    "source": events[2].source,
                },
            ]

            self.attack_chain = {}

        def set_attack_chain(
            self,
            attack_chain: Dict[str, Any],
        ) -> None:
            self.attack_chain = attack_chain

        def touch(self) -> None:
            pass

    investigation = FakeInvestigation()

    result = reconstructor.reconstruct_and_store(
        investigation
    )

    assert result["summary"]["step_count"] == 3
    assert result["summary"]["link_count"] >= 3
    assert result["summary"]["technique_count"] == 3
    assert result["summary"]["technique_name_count"] == 3
    assert result["summary"]["tactic_count"] == 3
    assert result["summary"]["evidence_count"] == 3
    assert result["summary"]["process_relationship_count"] == 2

    assert len(result["steps"]) == 3
    assert len(result["links"]) >= 3

    assert result["steps"][0]["technique_ids"] == [
        "T1021.004"
    ]
    assert result["steps"][1]["technique_ids"] == [
        "T1548.003"
    ]
    assert result["steps"][2]["technique_ids"] == [
        "T1059"
    ]

    assert investigation.attack_chain == result

    print("Attack Chain Reconstruction self-test: PASSED")
    print(
        f"Steps: {result['summary']['step_count']}, "
        f"Links: {result['summary']['link_count']}, "
        f"Techniques: {result['summary']['technique_count']}, "
        f"Process relationships: "
        f"{result['summary']['process_relationship_count']}"
    )
