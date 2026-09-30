from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from logviewer.licensing.feature_gate import FeatureGate


MITRE_FEATURE = "mitre"


@dataclass(frozen=True)
class TechniqueRule:
    technique_id: str
    technique_name: str
    tactic: str
    event_types: Tuple[str, ...] = ()
    keywords: Tuple[str, ...] = ()
    commands: Tuple[str, ...] = ()
    rationale: str = ""
    base_confidence: float = 0.50


@dataclass
class MitreMapping:
    """
    Evidence-backed candidate mapping between observed events and
    a MITRE ATT&CK technique.

    A mapping represents an observed pattern. It does not by itself
    prove that the technique was successfully executed.
    """

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    matched_events: List[Dict[str, Any]] = field(
        default_factory=list
    )
    rationale: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": round(
                max(0.0, min(1.0, self.confidence)),
                4,
            ),
            "matched_events": self.matched_events,
            "rationale": self.rationale,
        }


class MitreMappingError(RuntimeError):
    """Raised when MITRE mapping cannot be performed."""


# These are intentionally high-signal host-log patterns rather than
# broad guesses based on every network or authentication event.
TECHNIQUE_RULES: Tuple[TechniqueRule, ...] = (
    TechniqueRule(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        event_types=(
            "command",
            "command_execution",
            "execution",
            "process",
        ),
        keywords=(
            "bash -c",
            "sh -c",
            "python -c",
            "python3 -c",
            "perl -e",
            "powershell",
            "cmd.exe",
        ),
        rationale=(
            "The event contains an explicit command or scripting "
            "interpreter execution pattern."
        ),
        base_confidence=0.82,
    ),
    TechniqueRule(
        technique_id="T1548.003",
        technique_name="Sudo and Sudo Caching",
        tactic="Privilege Escalation",
        event_types=(
            "sudo",
            "privilege",
            "privilege_escalation",
            "command",
            "execution",
        ),
        keywords=(
            "sudo:",
            "sudo ",
            "sudo[",
            "command allowed",
            "user is not in the sudoers file",
        ),
        commands=(
            "sudo",
        ),
        rationale=(
            "The event contains an explicit sudo invocation or "
            "sudo authorization result."
        ),
        base_confidence=0.90,
    ),
    TechniqueRule(
        technique_id="T1057",
        technique_name="Process Discovery",
        tactic="Discovery",
        event_types=(
            "process",
            "command",
            "command_execution",
            "execution",
        ),
        commands=(
            "ps",
            "pstree",
            "top",
            "htop",
        ),
        keywords=(
            "ps aux",
            "ps -ef",
            "pstree",
        ),
        rationale=(
            "The event contains a process-enumeration command "
            "associated with process discovery."
        ),
        base_confidence=0.86,
    ),
    TechniqueRule(
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="Discovery",
        event_types=(
            "command",
            "command_execution",
            "execution",
        ),
        commands=(
            "getent passwd",
            "getent group",
            "last",
            "lastlog",
        ),
        keywords=(
            "/etc/passwd",
            "/etc/group",
            "getent passwd",
            "getent group",
        ),
        rationale=(
            "The event contains an account or local-user "
            "enumeration pattern."
        ),
        base_confidence=0.82,
    ),
    TechniqueRule(
        technique_id="T1049",
        technique_name="System Network Connections Discovery",
        tactic="Discovery",
        event_types=(
            "command",
            "command_execution",
            "execution",
        ),
        commands=(
            "netstat",
            "ss ",
            "ip addr",
            "ip route",
        ),
        keywords=(
            "netstat -",
            "ss -",
            "ip addr",
            "ip route",
        ),
        rationale=(
            "The event contains a command used to enumerate "
            "network interfaces, routes, or connections."
        ),
        base_confidence=0.84,
    ),
    TechniqueRule(
        technique_id="T1562.004",
        technique_name="Disable or Modify System Firewall",
        tactic="Defense Evasion",
        event_types=(
            "ufw",
            "firewall",
            "command",
            "command_execution",
            "execution",
        ),
        commands=(
            "ufw disable",
            "ufw reset",
            "iptables -F",
            "nft flush ruleset",
        ),
        keywords=(
            "ufw disabled",
            "ufw disable",
            "ufw reset",
            "iptables -f",
            "iptables --flush",
            "nft flush ruleset",
        ),
        rationale=(
            "The event contains an explicit firewall disabling "
            "or flushing operation."
        ),
        base_confidence=0.94,
    ),
    TechniqueRule(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic="Command and Control",
        event_types=(
            "command",
            "command_execution",
            "execution",
        ),
        commands=(
            "curl ",
            "wget ",
        ),
        keywords=(
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://",
        ),
        rationale=(
            "The event contains an explicit curl or wget request "
            "that transfers content from a remote URL."
        ),
        base_confidence=0.80,
    ),
    TechniqueRule(
        technique_id="T1021.004",
        technique_name="SSH",
        tactic="Lateral Movement",
        event_types=(
            "ssh",
            "authentication",
            "auth",
            "login",
        ),
        keywords=(
            "sshd",
            "ssh session",
            "accepted publickey",
            "accepted password",
        ),
        rationale=(
            "The event contains an SSH service or SSH session "
            "indicator."
        ),
        base_confidence=0.78,
    ),
    TechniqueRule(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        event_types=(
            "authentication",
            "auth",
            "login",
            "ssh",
        ),
        keywords=(
            "failed password",
            "authentication failure",
            "failed login",
            "invalid user",
            "authentication failed",
        ),
        rationale=(
            "The event contains an authentication failure pattern. "
            "Repeated failures increase the strength of this "
            "candidate but do not independently prove brute force."
        ),
        base_confidence=0.62,
    ),
)


class MitreMapper:
    """
    Maps high-signal normalized LogViewer events to MITRE ATT&CK
    technique candidates.

    Mapping is offline and deterministic. No live MITRE API is
    required.
    """

    def __init__(
        self,
        feature_gate: Optional[FeatureGate] = None,
    ):
        self.feature_gate = (
            feature_gate or FeatureGate()
        )

    def map_events(
        self,
        events: Iterable[Any],
    ) -> List[Dict[str, Any]]:
        self.feature_gate.require(MITRE_FEATURE)

        event_list = list(events)
        mappings: List[MitreMapping] = []

        for rule in TECHNIQUE_RULES:
            matched: List[Dict[str, Any]] = []

            for event in event_list:
                match = self._match_event(
                    event,
                    rule,
                )

                if match is not None:
                    matched.append(match)

            if not matched:
                continue

            confidence = self._calculate_confidence(
                rule,
                matched,
            )

            mappings.append(
                MitreMapping(
                    technique_id=rule.technique_id,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    confidence=confidence,
                    matched_events=matched,
                    rationale=rule.rationale,
                )
            )

        return [
            mapping.as_dict()
            for mapping in mappings
        ]

    def map_investigation(
        self,
        investigation: Any,
    ) -> List[Dict[str, Any]]:
        self.feature_gate.require(MITRE_FEATURE)

        mappings = self.map_events(
            investigation.events
        )

        investigation.mitre_mappings = mappings

        if hasattr(investigation, "touch"):
            investigation.touch()

        return mappings

    @staticmethod
    def _event_text(event: Any) -> str:
        parts: List[str] = []

        for attribute in (
            "message",
            "event_type",
            "action",
            "command",
            "description",
            "source",
        ):
            value = getattr(
                event,
                attribute,
                None,
            )

            if value is not None:
                parts.append(str(value))

        raw = getattr(
            event,
            "raw",
            None,
        )

        if isinstance(raw, dict):
            for key, value in raw.items():
                if value is not None:
                    parts.append(
                        f"{key}={value}"
                    )
        elif raw is not None:
            parts.append(str(raw))

        return " ".join(parts).lower()

    @staticmethod
    def _event_type(event: Any) -> str:
        value = getattr(
            event,
            "event_type",
            "",
        )

        return str(value).strip().lower()

    @classmethod
    def _match_event(
        cls,
        event: Any,
        rule: TechniqueRule,
    ) -> Optional[Dict[str, Any]]:
        text = cls._event_text(event)
        event_type = cls._event_type(event)

        matched_patterns: List[str] = []

        if event_type and event_type in rule.event_types:
            matched_patterns.append(
                f"event_type:{event_type}"
            )

        for keyword in rule.keywords:
            if keyword.lower() in text:
                matched_patterns.append(
                    f"keyword:{keyword}"
                )

        for command in rule.commands:
            if command.lower() in text:
                matched_patterns.append(
                    f"command:{command}"
                )

        if not matched_patterns:
            return None

        timestamp = getattr(
            event,
            "timestamp",
            None,
        )

        source = getattr(
            event,
            "source",
            None,
        )

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        result: Dict[str, Any] = {
            "matched_patterns": sorted(
                set(matched_patterns)
            ),
        }

        if event_id is not None:
            result["event_id"] = str(event_id)

        if timestamp is not None:
            result["timestamp"] = str(timestamp)

        if source is not None:
            result["source"] = str(source)

        return result

    @staticmethod
    def _calculate_confidence(
        rule: TechniqueRule,
        matched_events: List[Dict[str, Any]],
    ) -> float:
        confidence = rule.base_confidence

        event_count = len(matched_events)

        if event_count >= 10:
            confidence += 0.08
        elif event_count >= 5:
            confidence += 0.05
        elif event_count >= 2:
            confidence += 0.03

        return round(
            min(0.99, confidence),
            4,
        )
