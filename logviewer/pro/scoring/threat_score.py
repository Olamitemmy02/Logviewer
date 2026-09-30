from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional

from logviewer.licensing.feature_gate import FeatureGate

THREAT_SCORING_FEATURE = "threat_scoring"

SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 8,
    "MEDIUM": 16,
    "HIGH": 24,
    "CRITICAL": 30,
}

IOC_WEIGHTS = {
    "ipv4": 4,
    "domain": 5,
    "url": 6,
    "sha256": 8,
    "sha1": 7,
    "md5": 6,
}

AUTHENTICATION_TYPES = {
    "authentication",
    "auth",
    "login",
    "ssh",
    "sudo",
    "privilege",
    "privilege_escalation",
}

SECURITY_TYPES = {
    "security",
    "security_control",
    "firewall",
    "ufw",
    "snort",
    "intrusion",
    "alert",
}

EXECUTION_TYPES = {
    "execution",
    "process",
    "command",
    "shell",
    "script",
}

THREAT_LEVELS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "INFO"),
)


@dataclass(frozen=True)
class ScoreComponent:
    name: str
    points: int
    maximum: int
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "points": self.points,
            "maximum": self.maximum,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ThreatScore:
    score: int
    level: str
    components: tuple = field(default_factory=tuple)

    @property
    def reasons(self) -> list:
        return [
            component.reason
            for component in self.components
            if component.reason
        ]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "components": [
                component.as_dict()
                for component in self.components
            ],
            "reasons": self.reasons,
        }


class ThreatScoringError(RuntimeError):
    """Raised when threat scoring cannot be performed."""


class ThreatScorer:
    """
    Explainable LogViewer Pro threat scoring engine.

    The scorer produces a deterministic score from investigation
    evidence already collected by LogViewer.

    Maximum score: 100.

    Components:
        Severity        30 points
        IOC activity    25 points
        Evidence        15 points
        Correlations    20 points
        Security signals 10 points

    No component is based on an opaque or random value.
    """

    def __init__(
        self,
        feature_gate: Optional[FeatureGate] = None,
    ):
        self.feature_gate = feature_gate or FeatureGate()

    def score(self, investigation) -> ThreatScore:
        self.feature_gate.require(
            THREAT_SCORING_FEATURE
        )

        components = [
            self._score_severity(
                getattr(investigation, "severity", "INFO")
            ),
            self._score_iocs(
                getattr(investigation, "iocs", {})
            ),
            self._score_evidence(
                getattr(investigation, "evidence", [])
            ),
            self._score_correlations(
                getattr(investigation, "correlations", {})
            ),
            self._score_security_signals(
                getattr(investigation, "events", [])
            ),
        ]

        total = min(
            100,
            max(
                0,
                sum(component.points for component in components),
            ),
        )

        return ThreatScore(
            score=total,
            level=self.level_for(total),
            components=tuple(components),
        )

    @staticmethod
    def level_for(score: int) -> str:
        normalized = min(
            100,
            max(0, int(score)),
        )

        for threshold, level in THREAT_LEVELS:
            if normalized >= threshold:
                return level

        return "INFO"

    @staticmethod
    def _score_severity(severity: str) -> ScoreComponent:
        normalized = str(
            severity or "INFO"
        ).strip().upper()

        points = SEVERITY_POINTS.get(
            normalized,
            SEVERITY_POINTS["INFO"],
        )

        return ScoreComponent(
            name="severity",
            points=points,
            maximum=30,
            reason=(
                f"Investigation severity is {normalized}; "
                f"severity contributes {points}/30 points."
            ),
        )

    @staticmethod
    def _score_iocs(
        iocs: Mapping[str, Iterable[Any]],
    ) -> ScoreComponent:
        points = 0
        total_iocs = 0
        contributing_types = []

        if not isinstance(iocs, Mapping):
            iocs = {}

        for ioc_type, values in iocs.items():
            normalized_type = str(
                ioc_type
            ).strip().lower()

            try:
                count = len(values)
            except TypeError:
                count = 0

            if count <= 0:
                continue

            total_iocs += count

            weight = IOC_WEIGHTS.get(
                normalized_type,
                2,
            )

            points += min(
                12,
                count * weight,
            )

            contributing_types.append(
                f"{normalized_type} ({count})"
            )

        points = min(25, points)

        if total_iocs:
            detail = ", ".join(
                contributing_types
            )
            reason = (
                f"{total_iocs} IOC(s) detected across "
                f"{detail}; IOC activity contributes "
                f"{points}/25 points."
            )
        else:
            reason = (
                "No extracted IOCs are present; "
                "IOC activity contributes 0/25 points."
            )

        return ScoreComponent(
            name="ioc_activity",
            points=points,
            maximum=25,
            reason=reason,
        )

    @staticmethod
    def _score_evidence(
        evidence: Iterable[Any],
    ) -> ScoreComponent:
        try:
            count = len(evidence)
        except TypeError:
            evidence = list(evidence or [])
            count = len(evidence)

        points = min(
            15,
            count * 2,
        )

        if count == 0:
            reason = (
                "No evidence items are attached; "
                "evidence contributes 0/15 points."
            )
        else:
            reason = (
                f"{count} evidence item(s) attached; "
                f"evidence contributes {points}/15 points."
            )

        return ScoreComponent(
            name="evidence_volume",
            points=points,
            maximum=15,
            reason=reason,
        )

    @staticmethod
    def _score_correlations(
        correlations: Any,
    ) -> ScoreComponent:
        count = ThreatScorer._count_correlations(
            correlations
        )

        points = min(
            20,
            count * 2,
        )

        if count == 0:
            reason = (
                "No correlation relationships are present; "
                "correlation contributes 0/20 points."
            )
        else:
            reason = (
                f"{count} correlation relationship(s) detected; "
                f"correlation contributes {points}/20 points."
            )

        return ScoreComponent(
            name="correlations",
            points=points,
            maximum=20,
            reason=reason,
        )

    @staticmethod
    def _count_correlations(
        correlations: Any,
    ) -> int:
        if correlations is None:
            return 0

        if isinstance(correlations, Mapping):
            total = 0

            for value in correlations.values():
                if isinstance(value, Mapping):
                    total += len(value)
                elif isinstance(value, (list, tuple, set)):
                    total += len(value)
                elif value:
                    total += 1

            return total

        if isinstance(
            correlations,
            (list, tuple, set),
        ):
            return len(correlations)

        return 1 if correlations else 0

    @staticmethod
    def _score_security_signals(
        events: Iterable[Any],
    ) -> ScoreComponent:
        authentication = 0
        security = 0
        execution = 0

        for event in events or []:
            event_type = ThreatScorer._event_type(
                event
            )

            if not event_type:
                continue

            if event_type in AUTHENTICATION_TYPES:
                authentication += 1

            if event_type in SECURITY_TYPES:
                security += 1

            if event_type in EXECUTION_TYPES:
                execution += 1

        signal_count = (
            authentication
            + security
            + execution
        )

        points = min(
            10,
            authentication * 2
            + security * 2
            + execution,
        )

        if signal_count == 0:
            reason = (
                "No authentication, security-control, or "
                "execution signals were identified; "
                "security signals contribute 0/10 points."
            )
        else:
            reason = (
                f"Security signals detected: "
                f"authentication={authentication}, "
                f"security={security}, "
                f"execution={execution}; "
                f"signals contribute {points}/10 points."
            )

        return ScoreComponent(
            name="security_signals",
            points=points,
            maximum=10,
            reason=reason,
        )

    @staticmethod
    def _event_type(event: Any) -> str:
        value = getattr(
            event,
            "event_type",
            "",
        )

        if not value and isinstance(event, Mapping):
            value = event.get(
                "event_type",
                "",
            )

        return str(
            value or ""
        ).strip().lower()


def score_investigation(
    investigation,
    feature_gate: Optional[FeatureGate] = None,
) -> ThreatScore:
    """
    Convenience wrapper around ThreatScorer.
    """
    return ThreatScorer(
        feature_gate=feature_gate
    ).score(investigation)
