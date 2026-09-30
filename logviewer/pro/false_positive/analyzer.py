from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from logviewer.licensing.feature_gate import FeatureGate


FALSE_POSITIVE_FEATURE = "false_positive_analysis"


@dataclass(frozen=True)
class FalsePositiveSignal:
    name: str
    points: int
    reason: str


@dataclass(frozen=True)
class FalsePositiveAnalysis:
    classification: str
    confidence: int
    score: int
    reasons: List[str] = field(default_factory=list)
    signals: List[Dict[str, Any]] = field(default_factory=list)
    evidence_count: int = 0
    ioc_count: int = 0
    correlation_count: int = 0
    mitre_count: int = 0
    threat_score: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": self.confidence,
            "score": self.score,
            "reasons": list(self.reasons),
            "signals": [dict(signal) for signal in self.signals],
            "evidence_count": self.evidence_count,
            "ioc_count": self.ioc_count,
            "correlation_count": self.correlation_count,
            "mitre_count": self.mitre_count,
            "threat_score": self.threat_score,
        }


class FalsePositiveAnalysisError(RuntimeError):
    """Raised when false-positive analysis cannot be completed."""


class FalsePositiveAnalyzer:
    """
    Evidence-based false-positive analysis for LogViewer Pro.

    This analyzer does not suppress, delete, or hide evidence.
    It produces an explainable assessment that investigators can
    use alongside the original evidence.
    """

    BENIGN_EVENT_TYPES = {
        "cron",
        "apt_transaction",
        "package_install",
        "package_upgrade",
        "package_remove",
        "system_update",
    }

    SECURITY_EVENT_TYPES = {
        "authentication_failure",
        "authentication_success",
        "privilege_escalation",
        "firewall",
        "security_alert",
        "intrusion_detection",
        "command_execution",
        "process_execution",
    }

    def __init__(
        self,
        feature_gate: Optional[FeatureGate] = None,
    ):
        self.feature_gate = feature_gate or FeatureGate()

    def analyze(self, investigation: Any) -> FalsePositiveAnalysis:
        self.feature_gate.require(FALSE_POSITIVE_FEATURE)

        if investigation is None:
            raise FalsePositiveAnalysisError(
                "Investigation cannot be None."
            )

        events = self._get_events(investigation)
        evidence = self._get_evidence(investigation)
        iocs = self._get_iocs(investigation)
        correlations = self._get_correlations(investigation)
        mitre_mappings = self._get_mitre_mappings(investigation)
        threat_score = self._get_threat_score(investigation)

        event_types = self._extract_event_types(events)
        messages = self._extract_messages(events, evidence)

        signals: List[FalsePositiveSignal] = []

        self._add_benign_signals(
            signals,
            event_types,
            messages,
        )

        self._add_security_signals(
            signals,
            event_types,
            messages,
        )

        self._add_context_signals(
            signals,
            iocs,
            correlations,
            mitre_mappings,
            threat_score,
        )

        score = sum(signal.points for signal in signals)

        classification = self._classify(
            score=score,
            ioc_count=len(iocs),
            correlation_count=len(correlations),
            mitre_count=len(mitre_mappings),
            threat_score=threat_score,
        )

        confidence = self._confidence(
            score=score,
            evidence_count=len(evidence),
            event_count=len(events),
            ioc_count=len(iocs),
            correlation_count=len(correlations),
            mitre_count=len(mitre_mappings),
        )

        reasons = self._build_reasons(
            classification=classification,
            signals=signals,
            evidence_count=len(evidence),
            ioc_count=len(iocs),
            correlation_count=len(correlations),
            mitre_count=len(mitre_mappings),
            threat_score=threat_score,
        )

        return FalsePositiveAnalysis(
            classification=classification,
            confidence=confidence,
            score=score,
            reasons=reasons,
            signals=[
                {
                    "name": signal.name,
                    "points": signal.points,
                    "reason": signal.reason,
                }
                for signal in signals
            ],
            evidence_count=len(evidence),
            ioc_count=len(iocs),
            correlation_count=len(correlations),
            mitre_count=len(mitre_mappings),
            threat_score=threat_score,
        )

    def analyze_and_store(
        self,
        investigation: Any,
    ) -> FalsePositiveAnalysis:
        analysis = self.analyze(investigation)

        if hasattr(investigation, "set_false_positive_analysis"):
            investigation.set_false_positive_analysis(
                analysis.as_dict()
            )
        else:
            setattr(
                investigation,
                "false_positive_analysis",
                analysis.as_dict(),
            )

        return analysis

    def _get_events(
        self,
        investigation: Any,
    ) -> List[Any]:
        events = getattr(investigation, "events", [])
        return list(events or [])

    def _get_evidence(
        self,
        investigation: Any,
    ) -> List[Any]:
        evidence = getattr(investigation, "evidence", [])
        return list(evidence or [])

    def _get_iocs(
        self,
        investigation: Any,
    ) -> List[Any]:
        raw_iocs = getattr(investigation, "iocs", {})

        if isinstance(raw_iocs, dict):
            values: List[Any] = []

            for item in raw_iocs.values():
                if isinstance(item, (list, tuple, set)):
                    values.extend(item)
                elif item:
                    values.append(item)

            return values

        if isinstance(raw_iocs, (list, tuple, set)):
            return list(raw_iocs)

        return []

    def _get_correlations(
        self,
        investigation: Any,
    ) -> List[Any]:
        correlations = getattr(
            investigation,
            "correlations",
            {},
        )

        if isinstance(correlations, dict):
            values: List[Any] = []

            for item in correlations.values():
                if isinstance(item, (list, tuple, set)):
                    values.extend(item)
                elif item:
                    values.append(item)

            return values

        if isinstance(correlations, (list, tuple, set)):
            return list(correlations)

        return []

    def _get_mitre_mappings(
        self,
        investigation: Any,
    ) -> List[Any]:
        mappings = getattr(
            investigation,
            "mitre_mappings",
            [],
        )

        return list(mappings or [])

    def _get_threat_score(
        self,
        investigation: Any,
    ) -> int:
        value = getattr(
            investigation,
            "threat_score",
            0,
        )

        try:
            return max(0, min(100, int(value)))
        except (TypeError, ValueError):
            return 0

    def _extract_event_types(
        self,
        events: Iterable[Any],
    ) -> set:
        event_types = set()

        for event in events:
            value = self._value(
                event,
                "event_type",
            )

            if value:
                event_types.add(
                    str(value).strip().lower()
                )

        return event_types

    def _extract_messages(
        self,
        events: Iterable[Any],
        evidence: Iterable[Any],
    ) -> List[str]:
        messages: List[str] = []

        for item in list(events) + list(evidence):
            for field_name in (
                "message",
                "raw",
                "description",
                "action",
                "command",
            ):
                value = self._value(
                    item,
                    field_name,
                )

                if value is None:
                    continue

                if isinstance(value, dict):
                    value = " ".join(
                        str(v)
                        for v in value.values()
                    )

                text = str(value).strip().lower()

                if text:
                    messages.append(text)

        return messages

    def _add_benign_signals(
        self,
        signals: List[FalsePositiveSignal],
        event_types: set,
        messages: List[str],
    ) -> None:
        benign_types = event_types & self.BENIGN_EVENT_TYPES

        if benign_types:
            names = ", ".join(
                sorted(benign_types)
            )

            signals.append(
                FalsePositiveSignal(
                    name="expected_system_activity",
                    points=10,
                    reason=(
                        "Observed event types commonly associated "
                        f"with routine system activity: {names}."
                    ),
                )
            )

        routine_terms = (
            "automatic update",
            "unattended-upgrade",
            "package update",
            "package upgrade",
            "cron job",
            "scheduled task",
            "log rotation",
        )

        if self._contains_any(
            messages,
            routine_terms,
        ):
            signals.append(
                FalsePositiveSignal(
                    name="routine_activity_indicator",
                    points=12,
                    reason=(
                        "Evidence contains indicators associated "
                        "with routine scheduled or maintenance activity."
                    ),
                )
            )

    def _add_security_signals(
        self,
        signals: List[FalsePositiveSignal],
        event_types: set,
        messages: List[str],
    ) -> None:
        security_types = event_types & self.SECURITY_EVENT_TYPES

        if security_types:
            names = ", ".join(
                sorted(security_types)
            )

            signals.append(
                FalsePositiveSignal(
                    name="security_relevant_event",
                    points=-15,
                    reason=(
                        "Observed event types are security-relevant: "
                        f"{names}."
                    ),
                )
            )

        suspicious_terms = (
            "authentication failure",
            "failed password",
            "invalid user",
            "brute force",
            "permission denied",
            "privilege escalation",
            "sudo",
            "command execution",
            "reverse shell",
            "malware",
            "intrusion",
            "exploit",
        )

        if self._contains_any(
            messages,
            suspicious_terms,
        ):
            signals.append(
                FalsePositiveSignal(
                    name="security_indicator",
                    points=-20,
                    reason=(
                        "Evidence contains security-relevant "
                        "authentication, privilege, execution, "
                        "or intrusion indicators."
                    ),
                )
            )

    def _add_context_signals(
        self,
        signals: List[FalsePositiveSignal],
        iocs: List[Any],
        correlations: List[Any],
        mitre_mappings: List[Any],
        threat_score: int,
    ) -> None:
        if iocs:
            signals.append(
                FalsePositiveSignal(
                    name="ioc_presence",
                    points=-15,
                    reason=(
                        f"Investigation contains {len(iocs)} extracted "
                        "indicator(s) of compromise."
                    ),
                )
            )

        if correlations:
            signals.append(
                FalsePositiveSignal(
                    name="correlated_activity",
                    points=-15,
                    reason=(
                        f"Investigation contains {len(correlations)} "
                        "correlated relationship(s)."
                    ),
                )
            )

        if mitre_mappings:
            signals.append(
                FalsePositiveSignal(
                    name="mitre_mapping",
                    points=-15,
                    reason=(
                        f"Evidence maps to {len(mitre_mappings)} "
                        "MITRE ATT&CK technique mapping(s)."
                    ),
                )
            )

        if threat_score >= 70:
            signals.append(
                FalsePositiveSignal(
                    name="high_threat_score",
                    points=-20,
                    reason=(
                        f"Existing threat score is high ({threat_score}/100)."
                    ),
                )
            )
        elif threat_score >= 40:
            signals.append(
                FalsePositiveSignal(
                    name="moderate_threat_score",
                    points=-10,
                    reason=(
                        f"Existing threat score is moderate ({threat_score}/100)."
                    ),
                )
            )

    def _classify(
        self,
        score: int,
        ioc_count: int,
        correlation_count: int,
        mitre_count: int,
        threat_score: int,
    ) -> str:
        if (
            score >= 15
            and ioc_count == 0
            and correlation_count == 0
            and mitre_count == 0
            and threat_score < 40
        ):
            return "LIKELY_BENIGN"

        if (
            score <= -15
            or ioc_count > 0
            or correlation_count > 0
            or mitre_count > 0
            or threat_score >= 70
        ):
            return "LIKELY_SECURITY_RELEVANT"

        return "UNCERTAIN"

    def _confidence(
        self,
        score: int,
        evidence_count: int,
        event_count: int,
        ioc_count: int,
        correlation_count: int,
        mitre_count: int,
    ) -> int:
        confidence = 50

        confidence += min(
            20,
            abs(score),
        )

        if evidence_count > 0:
            confidence += 5

        if event_count >= 5:
            confidence += 5

        if ioc_count > 0:
            confidence += 5

        if correlation_count > 0:
            confidence += 5

        if mitre_count > 0:
            confidence += 5

        return max(
            0,
            min(100, confidence),
        )

    def _build_reasons(
        self,
        classification: str,
        signals: List[FalsePositiveSignal],
        evidence_count: int,
        ioc_count: int,
        correlation_count: int,
        mitre_count: int,
        threat_score: int,
    ) -> List[str]:
        reasons = [
            (
                f"Classification: {classification} "
                "based on available investigation evidence."
            ),
            (
                f"Evidence items: {evidence_count}; "
                f"IOCs: {ioc_count}; "
                f"correlations: {correlation_count}; "
                f"MITRE mappings: {mitre_count}."
            ),
        ]

        if threat_score:
            reasons.append(
                f"Existing threat score: {threat_score}/100."
            )

        reasons.extend(
            signal.reason
            for signal in signals
        )

        reasons.append(
            "This assessment does not suppress or delete evidence."
        )

        return reasons

    @staticmethod
    def _contains_any(
        messages: Iterable[str],
        terms: Iterable[str],
    ) -> bool:
        for message in messages:
            if any(
                term in message
                for term in terms
            ):
                return True

        return False

    @staticmethod
    def _value(
        item: Any,
        field_name: str,
    ) -> Any:
        if isinstance(item, dict):
            return item.get(field_name)

        return getattr(
            item,
            field_name,
            None,
        )
