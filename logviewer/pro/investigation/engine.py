from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from logviewer.pro.attack_chain.reconstructor import AttackChainReconstructor
from logviewer.pro.false_positive.analyzer import FalsePositiveAnalyzer
from logviewer.pro.findings.analyzer import FindingAnalyzer
from logviewer.pro.investigation.model import Investigation
from logviewer.pro.investigation.store import InvestigationStore
from logviewer.pro.mitre.mapper import MitreMapper
from logviewer.pro.process.analyzer import ProcessTreeAnalyzer
from logviewer.pro.scoring.threat_score import ThreatScorer
from logviewer.pro.timeline.reconstructor import TimelineReconstructor


INVESTIGATION_FEATURE = "investigation"
THREAT_SCORING_FEATURE = "threat_scoring"
MITRE_FEATURE = "mitre"
FALSE_POSITIVE_FEATURE = "false_positive_analysis"
PROCESS_TREE_FEATURE = "process_tree"
ATTACK_CHAIN_FEATURE = "attack_chain"
TIMELINE_FEATURE = "timeline"
FINDINGS_FEATURE = "findings"


class InvestigationEngine:
    def __init__(
        self,
        feature_gate,
        store: Optional[InvestigationStore] = None,
        correlation_engine=None,
    ) -> None:
        self.feature_gate = feature_gate
        self.store = store
        self.correlation_engine = correlation_engine

        self.mitre_mapper = MitreMapper(
            feature_gate=self.feature_gate
        )
        self.threat_scorer = ThreatScorer(
            feature_gate=self.feature_gate
        )
        self.false_positive_analyzer = FalsePositiveAnalyzer(
            feature_gate=self.feature_gate
        )
        self.process_tree_analyzer = ProcessTreeAnalyzer(
            feature_gate=self.feature_gate
        )
        self.attack_chain_reconstructor = AttackChainReconstructor(
            feature_gate=self.feature_gate
        )
        self.timeline_reconstructor = TimelineReconstructor(
            feature_gate=self.feature_gate
        )
        self.finding_analyzer = FindingAnalyzer(
            feature_gate=self.feature_gate
        )

    def create_investigation(
        self,
        investigation_id: str,
        events: Optional[Iterable[Any]] = None,
        title: str = "Untitled Investigation",
        status: str = "open",
        severity: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Investigation:
        self._require_feature(INVESTIGATION_FEATURE)

        investigation = Investigation(
            investigation_id=investigation_id,
            title=title,
            status=status,
            severity=severity,
            metadata=dict(metadata or {}),
        )

        for event in events or []:
            investigation.add_event(event)

        self._extract_iocs(investigation)
        self._build_evidence(investigation)
        self._run_correlation(investigation)

        if self.feature_gate.check(MITRE_FEATURE):
            mappings = self.mitre_mapper.map_events(
                investigation.events
            )

            investigation.set_mitre_mappings(
                self._serialize_mitre_mappings(mappings)
            )

        investigation.confidence = self._calculate_confidence(
            investigation
        )

        if self.feature_gate.check(THREAT_SCORING_FEATURE):
            threat_score = self.threat_scorer.score(
                investigation
            )

            self._store_threat_score(
                investigation,
                threat_score,
            )

        if self.feature_gate.check(FALSE_POSITIVE_FEATURE):
            self.false_positive_analyzer.analyze_and_store(
                investigation
            )

        if self.feature_gate.check(PROCESS_TREE_FEATURE):
            self.process_tree_analyzer.analyze_and_store(
                investigation
            )

        if self.feature_gate.check(ATTACK_CHAIN_FEATURE):
            self.attack_chain_reconstructor.reconstruct_and_store(
                investigation
            )

        if self.feature_gate.check(TIMELINE_FEATURE):
            self.timeline_reconstructor.reconstruct_and_store(
                investigation
            )

        if self.feature_gate.check(FINDINGS_FEATURE):
            self.finding_analyzer.analyze_and_store(
                investigation
            )

        if self.store is not None:
            self.store.save(investigation)

        return investigation

    def _require_feature(self, feature: str) -> None:
        if not self.feature_gate.check(feature):
            raise PermissionError(
                f"Feature '{feature}' requires an active Pro license."
            )

    @staticmethod
    def _serialize_mitre_mappings(
        mappings: Optional[Iterable[Any]],
    ) -> list[Dict[str, Any]]:
        serialized: list[Dict[str, Any]] = []

        for mapping in mappings or []:
            if isinstance(mapping, dict):
                serialized.append(dict(mapping))
                continue

            as_dict = getattr(mapping, "as_dict", None)

            if callable(as_dict):
                value = as_dict()

                if isinstance(value, dict):
                    serialized.append(dict(value))

        return serialized

    @staticmethod
    def _store_threat_score(
        investigation: Investigation,
        threat_score: Any,
    ) -> None:
        """
        Normalize ThreatScore output into the Investigation model.

        The scoring component owns score calculation. The investigation
        model owns persistence of the normalized score and its details.
        """

        if threat_score is None:
            return

        if isinstance(threat_score, dict):
            score_value = threat_score.get(
                "score",
                threat_score.get("threat_score", 0),
            )

            level = threat_score.get(
                "level",
                threat_score.get("threat_level", "INFO"),
            )

            details = dict(threat_score)

        else:
            score_value = getattr(
                threat_score,
                "score",
                getattr(threat_score, "threat_score", 0),
            )

            level = getattr(
                threat_score,
                "level",
                getattr(
                    threat_score,
                    "threat_level",
                    "INFO",
                ),
            )

            as_dict = getattr(
                threat_score,
                "as_dict",
                None,
            )

            if callable(as_dict):
                serialized = as_dict()
                details = (
                    dict(serialized)
                    if isinstance(serialized, dict)
                    else {}
                )
            else:
                details = {}

        try:
            normalized_score = int(score_value)
        except (TypeError, ValueError):
            normalized_score = 0

        normalized_level = (
            str(level)
            if level is not None
            else "INFO"
        )

        investigation.set_threat_score(
            normalized_score,
            normalized_level,
            details,
        )

    def _extract_iocs(self, investigation: Investigation) -> None:
        iocs = []

        for event in investigation.events:
            event_dict = (
                event.as_dict()
                if hasattr(event, "as_dict")
                else dict(event)
                if isinstance(event, dict)
                else {}
            )

            for field_name, value in event_dict.items():
                if value is None:
                    continue

                if isinstance(value, str) and value.strip():
                    lowered = field_name.lower()

                    if (
                        "ip" in lowered
                        or "domain" in lowered
                        or "url" in lowered
                        or "hash" in lowered
                    ):
                        iocs.append(
                            {
                                "type": field_name,
                                "value": value,
                            }
                        )

        investigation.iocs = iocs

    def _build_evidence(self, investigation: Investigation) -> None:
        evidence = []

        for index, event in enumerate(investigation.events):
            event_dict = (
                event.as_dict()
                if hasattr(event, "as_dict")
                else dict(event)
                if isinstance(event, dict)
                else {}
            )

            evidence.append(
                {
                    "evidence_id": (
                        f"{investigation.investigation_id}-evt-{index + 1}"
                    ),
                    "type": "event",
                    "source": event_dict.get(
                        "source",
                        "",
                    ),
                    "timestamp": event_dict.get(
                        "timestamp",
                        "",
                    ),
                    "severity": event_dict.get(
                        "severity",
                        "INFO",
                    ),
                    "message": event_dict.get(
                        "message",
                        "",
                    ),
                    "event_index": index,
                }
            )

        investigation.evidence = evidence

    def _run_correlation(self, investigation: Investigation) -> None:
        if self.correlation_engine is None:
            return

        try:
            result = self.correlation_engine.correlate(
                investigation.events
            )
        except TypeError:
            result = self.correlation_engine.correlate(
                events=investigation.events
            )

        if result is None:
            return

        if isinstance(result, dict):
            investigation.correlations = result.get(
                "correlations",
                result.get("findings", []),
            )

        elif isinstance(result, list):
            investigation.correlations = result

        else:
            investigation.correlations = []

    def _calculate_confidence(
        self,
        investigation: Investigation,
    ) -> float:
        values = []

        for mapping in investigation.mitre_mappings:
            confidence = mapping.get("confidence")

            if isinstance(confidence, (int, float)):
                value = float(confidence)

                if value > 1:
                    value /= 100.0

                values.append(
                    max(0.0, min(1.0, value))
                )

        if values:
            return round(
                sum(values) / len(values),
                4,
            )

        if investigation.events:
            return 0.5

        return 0.0

    def save(self, investigation: Investigation) -> None:
        if self.store is None:
            raise RuntimeError(
                "No investigation store is configured."
            )

        self.store.save(investigation)

    def load(self, investigation_id: str) -> Optional[Investigation]:
        if self.store is None:
            raise RuntimeError(
                "No investigation store is configured."
            )

        return self.store.load(investigation_id)
