from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple
import hashlib
import json


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)

    method = getattr(value, "as_dict", None)
    if callable(method):
        result = method()
        if isinstance(result, dict):
            return dict(result)

    if hasattr(value, "__dict__"):
        return {
            key: item
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return {}


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _confidence(value: Any, default: float = 0.5) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        result = default

    if result > 1:
        result /= 100.0

    return max(0.0, min(1.0, result))


def _severity(value: Any, default: str = "INFO") -> str:
    normalized = _text(value, default).upper()

    aliases = {
        "INFORMATIONAL": "INFO",
        "WARNING": "MEDIUM",
        "ERROR": "HIGH",
        "SEVERE": "HIGH",
    }

    normalized = aliases.get(normalized, normalized)

    if normalized not in SEVERITY_ORDER:
        return default

    return normalized


def _stable_id(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return "F-" + hashlib.sha256(encoded).hexdigest()[:16].upper()


class FindingAnalyzer:
    """
    Build structured, evidence-linked findings from an Investigation.

    The analyzer does not independently declare malicious activity.
    It summarizes supplied events, correlations, and MITRE mappings,
    retaining their references and confidence values.
    """

    def __init__(self, feature_gate=None) -> None:
        self.feature_gate = feature_gate

    def analyze(self, investigation: Any) -> List[Dict[str, Any]]:
        if self.feature_gate is not None:
            check = getattr(self.feature_gate, "check", None)
            if callable(check) and not check("findings"):
                return []

        findings: List[Dict[str, Any]] = []
        seen = set()

        self._add_event_findings(investigation, findings, seen)
        self._add_correlation_findings(
            investigation,
            findings,
            seen,
        )
        self._add_mitre_findings(investigation, findings, seen)

        findings.sort(
            key=lambda item: (
                -SEVERITY_ORDER.get(item["severity"], 0),
                -item["confidence"],
                item["finding_id"],
            )
        )

        return findings

    def analyze_and_store(self, investigation: Any) -> List[Dict[str, Any]]:
        findings = self.analyze(investigation)

        setter = getattr(investigation, "add_finding", None)
        if callable(setter):
            for finding in findings:
                setter(finding)
        elif hasattr(investigation, "findings"):
            investigation.findings = list(findings)

        return findings

    def _append_unique(
        self,
        finding: Dict[str, Any],
        findings: List[Dict[str, Any]],
        seen: set,
    ) -> None:
        key = (
            finding["title"].casefold(),
            tuple(sorted(finding["event_ids"])),
            tuple(sorted(finding["evidence_ids"])),
            tuple(sorted(finding["mitre_techniques"])),
        )

        if key in seen:
            return

        seen.add(key)
        finding["finding_id"] = _stable_id({
            "title": finding["title"],
            "event_ids": finding["event_ids"],
            "evidence_ids": finding["evidence_ids"],
            "mitre_techniques": finding["mitre_techniques"],
        })
        findings.append(finding)

    def _add_event_findings(
        self,
        investigation: Any,
        findings: List[Dict[str, Any]],
        seen: set,
    ) -> None:
        events = getattr(investigation, "events", []) or []
        evidence = getattr(investigation, "evidence", []) or []

        evidence_by_index = {}
        for item in evidence:
            data = _as_dict(item)
            index = data.get("event_index")
            if index is not None:
                evidence_by_index[str(index)] = data

        for index, event in enumerate(events):
            data = _as_dict(event)
            if not data:
                continue

            message = _text(data.get("message"))
            source = _text(data.get("source"), "unknown")
            timestamp = _text(data.get("timestamp"))
            severity = _severity(data.get("severity"), "INFO")

            if not message:
                continue

            event_id = _text(
                data.get("event_id", data.get("id", f"event-{index + 1}"))
            )

            evidence_data = evidence_by_index.get(str(index), {})
            evidence_id = _text(evidence_data.get("evidence_id"))

            title = _text(
                data.get("finding_title"),
                f"Observed {source} event",
            )

            finding = {
                "title": title,
                "summary": message,
                "severity": severity,
                "confidence": _confidence(
                    data.get("confidence"),
                    0.5,
                ),
                "rationale": (
                    "This finding summarizes an event supplied "
                    "to the investigation. Its presence alone "
                    "does not establish malicious intent."
                ),
                "source": source,
                "first_seen": timestamp or None,
                "last_seen": timestamp or None,
                "event_ids": [event_id],
                "evidence_ids": [evidence_id] if evidence_id else [],
                "ioc_values": self._event_iocs(data),
                "mitre_techniques": [],
                "correlation_ids": [],
                "false_positive_context": (
                    "Review event context, expected system activity, "
                    "and corroborating evidence before disposition."
                ),
                "metadata": {
                    "origin": "event",
                    "event_index": index,
                },
            }

            self._append_unique(finding, findings, seen)

    def _add_correlation_findings(
        self,
        investigation: Any,
        findings: List[Dict[str, Any]],
        seen: set,
    ) -> None:
        for index, correlation in enumerate(
            getattr(investigation, "correlations", []) or []
        ):
            data = _as_dict(correlation)
            if not data:
                continue

            title = _text(
                data.get("title", data.get("name")),
                "Correlated security activity",
            )
            summary = _text(
                data.get("summary", data.get("description", data.get("message"))),
                "Related events were grouped by the correlation component.",
            )

            event_ids = self._string_list(
                data.get("event_ids", data.get("related_event_ids", []))
            )
            evidence_ids = self._string_list(
                data.get("evidence_ids", []),
            )
            ioc_values = self._string_list(
                data.get("ioc_values", data.get("iocs", []))
            )
            technique_ids = self._string_list(
                data.get(
                    "mitre_techniques",
                    data.get("technique_ids", []),
                )
            )

            finding = {
                "title": title,
                "summary": summary,
                "severity": _severity(
                    data.get("severity", data.get("level")),
                    "MEDIUM",
                ),
                "confidence": _confidence(
                    data.get("confidence"),
                    0.6,
                ),
                "rationale": _text(
                    data.get("rationale"),
                    "The correlation component grouped related activity. "
                    "Validate the underlying events and correlation logic.",
                ),
                "source": _text(data.get("source"), "correlation"),
                "first_seen": data.get("first_seen", data.get("start_time")),
                "last_seen": data.get("last_seen", data.get("end_time")),
                "event_ids": event_ids,
                "evidence_ids": evidence_ids,
                "ioc_values": ioc_values,
                "mitre_techniques": technique_ids,
                "correlation_ids": self._string_list([
                    data.get(
                        "correlation_id",
                        data.get("finding_id", f"correlation-{index + 1}"),
                    )
                ]),
                "false_positive_context": _text(
                    data.get("false_positive_context"),
                    "Check whether the events share a legitimate cause "
                    "before treating the correlation as suspicious.",
                ),
                "metadata": {
                    "origin": "correlation",
                    "correlation_index": index,
                },
            }

            self._append_unique(finding, findings, seen)

    def _add_mitre_findings(
        self,
        investigation: Any,
        findings: List[Dict[str, Any]],
        seen: set,
    ) -> None:
        for index, mapping in enumerate(
            getattr(investigation, "mitre_mappings", []) or []
        ):
            data = _as_dict(mapping)
            if not data:
                continue

            technique_id = _text(
                data.get("technique_id", data.get("id"))
            )
            technique_name = _text(
                data.get("technique_name", data.get("name")),
                "MITRE ATT&CK technique",
            )

            if not technique_id and not technique_name:
                continue

            title = (
                f"ATT&CK mapping: {technique_id} — {technique_name}"
                if technique_id
                else f"ATT&CK mapping: {technique_name}"
            )

            event_ids = self._string_list(
                data.get("event_ids", data.get("matched_event_ids", []))
            )
            evidence_ids = self._string_list(data.get("evidence_ids", []))

            finding = {
                "title": title,
                "summary": _text(
                    data.get("description", data.get("summary")),
                    "The MITRE mapper associated investigation activity "
                    "with this technique.",
                ),
                "severity": _severity(data.get("severity"), "INFO"),
                "confidence": _confidence(
                    data.get("confidence"),
                    0.5,
                ),
                "rationale": (
                    "This is a technique mapping, not proof that the "
                    "technique was successfully used. Validate the "
                    "matched event evidence."
                ),
                "source": "mitre",
                "first_seen": data.get("first_seen", data.get("timestamp")),
                "last_seen": data.get("last_seen", data.get("timestamp")),
                "event_ids": event_ids,
                "evidence_ids": evidence_ids,
                "ioc_values": self._string_list(data.get("ioc_values", [])),
                "mitre_techniques": (
                    [technique_id] if technique_id else []
                ),
                "correlation_ids": self._string_list(
                    data.get("correlation_ids", [])
                ),
                "false_positive_context": (
                    "ATT&CK mappings can be ambiguous. Confirm that "
                    "the observed behavior matches the technique's "
                    "documented behavior in this environment."
                ),
                "metadata": {
                    "origin": "mitre",
                    "mapping_index": index,
                    "tactic": data.get("tactic"),
                },
            }

            self._append_unique(finding, findings, seen)

    @staticmethod
    def _string_list(value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, (str, int, float)):
            values = [value]
        elif isinstance(value, dict):
            values = list(value.values())
        elif isinstance(value, Iterable):
            values = list(value)
        else:
            values = [value]

        result = []
        for item in values:
            if isinstance(item, dict):
                item = (
                    item.get("value")
                    or item.get("id")
                    or item.get("event_id")
                    or item.get("evidence_id")
                )

            if item is None:
                continue

            text = str(item).strip()
            if text and text not in result:
                result.append(text)

        return result

    @classmethod
    def _event_iocs(cls, event: Dict[str, Any]) -> List[str]:
        values = []

        for key, value in event.items():
            lowered = str(key).lower()
            if any(token in lowered for token in (
                "ip",
                "domain",
                "url",
                "hash",
                "ioc",
            )):
                values.extend(cls._string_list(value))

        return values
