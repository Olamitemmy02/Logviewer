from typing import Iterable, List, Optional

from .engine import CorrelationFinding


class CorrelationFilter:
    """
    Filters correlation findings without changing the underlying
    correlation analysis.

    Filtering is an investigation/viewing operation.
    It does not alter or reclassify findings.
    """

    def __init__(
        self,
        ioc_type: Optional[str] = None,
        relationship: Optional[str] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        query: Optional[str] = None,
        min_events: Optional[int] = None,
        max_events: Optional[int] = None,
        min_sources: Optional[int] = None,
        min_time_span: Optional[float] = None,
        max_time_span: Optional[float] = None,
    ):
        self.ioc_type = self._clean(ioc_type)
        self.relationship = self._clean(relationship)
        self.source = self._clean(source)
        self.event_type = self._clean(event_type)
        self.severity = self._clean(severity)
        self.query = self._clean(query)

        self.min_events = min_events
        self.max_events = max_events
        self.min_sources = min_sources

        self.min_time_span = min_time_span
        self.max_time_span = max_time_span

    @staticmethod
    def _clean(
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        value = str(value).strip().lower()

        return value or None

    def matches(
        self,
        finding: CorrelationFinding,
    ) -> bool:
        """
        Determine whether one finding satisfies every configured
        filter.
        """

        if self.ioc_type:
            if finding.ioc_type.lower() != self.ioc_type:
                return False

        if self.relationship:
            if (
                finding.relationship.lower()
                != self.relationship
            ):
                return False

        if self.source:
            sources = {
                source.lower()
                for source in finding.sources
            }

            if self.source not in sources:
                return False

        if self.event_type:
            event_types = {
                event_type.lower()
                for event_type in finding.event_types
            }

            if self.event_type not in event_types:
                return False

        if self.severity:
            if not self._finding_has_severity(
                finding,
                self.severity,
            ):
                return False

        if self.query:
            if not self._matches_query(
                finding,
                self.query,
            ):
                return False

        if (
            self.min_events is not None
            and finding.event_count < self.min_events
        ):
            return False

        if (
            self.max_events is not None
            and finding.event_count > self.max_events
        ):
            return False

        if (
            self.min_sources is not None
            and finding.source_count < self.min_sources
        ):
            return False

        if self.min_time_span is not None:
            if finding.time_span_seconds is None:
                return False

            if finding.time_span_seconds < self.min_time_span:
                return False

        if self.max_time_span is not None:
            if finding.time_span_seconds is None:
                return False

            if finding.time_span_seconds > self.max_time_span:
                return False

        return True

    def apply(
        self,
        findings: Iterable[CorrelationFinding],
    ) -> List[CorrelationFinding]:
        """
        Return findings matching the current filter.
        """

        return [
            finding
            for finding in findings
            if self.matches(finding)
        ]

    @staticmethod
    def _matches_query(
        finding: CorrelationFinding,
        query: str,
    ) -> bool:
        """
        Search the finding and its supporting evidence context.
        """

        searchable = [
            finding.ioc_type,
            finding.value,
            finding.relationship,
            finding.description,
        ]

        searchable.extend(
            finding.sources
        )

        searchable.extend(
            finding.event_types
        )

        for evidence in finding.evidence:
            searchable.extend(
                [
                    evidence.source or "",
                    evidence.evidence_type or "",
                    evidence.description or "",
                ]
            )

            searchable.extend(
                str(value)
                for value in evidence.metadata.values()
                if value is not None
            )

        haystack = " ".join(
            str(value)
            for value in searchable
        ).lower()

        return query in haystack

    @staticmethod
    def _finding_has_severity(
        finding: CorrelationFinding,
        severity: str,
    ) -> bool:
        """
        Check severity against the supporting evidence.

        A finding matches when at least one supporting evidence
        item has the requested severity.
        """

        for evidence in finding.evidence:
            evidence_severity = str(
                evidence.metadata.get(
                    "severity",
                    "",
                )
            ).lower()

            if evidence_severity == severity:
                return True

        return False


def filter_findings(
    findings: Iterable[CorrelationFinding],
    **kwargs,
) -> List[CorrelationFinding]:
    """
    Convenience function for applying filters.
    """

    correlation_filter = CorrelationFilter(
        **kwargs
    )

    return correlation_filter.apply(
        findings
    )


def available_ioc_types(
    findings: Iterable[CorrelationFinding],
) -> List[str]:
    return sorted(
        {
            finding.ioc_type
            for finding in findings
            if finding.ioc_type
        }
    )


def available_relationships(
    findings: Iterable[CorrelationFinding],
) -> List[str]:
    return sorted(
        {
            finding.relationship
            for finding in findings
            if finding.relationship
        }
    )


def available_sources(
    findings: Iterable[CorrelationFinding],
) -> List[str]:
    sources = set()

    for finding in findings:
        sources.update(
            source
            for source in finding.sources
            if source
        )

    return sorted(
        sources
    )


def available_event_types(
    findings: Iterable[CorrelationFinding],
) -> List[str]:
    event_types = set()

    for finding in findings:
        event_types.update(
            event_type
            for event_type in finding.event_types
            if event_type
        )

    return sorted(
        event_types
    )


def available_severities(
    findings: Iterable[CorrelationFinding],
) -> List[str]:
    severities = set()

    for finding in findings:
        for evidence in finding.evidence:
            severity = evidence.metadata.get(
                "severity"
            )

            if severity:
                severities.add(
                    str(severity)
                )

    return sorted(
        severities
    )
