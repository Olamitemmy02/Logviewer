import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from logviewer.licensing.feature_gate import FeatureGate


PROCESS_TREE_FEATURE = "process_tree"


PID_PATTERN = re.compile(
    r"\b(?:pid|process[_\s-]*id)\s*[=:]\s*(\d+)\b",
    re.IGNORECASE,
)

PPID_PATTERN = re.compile(
    r"\b(?:ppid|parent[_\s-]*pid|parent[_\s-]*process[_\s-]*id)"
    r"\s*[=:]\s*(\d+)\b",
    re.IGNORECASE,
)

COMMAND_PATTERN = re.compile(
    r"\b(?:command|cmd|command_line|argv)\s*[=:]\s*"
    r"([^\n\r]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProcessNode:
    pid: int
    ppid: Optional[int] = None
    process: str = ""
    command: str = ""
    source: str = ""
    timestamp: Optional[str] = None
    event_index: Optional[int] = None
    evidence: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "process": self.process,
            "command": self.command,
            "source": self.source,
            "timestamp": self.timestamp,
            "event_index": self.event_index,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ProcessRelationship:
    parent_pid: int
    child_pid: int
    relationship: str = "parent_child"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parent_pid": self.parent_pid,
            "child_pid": self.child_pid,
            "relationship": self.relationship,
        }


@dataclass(frozen=True)
class ProcessTree:
    nodes: List[ProcessNode]
    relationships: List[ProcessRelationship]
    roots: List[int]
    orphaned: List[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                node.as_dict()
                for node in self.nodes
            ],
            "relationships": [
                relationship.as_dict()
                for relationship in self.relationships
            ],
            "roots": list(self.roots),
            "orphaned": list(self.orphaned),
            "node_count": len(self.nodes),
            "relationship_count": len(
                self.relationships
            ),
        }


class ProcessTreeError(RuntimeError):
    """Raised when process-tree analysis cannot be completed."""


class ProcessTreeAnalyzer:
    """
    Builds an evidence-based process tree from investigation events.

    The analyzer only creates process relationships when PID/PPID
    information is present in the supplied evidence. Missing process
    information is represented by an empty result rather than inferred.
    """

    def __init__(
        self,
        feature_gate: Optional[FeatureGate] = None,
    ):
        self.feature_gate = (
            feature_gate or FeatureGate()
        )

    def analyze(
        self,
        investigation: Any,
    ) -> ProcessTree:
        self.feature_gate.require(
            PROCESS_TREE_FEATURE
        )

        if investigation is None:
            raise ProcessTreeError(
                "Investigation cannot be None."
            )

        events = getattr(
            investigation,
            "events",
            [],
        )

        return self.build(
            events or []
        )

    def build(
        self,
        events: Iterable[Any],
    ) -> ProcessTree:
        nodes_by_pid: Dict[int, ProcessNode] = {}

        for index, event in enumerate(events):
            record = self._extract_process_record(
                event,
                index,
            )

            if record is None:
                continue

            pid = record["pid"]

            existing = nodes_by_pid.get(pid)

            if existing is None:
                nodes_by_pid[pid] = ProcessNode(
                    pid=pid,
                    ppid=record["ppid"],
                    process=record["process"],
                    command=record["command"],
                    source=record["source"],
                    timestamp=record["timestamp"],
                    event_index=index,
                    evidence=record["evidence"],
                )
                continue

            nodes_by_pid[pid] = self._merge_nodes(
                existing,
                record,
            )

        nodes = sorted(
            nodes_by_pid.values(),
            key=lambda node: node.pid,
        )

        relationships: List[ProcessRelationship] = []

        for node in nodes:
            if node.ppid is None:
                continue

            if node.ppid == node.pid:
                continue

            if node.ppid not in nodes_by_pid:
                continue

            relationships.append(
                ProcessRelationship(
                    parent_pid=node.ppid,
                    child_pid=node.pid,
                )
            )

        relationship_children = {
            relationship.child_pid
            for relationship in relationships
        }

        roots = sorted(
            node.pid
            for node in nodes
            if node.pid not in relationship_children
        )

        known_pids = set(
            nodes_by_pid
        )

        orphaned = sorted(
            node.pid
            for node in nodes
            if (
                node.ppid is not None
                and node.ppid != node.pid
                and node.ppid not in known_pids
            )
        )

        return ProcessTree(
            nodes=nodes,
            relationships=relationships,
            roots=roots,
            orphaned=orphaned,
        )

    def analyze_and_store(
        self,
        investigation: Any,
    ) -> ProcessTree:
        tree = self.analyze(
            investigation
        )

        tree_data = tree.as_dict()

        if hasattr(
            investigation,
            "set_process_tree",
        ):
            investigation.set_process_tree(
                tree_data
            )
        else:
            setattr(
                investigation,
                "process_tree",
                tree_data,
            )

        return tree

    def _extract_process_record(
        self,
        event: Any,
        index: int,
    ) -> Optional[Dict[str, Any]]:
        pid = self._extract_int(
            event,
            (
                "pid",
                "process_id",
                "process_pid",
            ),
        )

        ppid = self._extract_int(
            event,
            (
                "ppid",
                "parent_pid",
                "parent_process_id",
                "parent_pid",
            ),
        )

        text_values = self._collect_text(
            event
        )

        combined_text = "\n".join(
            text_values
        )

        if pid is None:
            match = PID_PATTERN.search(
                combined_text
            )

            if match:
                pid = int(
                    match.group(1)
                )

        if ppid is None:
            match = PPID_PATTERN.search(
                combined_text
            )

            if match:
                ppid = int(
                    match.group(1)
                )

        if pid is None:
            return None

        process = self._extract_text_value(
            event,
            (
                "process",
                "process_name",
                "comm",
                "executable",
            ),
        )

        command = self._extract_text_value(
            event,
            (
                "command",
                "command_line",
                "cmd",
                "argv",
            ),
        )

        if not command:
            match = COMMAND_PATTERN.search(
                combined_text
            )

            if match:
                command = match.group(1).strip()

        source = self._extract_text_value(
            event,
            (
                "source",
                "source_path",
                "log_source",
            ),
        )

        timestamp = self._extract_text_value(
            event,
            (
                "timestamp",
                "time",
                "datetime",
            ),
        )

        evidence = self._build_evidence(
            event,
            pid,
            ppid,
        )

        return {
            "pid": pid,
            "ppid": ppid,
            "process": process or "",
            "command": command or "",
            "source": source or "",
            "timestamp": timestamp,
            "evidence": evidence,
        }

    @staticmethod
    def _extract_int(
        event: Any,
        fields: Iterable[str],
    ) -> Optional[int]:
        for field_name in fields:
            value = ProcessTreeAnalyzer._value(
                event,
                field_name,
            )

            if value is None:
                continue

            try:
                return int(value)
            except (TypeError, ValueError):
                continue

        return None

    @staticmethod
    def _extract_text_value(
        event: Any,
        fields: Iterable[str],
    ) -> str:
        for field_name in fields:
            value = ProcessTreeAnalyzer._value(
                event,
                field_name,
            )

            if value is None:
                continue

            if isinstance(value, (dict, list, tuple)):
                continue

            text = str(value).strip()

            if text:
                return text

        return ""

    @staticmethod
    def _collect_text(
        event: Any,
    ) -> List[str]:
        values: List[str] = []

        for field_name in (
            "message",
            "raw",
            "description",
            "action",
            "command",
            "command_line",
        ):
            value = ProcessTreeAnalyzer._value(
                event,
                field_name,
            )

            if value is None:
                continue

            if isinstance(value, dict):
                values.extend(
                    str(item)
                    for item in value.values()
                )
                continue

            if isinstance(value, (list, tuple)):
                values.extend(
                    str(item)
                    for item in value
                )
                continue

            values.append(
                str(value)
            )

        return values

    @staticmethod
    def _build_evidence(
        event: Any,
        pid: int,
        ppid: Optional[int],
    ) -> List[str]:
        evidence = [
            f"PID={pid}"
        ]

        if ppid is not None:
            evidence.append(
                f"PPID={ppid}"
            )

        for field_name in (
            "message",
            "raw",
        ):
            value = ProcessTreeAnalyzer._value(
                event,
                field_name,
            )

            if value is None:
                continue

            text = str(value).strip()

            if text:
                evidence.append(
                    text
                )

        return evidence

    @staticmethod
    def _merge_nodes(
        existing: ProcessNode,
        record: Dict[str, Any],
    ) -> ProcessNode:
        evidence = list(
            existing.evidence
        )

        for item in record["evidence"]:
            if item not in evidence:
                evidence.append(item)

        return ProcessNode(
            pid=existing.pid,
            ppid=(
                existing.ppid
                if existing.ppid is not None
                else record["ppid"]
            ),
            process=(
                existing.process
                or record["process"]
            ),
            command=(
                existing.command
                or record["command"]
            ),
            source=(
                existing.source
                or record["source"]
            ),
            timestamp=(
                existing.timestamp
                or record["timestamp"]
            ),
            event_index=existing.event_index,
            evidence=evidence,
        )

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
