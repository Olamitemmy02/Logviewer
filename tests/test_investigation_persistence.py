from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from logviewer.pro.investigation.model import Investigation
from logviewer.pro.investigation.store import InvestigationStore


def build_investigation() -> Investigation:
    investigation = Investigation(
        investigation_id="persistence-test-001",
        title="Persistence Verification",
        status="open",
        severity="high",
        confidence=0.91,
        events=[
            {
                "event_id": "evt-001",
                "message": "Persistence test event",
            }
        ],
        evidence=[
            {
                "evidence_id": "ev-001",
                "type": "log",
            }
        ],
        iocs=[
            {
                "type": "ip",
                "value": "192.0.2.10",
            }
        ],
        correlations=[
            {
                "correlation_id": "corr-001",
            }
        ],
        mitre_mappings=[
            {
                "technique_id": "T1059",
            }
        ],
        findings=[
            {
                "finding_id": "finding-001",
                "title": "Persistence Test Finding",
                "severity": "high",
            }
        ],
        metadata={
            "persistence_test": True,
        },
    )

    investigation.set_threat_score(
        73,
        {
            "test": True,
            "score": 73,
        },
    )

    investigation.set_false_positive_analysis(
        {
            "test": True,
            "likely_false_positive": False,
        }
    )

    investigation.set_process_tree(
        {
            "node_count": 1,
            "relationship_count": 0,
            "nodes": [
                {
                    "pid": 100,
                    "name": "sshd",
                }
            ],
            "relationships": [],
        }
    )

    # Investigation.summary() expects attack_chain["summary"]
    # to be a dictionary containing these counters.
    investigation.set_attack_chain(
        {
            "summary": {
                "step_count": 1,
                "link_count": 0,
                "technique_count": 1,
                "tactic_count": 1,
                "process_relationship_count": 0,
            },
            "steps": [
                {
                    "step": 1,
                    "name": "Initial Access",
                }
            ],
        }
    )

    # Investigation.summary() expects timeline["summary"]
    # to be a dictionary containing these counters.
    investigation.set_timeline(
        {
            "summary": {
                "entry_count": 1,
                "event_count": 1,
                "correlation_count": 0,
                "mitre_count": 1,
                "process_relationship_count": 0,
                "attack_chain_step_count": 1,
                "gap_count": 0,
                "confidence": 0.91,
            },
            "entries": [
                {
                    "event_id": "evt-001",
                }
            ],
        }
    )

    investigation.set_mitre_mappings(
        [
            {
                "technique_id": "T1059",
            }
        ]
    )

    return investigation


def make_store(path: Path) -> InvestigationStore:
    attempts = (
        lambda: InvestigationStore(str(path)),
        lambda: InvestigationStore(path=str(path)),
        lambda: InvestigationStore(storage_path=str(path)),
        lambda: InvestigationStore(),
    )

    last_error = None

    for constructor in attempts:
        try:
            return constructor()
        except TypeError as exc:
            last_error = exc

    raise AssertionError(
        f"Could not construct InvestigationStore: {last_error}"
    )


def save_and_load(
    store: InvestigationStore,
    investigation: Investigation,
) -> Investigation:
    save_method = None

    for name in (
        "save",
        "store",
        "create",
        "add",
        "save_investigation",
    ):
        candidate = getattr(store, name, None)

        if callable(candidate):
            save_method = candidate
            break

    if save_method is None:
        raise AssertionError(
            "InvestigationStore has no supported save method."
        )

    save_method(investigation)

    investigation_id = investigation.investigation_id

    for name in (
        "get",
        "load",
        "find",
        "get_investigation",
        "load_investigation",
    ):
        candidate = getattr(store, name, None)

        if not callable(candidate):
            continue

        try:
            loaded = candidate(investigation_id)
        except (KeyError, FileNotFoundError):
            continue

        if loaded is not None:
            return loaded

    raise AssertionError(
        "InvestigationStore saved the investigation but no supported "
        "load/get method returned it."
    )


def test_investigation_round_trip_persistence():
    with TemporaryDirectory() as directory:
        storage_path = Path(directory) / "investigations"

        store = make_store(storage_path)
        original = build_investigation()

        # Verify serialization before persistence.
        original_data = original.as_dict()

        assert original_data["investigation_id"] == (
            "persistence-test-001"
        )
        assert original_data["attack_chain"]["summary"]["step_count"] == 1
        assert original_data["timeline"]["summary"]["entry_count"] == 1

        loaded = save_and_load(store, original)

        assert loaded is not None
        assert loaded.investigation_id == original.investigation_id
        assert loaded.title == original.title
        assert loaded.status == original.status
        assert loaded.severity == original.severity
        assert loaded.confidence == original.confidence

        assert loaded.events == original.events
        assert loaded.evidence == original.evidence
        assert loaded.iocs == original.iocs
        assert loaded.correlations == original.correlations
        assert loaded.mitre_mappings == original.mitre_mappings
        assert loaded.findings == original.findings

        assert loaded.threat_score == original.threat_score
        assert loaded.threat_level == original.threat_level
        assert loaded.threat_score_details == original.threat_score_details
        assert (
            loaded.false_positive_analysis
            == original.false_positive_analysis
        )
        assert loaded.process_tree == original.process_tree
        assert loaded.attack_chain == original.attack_chain
        assert loaded.timeline == original.timeline
        assert loaded.metadata == original.metadata


def test_investigation_serialization_contains_pro_fields():
    investigation = build_investigation()

    data = investigation.as_dict()

    required_fields = {
        "investigation_id",
        "title",
        "status",
        "severity",
        "confidence",
        "threat_score",
        "threat_level",
        "threat_score_details",
        "false_positive_analysis",
        "process_tree",
        "attack_chain",
        "timeline",
        "events",
        "evidence",
        "iocs",
        "correlations",
        "mitre_mappings",
        "findings",
        "metadata",
    }

    missing = required_fields - set(data)

    assert not missing, (
        f"Missing persisted Pro fields: {sorted(missing)}"
    )

    assert data["attack_chain"]["summary"]["step_count"] == 1
    assert data["timeline"]["summary"]["entry_count"] == 1
    assert data["process_tree"]["node_count"] == 1


def test_investigation_round_trip_keeps_nested_pro_data():
    investigation = build_investigation()

    data = investigation.as_dict()

    assert data["process_tree"]["nodes"][0]["name"] == "sshd"

    assert (
        data["attack_chain"]["steps"][0]["name"]
        == "Initial Access"
    )

    assert (
        data["attack_chain"]["summary"]["step_count"]
        == 1
    )

    assert (
        data["timeline"]["entries"][0]["event_id"]
        == "evt-001"
    )

    assert (
        data["timeline"]["summary"]["entry_count"]
        == 1
    )

    assert (
        data["findings"][0]["finding_id"]
        == "finding-001"
    )


if __name__ == "__main__":
    test_investigation_round_trip_persistence()
    test_investigation_serialization_contains_pro_fields()
    test_investigation_round_trip_keeps_nested_pro_data()
    print("Investigation Persistence self-test: PASSED")
