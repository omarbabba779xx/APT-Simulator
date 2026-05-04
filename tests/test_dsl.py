from __future__ import annotations

import pytest

from orchestrator.dsl.schema import Scenario, ScenarioStep


def _scenario(steps: list[dict]) -> Scenario:
    return Scenario(name="t", steps=[ScenarioStep(**s) for s in steps])


def test_valid_dag() -> None:
    sc = _scenario([
        {"id": "a", "ttp": "T1033"},
        {"id": "b", "ttp": "T1083", "depends_on": ["a"]},
    ])
    sc.validate_dag()


def test_unknown_dependency() -> None:
    sc = _scenario([
        {"id": "a", "ttp": "T1033"},
        {"id": "b", "ttp": "T1083", "depends_on": ["missing"]},
    ])
    with pytest.raises(ValueError, match="unknown step"):
        sc.validate_dag()


def test_cycle_detected() -> None:
    sc = _scenario([
        {"id": "a", "ttp": "T1033", "depends_on": ["b"]},
        {"id": "b", "ttp": "T1083", "depends_on": ["a"]},
    ])
    with pytest.raises(ValueError, match="cycle"):
        sc.validate_dag()


def test_duplicate_step_id() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        _scenario([
            {"id": "a", "ttp": "T1033"},
            {"id": "a", "ttp": "T1083"},
        ])


def test_invalid_attack_id() -> None:
    with pytest.raises(ValueError, match="invalid"):
        ScenarioStep(id="x", ttp="not-an-id")
