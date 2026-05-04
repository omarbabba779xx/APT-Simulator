from __future__ import annotations

import ttps  # noqa: F401
from orchestrator.detection import evaluate
from ttps.base import registry


def test_every_ttp_with_rule_has_synthetic_events_that_match() -> None:
    """Every TTP that ships a Sigma rule must ship synthetic events that the
    rule actually matches. Catches drift between rule and TTP behavior."""
    failures: list[str] = []
    for attack_id, ttp in sorted(registry.all().items()):
        rule = ttp.sigma_rule()
        if rule is None:
            continue
        events = ttp.synthetic_events({}, None)
        if not events:
            failures.append(f"{attack_id}: rule defined but no synthetic_events")
            continue
        matched = any(evaluate(rule, ev) for ev in events)
        if not matched:
            failures.append(
                f"{attack_id}: synthetic events {events} do not match rule"
            )
    assert not failures, "Coverage gaps detected:\n  " + "\n  ".join(failures)
