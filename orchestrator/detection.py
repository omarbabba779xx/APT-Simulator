"""Lightweight Sigma rule evaluator.

Supports the subset of Sigma syntax used by APT Simulator's own rules:

  - Field modifiers: |endswith, |startswith, |contains, |all
  - Selection values: string, list (any-of) or list with |all (all-of)
  - Condition primitives: 'selection', '1 of selection_*', 'all of selection_*'

For unknown conditions, returns False rather than raising — the matcher is a
fast-path for the simulator's own ruleset, not a general Sigma engine.
"""
from __future__ import annotations

from typing import Any


def _coerce(v: Any) -> str:
    return str(v) if v is not None else ""


def _field_match(event_value: Any, modifier: str | None, target: str) -> bool:
    ev = _coerce(event_value).lower()
    tv = _coerce(target).lower()
    if modifier == "endswith":
        return ev.endswith(tv)
    if modifier == "startswith":
        return ev.startswith(tv)
    if modifier == "contains":
        return tv in ev
    return ev == tv


def _matches_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for key, target in selection.items():
        parts = key.split("|")
        field = parts[0]
        modifiers = parts[1:]
        all_required = "all" in modifiers
        modifier = next((m for m in modifiers if m != "all"), None)

        ev_val = event.get(field)
        if ev_val is None:
            return False

        if isinstance(target, list):
            checks = [_field_match(ev_val, modifier, t) for t in target]
            if all_required:
                if not all(checks):
                    return False
            else:
                if not any(checks):
                    return False
        elif isinstance(target, bool):
            if bool(ev_val) != target:
                return False
        else:
            if not _field_match(ev_val, modifier, target):
                return False
    return True


def _selections_matching_prefix(matches: dict[str, bool], prefix: str) -> list[bool]:
    return [v for k, v in matches.items() if k.startswith(prefix)]


def evaluate(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection") or {}
    condition = str(detection.get("condition", "")).strip()
    selections = {k: v for k, v in detection.items() if k != "condition"}

    sel_match = {name: _matches_selection(event, sel) for name, sel in selections.items() if isinstance(sel, dict)}

    if condition == "selection":
        return sel_match.get("selection", False)

    if condition.startswith("1 of "):
        rest = condition[len("1 of ") :].strip()
        if rest.endswith("*"):
            prefix = rest[:-1]
            return any(_selections_matching_prefix(sel_match, prefix))
        return sel_match.get(rest, False)

    if condition.startswith("all of "):
        rest = condition[len("all of ") :].strip()
        if rest.endswith("*"):
            prefix = rest[:-1]
            matching = _selections_matching_prefix(sel_match, prefix)
            return bool(matching) and all(matching)
        return sel_match.get(rest, False)

    return False


def evaluate_many(rule: dict[str, Any], events: list[dict[str, Any]]) -> list[int]:
    """Return the indices of events that the rule matches."""
    return [i for i, ev in enumerate(events) if evaluate(rule, ev)]
