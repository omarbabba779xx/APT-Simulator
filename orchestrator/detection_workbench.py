"""Detection-as-code quality checks for simulator Sigma rules."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry


app = typer.Typer(no_args_is_help=True)

REQUIRED_SIGMA_FIELDS = ("title", "id", "status", "logsource", "detection", "falsepositives", "level", "tags")
TARGETS = ("splunk", "elastic", "sentinel", "chronicle")


@app.callback()
def _root() -> None:
    """Detection-as-code workbench."""


def _selection_fields(rule: dict[str, Any]) -> list[str]:
    fields: set[str] = set()
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return []
    for key, value in detection.items():
        if key == "condition" or not isinstance(value, dict):
            continue
        for field in value:
            fields.add(str(field).split("|", 1)[0])
    return sorted(fields)


def _logsource_quality(logsource: Any) -> str:
    if not isinstance(logsource, dict) or not logsource:
        return "missing"
    category = str(logsource.get("category", "")).lower()
    product = str(logsource.get("product", "")).lower()
    if category == "generic" and not product:
        return "generic"
    if category or product:
        return "specific"
    return "weak"


def _risk(missing: list[str], fields: list[str], logsource_quality: str) -> str:
    if "detection" in missing or logsource_quality == "missing":
        return "high"
    if missing or len(fields) < 2 or logsource_quality in {"generic", "weak"}:
        return "medium"
    return "low"


def analyze_rule(rule: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_SIGMA_FIELDS if field not in rule or rule.get(field) in (None, "", [])]
    fields = _selection_fields(rule)
    logsource_quality = _logsource_quality(rule.get("logsource"))
    risk = _risk(missing, fields, logsource_quality)
    score = 100
    score -= len(missing) * 8
    score -= 12 if logsource_quality == "generic" else 0
    score -= 20 if logsource_quality == "missing" else 0
    score -= 10 if len(fields) < 2 else 0
    if risk == "high":
        score -= 15
    elif risk == "medium":
        score -= 5
    return {
        "quality_score": max(0, min(100, score)),
        "false_positive_risk": risk,
        "missing_fields": missing,
        "selection_fields": fields,
        "field_count": len(fields),
        "logsource_quality": logsource_quality,
        "exports": list(TARGETS),
    }


def build_workbench(limit_items: int = 5000) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    risk_counts = {"low": 0, "medium": 0, "high": 0}
    missing_field_counts: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    score_total = 0
    for attack_id, ttp in sorted(registry.all().items()):
        rule = ttp.sigma_rule()
        if rule is None:
            continue
        result = analyze_rule(rule)
        score_total += int(result["quality_score"])
        risk_counts[result["false_positive_risk"]] += 1
        for field in result["missing_fields"]:
            missing_field_counts[field] = missing_field_counts.get(field, 0) + 1
        for field in result["selection_fields"]:
            field_counts[field] = field_counts.get(field, 0) + 1
        if len(items) < limit_items:
            items.append(
                {
                    "attack_id": attack_id,
                    "base_attack_id": str(getattr(ttp, "base_attack_id", attack_id)),
                    "name": ttp.name,
                    "pack": str(getattr(ttp, "pack", "core")),
                    **result,
                }
            )
    total = sum(risk_counts.values())
    top_fields: list[dict[str, object]] = [
        {"field": field, "count": count} for field, count in field_counts.items()
    ]
    top_fields.sort(key=lambda item: (-int(str(item["count"])), str(item["field"])))
    return {
        "total_rules": total,
        "average_quality_score": round(score_total / total, 2) if total else 0,
        "risk_counts": risk_counts,
        "missing_field_counts": dict(sorted(missing_field_counts.items())),
        "top_fields": top_fields[:25],
        "targets": list(TARGETS),
        "items": items,
    }


def _iter_rule_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted([p for p in path.rglob("*.yml")] + [p for p in path.rglob("*.yaml")])


def _rule_attack_ids(rule: dict[str, Any]) -> set[str]:
    text = json.dumps(rule, sort_keys=True)
    ids = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text.upper()))
    tags = rule.get("tags") or []
    for tag in tags:
        match = re.search(r"attack\.t(\d{4})(?:\.(\d{3}))?", str(tag).lower())
        if match:
            ids.add("T" + match.group(1) + (f".{match.group(2)}" if match.group(2) else ""))
    return ids


def compare_rule_directory(path: str) -> dict[str, Any]:
    base = Path(path)
    mapped: dict[str, int] = {}
    parse_errors = 0
    files = _iter_rule_files(base)
    for file_path in files:
        try:
            rule = yaml.safe_load(file_path.read_text(encoding="utf-8", errors="ignore")) or {}
        except yaml.YAMLError:
            parse_errors += 1
            continue
        if not isinstance(rule, dict):
            continue
        for attack_id in _rule_attack_ids(rule):
            mapped[attack_id] = mapped.get(attack_id, 0) + 1
    local_ids = {str(getattr(ttp, "base_attack_id", attack_id)).split(":", 1)[0] for attack_id, ttp in registry.all().items()}
    external_ids = set(mapped)
    overlap = local_ids & external_ids
    top_external_ids: list[dict[str, object]] = [
        {"attack_id": attack_id, "rules": count} for attack_id, count in mapped.items()
    ]
    top_external_ids.sort(key=lambda item: (-int(str(item["rules"])), str(item["attack_id"])))
    return {
        "files": len(files),
        "parse_errors": parse_errors,
        "external_attack_ids": len(external_ids),
        "local_base_ids": len(local_ids),
        "overlap": len(overlap),
        "local_only": sorted(local_ids - external_ids)[:200],
        "external_only": sorted(external_ids - local_ids)[:200],
        "top_external_ids": top_external_ids[:50],
    }


@app.command()
def score(out: str = "") -> None:
    """Score the local Sigma rule corpus."""
    data = build_workbench()
    text = json.dumps(data, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


@app.command()
def compare(path: str) -> None:
    """Compare local ATT&CK coverage against another detection-rule directory."""
    typer.echo(json.dumps(compare_rule_directory(path), indent=2, sort_keys=True))


if __name__ == "__main__":
    app()
