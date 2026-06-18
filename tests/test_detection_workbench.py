from __future__ import annotations

from orchestrator.detection_workbench import analyze_rule, build_workbench


def test_analyze_rule_reports_missing_fields_and_risk() -> None:
    result = analyze_rule({"title": "partial", "logsource": {}, "detection": {"condition": "selection"}})
    assert result["false_positive_risk"] == "high"
    assert "id" in result["missing_fields"]
    assert "tags" in result["missing_fields"]
    assert result["quality_score"] < 100


def test_workbench_scores_full_local_rule_set() -> None:
    workbench = build_workbench(limit_items=5)
    assert workbench["total_rules"] == 5064
    assert workbench["average_quality_score"] > 0
    assert len(workbench["items"]) == 5
    assert set(workbench["targets"]) == {"splunk", "elastic", "sentinel", "chronicle"}
