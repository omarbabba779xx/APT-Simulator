"""Structural validation of the Helm chart files."""
from __future__ import annotations

from pathlib import Path

import yaml


CHART_DIR = Path(__file__).resolve().parent.parent / "helm" / "apt-simulator"


def test_chart_yaml_present_and_valid() -> None:
    p = CHART_DIR / "Chart.yaml"
    assert p.exists()
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert cfg["apiVersion"] == "v2"
    assert cfg["name"] == "apt-simulator"
    assert "version" in cfg


def test_values_yaml_has_expected_top_level_keys() -> None:
    p = CHART_DIR / "values.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert {"orchestrator", "agent", "auth", "networkPolicy"} <= set(cfg.keys())
    assert cfg["orchestrator"]["service"]["port"] == 8765


def test_required_templates_exist() -> None:
    templates = CHART_DIR / "templates"
    expected = {
        "_helpers.tpl",
        "orchestrator-deployment.yaml",
        "orchestrator-service.yaml",
        "orchestrator-pvc.yaml",
        "agent-daemonset.yaml",
        "networkpolicy.yaml",
    }
    have = {p.name for p in templates.glob("*")}
    missing = expected - have
    assert not missing, f"missing helm templates: {missing}"


def test_orchestrator_deployment_pins_nonroot() -> None:
    body = (CHART_DIR / "templates" / "orchestrator-deployment.yaml").read_text(encoding="utf-8")
    assert "runAsNonRoot: true" in body
    assert "runAsUser: 10001" in body
    assert "/healthz" in body


def test_agent_daemonset_uses_label_override() -> None:
    body = (CHART_DIR / "templates" / "agent-daemonset.yaml").read_text(encoding="utf-8")
    assert "APT_SIM_LAB_OVERRIDE" in body
    assert "DaemonSet" in body


def test_networkpolicy_restricts_ingress() -> None:
    body = (CHART_DIR / "templates" / "networkpolicy.yaml").read_text(encoding="utf-8")
    assert "kind: NetworkPolicy" in body
    assert "policyTypes:" in body
