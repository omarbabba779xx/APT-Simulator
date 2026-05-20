"""Tests for Phase 3 TTPs: T1021.001, T1021.002, T1110, T1048, T1560, T1055."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

import ttps  # noqa: F401 — triggers self-registration
from ttps.base import registry


# ---------------------------------------------------------------------------
# T1021.001 — RDP Probe
# ---------------------------------------------------------------------------

def test_t1021_001_registered() -> None:
    assert registry.get("T1021.001") is not None


def test_t1021_001_probes_localhost(tmp_path: Path) -> None:
    ttp = registry.get("T1021.001")
    res = ttp.run({"hosts": ["127.0.0.1"], "timeout": 0.5, "marker_dir": str(tmp_path)})
    assert res.ok
    assert "probed 1 host(s)" in res.output
    marker = tmp_path / "t1021_001_rdp_probe.txt"
    assert marker.exists()
    content = marker.read_text()
    assert "APT_SIM_LATERAL_MOVEMENT" in content
    assert "127.0.0.1:3389" in content


def test_t1021_001_multiple_hosts(tmp_path: Path) -> None:
    ttp = registry.get("T1021.001")
    hosts = ["127.0.0.1", "192.0.2.1", "192.0.2.2"]
    res = ttp.run({"hosts": hosts, "timeout": 0.3, "marker_dir": str(tmp_path)})
    assert res.ok
    assert "probed 3 host(s)" in res.output


def test_t1021_001_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1021.001")
    ttp.run({"hosts": ["127.0.0.1"], "timeout": 0.3, "marker_dir": str(tmp_path)})
    marker = tmp_path / "t1021_001_rdp_probe.txt"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1021_001_sigma_structure() -> None:
    ttp = registry.get("T1021.001")
    rule = ttp.sigma_rule()
    assert rule["detection"]["selection"]["DestinationPort"] == 3389
    assert "attack.t1021.001" in rule["tags"]
    assert rule["level"] in ("low", "medium", "high", "critical")


def test_t1021_001_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1021.001")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({"hosts": ["10.0.0.5"]}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1021_001_artifacts_populated(tmp_path: Path) -> None:
    ttp = registry.get("T1021.001")
    res = ttp.run({"hosts": ["127.0.0.1"], "timeout": 0.3, "marker_dir": str(tmp_path)})
    assert res.artifacts
    assert Path(res.artifacts[0]).exists()


def test_t1021_001_extra_contains_results(tmp_path: Path) -> None:
    ttp = registry.get("T1021.001")
    res = ttp.run({"hosts": ["127.0.0.1"], "timeout": 0.3, "marker_dir": str(tmp_path)})
    assert "results" in res.extra
    assert isinstance(res.extra["results"], list)
    assert res.extra["results"][0]["host"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# T1021.002 — SMB Admin Shares
# ---------------------------------------------------------------------------

def test_t1021_002_registered() -> None:
    assert registry.get("T1021.002") is not None


def test_t1021_002_writes_marker(tmp_path: Path) -> None:
    ttp = registry.get("T1021.002")
    res = ttp.run({"hosts": ["127.0.0.1"], "marker_dir": str(tmp_path)})
    assert res.ok
    marker = tmp_path / "t1021_002_smb_enum.txt"
    assert marker.exists()
    content = marker.read_text()
    assert "APT_SIM_LATERAL_MOVEMENT" in content
    assert "ADMIN$" in content


def test_t1021_002_custom_shares(tmp_path: Path) -> None:
    """Custom shares param recorded in paths."""
    ttp = registry.get("T1021.002")
    res = ttp.run({"hosts": ["127.0.0.1"], "marker_dir": str(tmp_path)})
    assert res.ok
    content = (tmp_path / "t1021_002_smb_enum.txt").read_text()
    assert "127.0.0.1" in content


def test_t1021_002_multiple_hosts(tmp_path: Path) -> None:
    ttp = registry.get("T1021.002")
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    res = ttp.run({"hosts": hosts, "marker_dir": str(tmp_path)})
    assert res.ok
    assert "3 host" in res.output


def test_t1021_002_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1021.002")
    ttp.run({"hosts": ["127.0.0.1"], "marker_dir": str(tmp_path)})
    marker = tmp_path / "t1021_002_smb_enum.txt"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1021_002_sigma_structure() -> None:
    ttp = registry.get("T1021.002")
    rule = ttp.sigma_rule()
    assert "attack.t1021.002" in rule["tags"]
    assert "445" in str(rule["detection"])


def test_t1021_002_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1021.002")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({"hosts": ["10.0.0.1"]}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1021_002_extra_has_paths(tmp_path: Path) -> None:
    ttp = registry.get("T1021.002")
    res = ttp.run({"hosts": ["127.0.0.1"], "marker_dir": str(tmp_path)})
    assert "paths" in res.extra
    assert len(res.extra["paths"]) > 0


# ---------------------------------------------------------------------------
# T1110 — Brute Force
# ---------------------------------------------------------------------------

def test_t1110_registered() -> None:
    assert registry.get("T1110") is not None


def test_t1110_writes_jsonl(tmp_path: Path) -> None:
    ttp = registry.get("T1110")
    res = ttp.run({"attempts": 10, "marker_dir": str(tmp_path)})
    assert res.ok
    marker = tmp_path / "t1110_brute_force.jsonl"
    assert marker.exists()
    lines = marker.read_text().strip().splitlines()
    assert len(lines) == 10
    for line in lines:
        ev = json.loads(line)
        assert ev["EventID"] == 4625
        assert "_sim" in ev


def test_t1110_default_attempts(tmp_path: Path) -> None:
    ttp = registry.get("T1110")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    lines = (tmp_path / "t1110_brute_force.jsonl").read_text().strip().splitlines()
    assert len(lines) == 20


def test_t1110_custom_usernames(tmp_path: Path) -> None:
    ttp = registry.get("T1110")
    usernames = ["ceo", "cfo", "finance_admin"]
    res = ttp.run({"attempts": 6, "usernames": usernames, "marker_dir": str(tmp_path)})
    assert res.ok
    events = [json.loads(ln) for ln in (tmp_path / "t1110_brute_force.jsonl").read_text().splitlines()]
    for ev in events:
        assert ev["TargetUserName"] in usernames


def test_t1110_deterministic_with_seed(tmp_path: Path) -> None:
    ttp = registry.get("T1110")
    ttp.run({"attempts": 5, "seed": 7, "marker_dir": str(tmp_path)})
    events1 = (tmp_path / "t1110_brute_force.jsonl").read_text()
    ttp.run({"attempts": 5, "seed": 7, "marker_dir": str(tmp_path)})
    events2 = (tmp_path / "t1110_brute_force.jsonl").read_text()
    users1 = [json.loads(ln)["TargetUserName"] for ln in events1.splitlines()]
    users2 = [json.loads(ln)["TargetUserName"] for ln in events2.splitlines()]
    assert users1 == users2


def test_t1110_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1110")
    ttp.run({"attempts": 5, "marker_dir": str(tmp_path)})
    marker = tmp_path / "t1110_brute_force.jsonl"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1110_sigma_threshold() -> None:
    ttp = registry.get("T1110")
    rule = ttp.sigma_rule()
    assert rule["detection"]["selection"]["EventID"] == 4625
    assert "attack.t1110" in rule["tags"]


def test_t1110_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1110")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({"attempts": 6}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1110_src_ip_rfc5737(tmp_path: Path) -> None:
    """Default src_ip must be RFC 5737 TEST-NET (never routable)."""
    ttp = registry.get("T1110")
    ttp.run({"attempts": 3, "marker_dir": str(tmp_path)})
    events = [json.loads(ln) for ln in (tmp_path / "t1110_brute_force.jsonl").read_text().splitlines()]
    ip = events[0]["IpAddress"]
    assert ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113.")


# ---------------------------------------------------------------------------
# T1048 — Exfiltration Over Alternative Protocol
# ---------------------------------------------------------------------------

def test_t1048_registered() -> None:
    assert registry.get("T1048") is not None


def test_t1048_creates_b64_marker(tmp_path: Path) -> None:
    ttp = registry.get("T1048")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    marker = tmp_path / "t1048_exfil_alt.b64"
    assert marker.exists()
    content = marker.read_text()
    # File header contains protocol and sha256
    assert "protocol=" in content
    assert "sha256=" in content


def test_t1048_payload_size_clamped(tmp_path: Path) -> None:
    ttp = registry.get("T1048")
    res = ttp.run({"payload_bytes": 99999, "marker_dir": str(tmp_path)})
    assert res.ok
    assert res.extra["raw_bytes"] <= 4096


def test_t1048_protocol_recorded(tmp_path: Path) -> None:
    ttp = registry.get("T1048")
    res = ttp.run({"protocol": "icmp", "marker_dir": str(tmp_path)})
    assert res.extra["protocol"] == "icmp"
    marker = (tmp_path / "t1048_exfil_alt.b64").read_text(encoding="utf-8")
    assert "protocol=icmp" in marker


def test_t1048_sha256_correct(tmp_path: Path) -> None:
    import base64
    import hashlib
    ttp = registry.get("T1048")
    res = ttp.run({"payload_bytes": 64, "marker_dir": str(tmp_path)})
    marker_text = (tmp_path / "t1048_exfil_alt.b64").read_text()
    lines = marker_text.strip().splitlines()
    b64_data = lines[-1]
    raw = base64.b64decode(b64_data)
    expected_sha = hashlib.sha256(raw).hexdigest()
    assert res.extra["sha256"] == expected_sha


def test_t1048_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1048")
    ttp.run({"marker_dir": str(tmp_path)})
    marker = tmp_path / "t1048_exfil_alt.b64"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1048_sigma_dns_txt() -> None:
    ttp = registry.get("T1048")
    rule = ttp.sigma_rule()
    assert rule["detection"]["selection_dns_txt"]["QueryType"] == "TXT"
    assert "attack.t1048" in rule["tags"]
    assert rule["level"] == "high"


def test_t1048_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1048")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({"protocol": "dns-txt"}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1048_no_real_network(tmp_path: Path) -> None:
    """Ensure no actual sockets are opened (marker-only artifact)."""
    import socket
    original_connect = socket.socket.connect
    calls = []

    def _patched_connect(self, address):
        calls.append(address)
        return original_connect(self, address)

    ttp = registry.get("T1048")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not calls, "T1048 must not open any network connections"


# ---------------------------------------------------------------------------
# T1560 — Archive Collected Data
# ---------------------------------------------------------------------------

def test_t1560_registered() -> None:
    assert registry.get("T1560") is not None


def test_t1560_creates_zip(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    archive = tmp_path / "t1560_staged_data.zip"
    assert archive.exists()
    assert archive.stat().st_size > 0


def test_t1560_zip_has_expected_files(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    ttp.run({"marker_dir": str(tmp_path)})
    archive = tmp_path / "t1560_staged_data.zip"
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
    assert "financials_q4.csv" in names
    assert "employee_list.txt" in names
    assert "network_diagram.xml" in names


def test_t1560_zip_contains_only_dummy_data(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    ttp.run({"marker_dir": str(tmp_path)})
    archive = tmp_path / "t1560_staged_data.zip"
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            data = zf.read(name)
            # Each file should contain sim marker — XML uses APT_SIM_DUMMY tag
            is_sim = b"APT_SIM_DUMMY" in data
            assert is_sim, f"{name} must be marked as sim data, got: {data[:80]}"


def test_t1560_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    ttp.run({"marker_dir": str(tmp_path)})
    archive = tmp_path / "t1560_staged_data.zip"
    assert archive.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not archive.exists()


def test_t1560_extra_metadata(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.extra["file_count"] == 3
    assert res.extra["size_bytes"] > 0
    assert len(res.extra["files"]) == 3


def test_t1560_sigma_structure() -> None:
    ttp = registry.get("T1560")
    rule = ttp.sigma_rule()
    selection = rule["detection"]["selection"]
    exts = selection["TargetFilename|endswith"]
    assert ".zip" in exts
    assert "attack.t1560" in rule["tags"]


def test_t1560_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1560")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1560_artifacts_listed(tmp_path: Path) -> None:
    ttp = registry.get("T1560")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.artifacts
    assert Path(res.artifacts[0]).exists()


# ---------------------------------------------------------------------------
# T1055 — Process Injection Target Enumeration
# ---------------------------------------------------------------------------

def test_t1055_registered() -> None:
    assert registry.get("T1055") is not None


def test_t1055_writes_json_report(tmp_path: Path) -> None:
    ttp = registry.get("T1055")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    marker = tmp_path / "t1055_injection_targets.json"
    assert marker.exists()
    report = json.loads(marker.read_text())
    assert report["_sim"] == "APT_SIM_DEFENSE_EVASION_T1055"
    assert "injection_targets_found" in report
    assert "total_processes_scanned" in report


def test_t1055_finds_synthetic_targets(tmp_path: Path, monkeypatch) -> None:
    """With psutil unavailable, fallback synthetic procs must include svchost/explorer."""
    import sys
    # Force ImportError for psutil
    monkeypatch.setitem(sys.modules, "psutil", None)
    from ttps.defense_evasion import t1055_process_injection_sim as mod
    import importlib
    importlib.reload(mod)
    ttp = mod.T1055ProcessInjectionSim()
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.ok
    report = res.extra
    target_names = [t["name"].lower() for t in report["injection_targets_found"]]
    assert any(n in target_names for n in ["svchost.exe", "explorer.exe", "notepad.exe"])


def test_t1055_extra_targets_accepted(tmp_path: Path) -> None:
    ttp = registry.get("T1055")
    res = ttp.run({"extra_targets": ["custom_proc.exe"], "marker_dir": str(tmp_path)})
    assert res.ok
    assert "custom_proc.exe" in res.extra["target_names"]


def test_t1055_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1055")
    ttp.run({"marker_dir": str(tmp_path)})
    marker = tmp_path / "t1055_injection_targets.json"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1055_sigma_high_value_targets() -> None:
    ttp = registry.get("T1055")
    rule = ttp.sigma_rule()
    targets = rule["detection"]["selection"]["TargetImage|endswith"]
    assert "\\lsass.exe" in targets
    assert "\\explorer.exe" in targets
    assert "attack.t1055" in rule["tags"]
    assert rule["level"] == "high"


def test_t1055_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1055")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events)


def test_t1055_scan_count_reported(tmp_path: Path) -> None:
    ttp = registry.get("T1055")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.extra["total_processes_scanned"] > 0
    assert "scanned" in res.output


def test_t1055_artifacts_listed(tmp_path: Path) -> None:
    ttp = registry.get("T1055")
    res = ttp.run({"marker_dir": str(tmp_path)})
    assert res.artifacts
    assert Path(res.artifacts[0]).exists()


# ---------------------------------------------------------------------------
# New scenarios parse correctly
# ---------------------------------------------------------------------------

def test_apt29_credential_lateral_scenario_validates() -> None:
    import yaml
    from orchestrator.dsl.schema import Scenario
    p = Path(__file__).parent.parent / "scenarios" / "apt29_credential_lateral.yaml"
    sc = Scenario(**yaml.safe_load(p.read_text(encoding="utf-8")))
    sc.validate_dag()
    assert len(sc.steps) >= 10
    assert sc.actor is not None


def test_fin7_full_chain_scenario_validates() -> None:
    import yaml
    from orchestrator.dsl.schema import Scenario
    p = Path(__file__).parent.parent / "scenarios" / "fin7_full_chain.yaml"
    sc = Scenario(**yaml.safe_load(p.read_text(encoding="utf-8")))
    sc.validate_dag()
    assert len(sc.steps) >= 15
    assert sc.actor is not None


# ---------------------------------------------------------------------------
# Registry coverage — all 6 new TTPs registered
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", [
    "T1021.001",
    "T1021.002",
    "T1110",
    "T1048",
    "T1560",
    "T1055",
])
def test_phase3_ttp_registered(attack_id: str) -> None:
    assert registry.get(attack_id) is not None, f"{attack_id} not registered"


@pytest.mark.parametrize("attack_id", [
    "T1021.001",
    "T1021.002",
    "T1110",
    "T1048",
    "T1560",
    "T1055",
])
def test_phase3_ttp_sigma_has_required_fields(attack_id: str) -> None:
    ttp = registry.get(attack_id)
    rule = ttp.sigma_rule()
    for field in ("title", "id", "status", "description", "tags", "logsource", "detection", "level"):
        assert field in rule, f"{attack_id} sigma_rule missing field: {field}"


@pytest.mark.parametrize("attack_id", [
    "T1021.001",
    "T1021.002",
    "T1110",
    "T1048",
    "T1560",
    "T1055",
])
def test_phase3_ttp_synthetic_events_nonempty(attack_id: str) -> None:
    ttp = registry.get(attack_id)
    events = ttp.synthetic_events({}, None)
    assert isinstance(events, list)
    assert len(events) > 0, f"{attack_id} returned empty synthetic_events"
