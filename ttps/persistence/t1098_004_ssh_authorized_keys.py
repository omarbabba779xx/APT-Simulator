"""T1098.004 — Account Manipulation: SSH Authorized Keys (sim, Linux/macOS).

Real adversary technique: append attacker public key to
``~/.ssh/authorized_keys`` so they can SSH back in.

Simulation: writes a marker line to a SEPARATE file at
``~/.ssh/apt_sim_test_authorized_keys`` (NEVER the real one). Generates the
file-creation telemetry in the .ssh directory that detection rules look for,
without granting any actual remote access. cleanup() removes the marker.
"""
from __future__ import annotations

import os
import platform
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


SAFE_FILENAME = "apt_sim_test_authorized_keys"
MARKER_LINE = (
    "# apt-simulator marker (NOT a real key): "
    "ssh-rsa AAAAB3SimulatorMarkerNotAValidKeyJustForDetectionTesting apt-sim@lab\n"
)


def _ssh_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".ssh"


class T1098SshAuthorizedKeys(TTP):
    attack_id = "T1098.004"
    name = "SSH Authorized Keys (sim)"
    description = "Writes a marker line to ~/.ssh/apt_sim_test_authorized_keys (NOT the real authorized_keys)"
    tactic = "persistence"
    supported_platforms = ("linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() not in {"linux", "darwin"}:
            return TTPResult(ok=False, error="linux/darwin only", started_at=started, finished_at=time.time())

        ssh = _ssh_dir()
        ssh.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = ssh / SAFE_FILENAME

        try:
            with marker.open("a", encoding="utf-8") as f:
                f.write(MARKER_LINE)
            try:
                os.chmod(marker, 0o600)
            except OSError:
                pass
        except OSError as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

        return TTPResult(
            ok=True,
            output=f"appended marker to {marker}",
            artifacts=[str(marker)],
            started_at=started,
            finished_at=time.time(),
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        marker = _ssh_dir() / SAFE_FILENAME
        if marker.exists():
            marker.unlink()
            return TTPResult(ok=True, output=f"removed {marker}", started_at=started, finished_at=time.time())
        return TTPResult(ok=True, output="already absent", started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Authorized Keys File Modification (APT Simulator T1098.004)",
            "id": "a1098004-0000-0000-0000-000000001098",
            "status": "experimental",
            "description": "Detects writes to authorized_keys files in any user's ~/.ssh directory.",
            "references": ["https://attack.mitre.org/techniques/T1098/004"],
            "tags": ["attack.persistence", "attack.t1098.004"],
            "logsource": {"category": "file_event", "product": "linux"},
            "detection": {
                "selection_real": {
                    "TargetFilename|contains": ["/.ssh/authorized_keys"],
                },
                "selection_sim": {
                    "TargetFilename|contains": ["/.ssh/apt_sim_test_authorized_keys"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Configuration management tools"],
            "level": "high",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        if result and result.artifacts:
            path = result.artifacts[0]
        else:
            # Use POSIX-style path for rule matching; this TTP is Linux/macOS-only.
            path = f"/home/testuser/.ssh/{SAFE_FILENAME}"
        return [{"category": "file_event", "TargetFilename": path}]


registry.register(T1098SshAuthorizedKeys())
