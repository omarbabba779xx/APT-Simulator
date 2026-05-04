"""T1543.002 — Create or Modify System Process: Systemd Service (sim, Linux).

Real adversary technique: drop a systemd unit so the malicious process is
respawned across logins/reboots.

Simulation: writes ``~/.config/systemd/user/apt-sim-test.service`` with an
ExecStart pointing to ``/bin/true`` (no-op). NEVER enables, NEVER calls
``systemctl daemon-reload`` — purely a file artifact. cleanup() removes the
unit file.
"""
from __future__ import annotations

import os
import platform
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


UNIT_NAME = "apt-sim-test.service"
UNIT_BODY = (
    "[Unit]\n"
    "Description=APT Simulator marker unit (NOT a real service)\n"
    "\n"
    "[Service]\n"
    "Type=oneshot\n"
    "ExecStart=/bin/true\n"
    "\n"
    "[Install]\n"
    "WantedBy=default.target\n"
)


def _user_systemd_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".config" / "systemd" / "user"


class T1543SystemdService(TTP):
    attack_id = "T1543.002"
    name = "Systemd User Service (sim)"
    description = "Drops a benign systemd user unit file (no enable, no daemon-reload)"
    tactic = "persistence"
    supported_platforms = ("linux",)

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "linux":
            return TTPResult(ok=False, error="linux-only TTP", started_at=started, finished_at=time.time())

        d = _user_systemd_dir()
        d.mkdir(parents=True, exist_ok=True)
        path = d / UNIT_NAME
        try:
            path.write_text(UNIT_BODY, encoding="utf-8")
        except OSError as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

        return TTPResult(
            ok=True,
            output=f"wrote {path}",
            artifacts=[str(path)],
            started_at=started,
            finished_at=time.time(),
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        path = _user_systemd_dir() / UNIT_NAME
        if path.exists():
            path.unlink()
            return TTPResult(ok=True, output=f"removed {path}", started_at=started, finished_at=time.time())
        return TTPResult(ok=True, output="already absent", started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Systemd User Unit File Created (APT Simulator T1543.002)",
            "id": "a1543002-0000-0000-0000-000000001543",
            "status": "experimental",
            "description": "Detects creation of user-scope systemd .service files.",
            "references": ["https://attack.mitre.org/techniques/T1543/002"],
            "tags": ["attack.persistence", "attack.t1543.002"],
            "logsource": {"category": "file_event", "product": "linux"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": ["/.config/systemd/user/"],
                    "TargetFilename|endswith": [".service"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Legitimate user-installed services"],
            "level": "medium",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        if result and result.artifacts:
            path = result.artifacts[0]
        else:
            # Use POSIX-style path for rule matching; this TTP is Linux-only.
            path = f"/home/testuser/.config/systemd/user/{UNIT_NAME}"
        return [{"category": "file_event", "TargetFilename": path}]


registry.register(T1543SystemdService())
