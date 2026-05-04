"""T1053.005 — Scheduled Task/Job: Scheduled Task (simulation, Windows-only).

Real adversary technique: register a scheduled task that launches a payload on
a recurring schedule or at user logon, providing persistence across reboots.

Simulation: creates a scheduled task named ``AptSimulator_Test`` with
ExecStart pointing to ``cmd.exe /c rem apt-sim-marker`` (completely benign).
The task is created but NEVER enabled for execution. cleanup() deletes the
task immediately.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


TASK_NAME = "AptSimulator_Test"
SAFE_COMMAND = r"cmd.exe /c rem apt-sim-marker"


class T1053ScheduledTask(TTP):
    attack_id = "T1053.005"
    name = "Scheduled Task (sim)"
    description = "Creates a benign no-op scheduled task to generate T1053.005 telemetry"
    tactic = "persistence"
    supported_platforms = ("windows",)

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(ok=False, error="windows-only TTP", started_at=started, finished_at=time.time())

        task_name = str(params.get("task_name", TASK_NAME))
        trigger = str(params.get("trigger", "ONLOGON"))

        argv = [
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", SAFE_COMMAND,
            "/sc", trigger,
            "/f",  # force-overwrite if exists
        ]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
                check=False,
            )
            ok = proc.returncode == 0
            return TTPResult(
                ok=ok,
                output=proc.stdout[:2000] or f"created task '{task_name}' (trigger={trigger})",
                error=(proc.stderr[:1000] or None) if not ok else None,
                artifacts=[task_name],
                started_at=started,
                finished_at=time.time(),
                extra={"task_name": task_name, "trigger": trigger},
            )
        except subprocess.TimeoutExpired:
            return TTPResult(ok=False, error="timeout", started_at=started, finished_at=time.time())
        except FileNotFoundError as exc:
            return TTPResult(ok=False, error=f"schtasks not found: {exc}", started_at=started, finished_at=time.time())

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(ok=True, output="not windows; nothing to clean", started_at=started, finished_at=time.time())
        task_name = str(params.get("task_name", TASK_NAME))
        try:
            proc = subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
                check=False,
            )
            return TTPResult(
                ok=proc.returncode == 0,
                output=f"deleted scheduled task '{task_name}'",
                started_at=started,
                finished_at=time.time(),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Scheduled Task Creation via schtasks (APT Simulator T1053.005)",
            "id": "a1053005-0000-0000-0000-000000001053",
            "status": "experimental",
            "description": "Detects schtasks /create — the primary Windows mechanism for scheduling persistent payload execution.",
            "references": ["https://attack.mitre.org/techniques/T1053/005"],
            "tags": ["attack.persistence", "attack.t1053.005"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "Image|endswith": ["\\schtasks.exe"],
                    "CommandLine|contains": ["/create"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Software installers", "IT automation scripts"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        task_name = params.get("task_name", TASK_NAME)
        return [
            {
                "category": "process_creation",
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": f'schtasks /create /tn "{task_name}" /tr "{SAFE_COMMAND}" /sc ONLOGON /f',
            }
        ]


registry.register(T1053ScheduledTask())
