"""T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys (simulation).

Windows-only. Writes a marker value under
  HKCU\\Software\\AptSimulator\\Test\\Run
pointing to a benign no-op script path. NEVER touches real Run keys
(HKCU\\...CurrentVersion\\Run). cleanup() removes the marker.

The point: produce the registry-write telemetry that real T1547.001 emits, so
detection rules can be validated, without granting the simulator persistence on
the host.
"""
from __future__ import annotations

import platform
import time
from typing import Any, cast

from ..base import TTP, TTPResult, registry


SAFE_KEY_PATH = r"Software\AptSimulator\Test\Run"
DEFAULT_VALUE_NAME = "AptSimMarker"


class T1547RegistryRunKey(TTP):
    attack_id = "T1547.001"
    name = "Registry Run Keys (sim)"
    description = "Simulates Run-key persistence by writing to an isolated test key"
    tactic = "persistence"
    supported_platforms = ("windows",)

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(
                ok=False,
                error="windows-only TTP",
                started_at=started,
                finished_at=time.time(),
            )
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return TTPResult(
                ok=False,
                error="winreg unavailable",
                started_at=started,
                finished_at=time.time(),
            )
        winreg_api = cast(Any, winreg)
        value_name = str(params.get("value_name", DEFAULT_VALUE_NAME))
        value_data = str(params.get("value_data", "C:\\Windows\\System32\\cmd.exe /c rem apt-sim-marker"))
        try:
            key = winreg_api.CreateKeyEx(winreg_api.HKEY_CURRENT_USER, SAFE_KEY_PATH, 0, winreg_api.KEY_SET_VALUE)
            winreg_api.SetValueEx(key, value_name, 0, winreg_api.REG_SZ, value_data)
            winreg_api.CloseKey(key)
            return TTPResult(
                ok=True,
                output=f"wrote HKCU\\{SAFE_KEY_PATH}\\{value_name}",
                artifacts=[f"HKCU\\{SAFE_KEY_PATH}\\{value_name}"],
                started_at=started,
                finished_at=time.time(),
                extra={"key": SAFE_KEY_PATH, "value_name": value_name},
            )
        except OSError as exc:
            return TTPResult(
                ok=False, error=str(exc), started_at=started, finished_at=time.time()
            )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(ok=True, output="not windows; nothing to clean", started_at=started, finished_at=time.time())
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return TTPResult(ok=True, output="winreg unavailable; skip", started_at=started, finished_at=time.time())
        winreg_api = cast(Any, winreg)
        value_name = str(params.get("value_name", DEFAULT_VALUE_NAME))
        try:
            key = winreg_api.OpenKey(winreg_api.HKEY_CURRENT_USER, SAFE_KEY_PATH, 0, winreg_api.KEY_SET_VALUE)
            try:
                winreg_api.DeleteValue(key, value_name)
            finally:
                winreg_api.CloseKey(key)
            return TTPResult(
                ok=True,
                output=f"removed HKCU\\{SAFE_KEY_PATH}\\{value_name}",
                started_at=started,
                finished_at=time.time(),
            )
        except FileNotFoundError:
            return TTPResult(ok=True, output="already gone", started_at=started, finished_at=time.time())
        except OSError as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())


    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Registry Run Key Modification (APT Simulator T1547.001)",
            "id": "a1547001-0000-0000-0000-000000001547",
            "status": "experimental",
            "description": "Detects writes under Software\\AptSimulator\\Test\\Run (simulator test key) and to real Run keys.",
            "references": ["https://attack.mitre.org/techniques/T1547/001"],
            "tags": ["attack.persistence", "attack.t1547.001"],
            "logsource": {"category": "registry_set", "product": "windows"},
            "detection": {
                "selection_real": {
                    "TargetObject|contains": [
                        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    ],
                },
                "selection_sim": {
                    "TargetObject|contains": ["\\Software\\AptSimulator\\Test\\Run"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Legitimate installers"],
            "level": "high",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        value_name = params.get("value_name", DEFAULT_VALUE_NAME)
        return [
            {
                "category": "registry_set",
                "TargetObject": f"HKCU\\{SAFE_KEY_PATH}\\{value_name}",
            }
        ]


registry.register(T1547RegistryRunKey())
