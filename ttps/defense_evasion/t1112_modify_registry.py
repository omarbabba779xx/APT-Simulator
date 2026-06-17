"""T1112 — Modify Registry (simulation, Windows-only).

Writes a REG_DWORD value under HKCU\\Software\\AptSimulator\\Test\\Modify.
Mirrors the registry-write telemetry that real T1112 abuse generates without
touching real configuration keys. cleanup() removes the value.
"""
from __future__ import annotations

import platform
import time
from typing import Any, cast

from ..base import TTP, TTPResult, registry


SAFE_KEY_PATH = r"Software\AptSimulator\Test\Modify"
DEFAULT_VALUE_NAME = "AptSimDword"


class T1112ModifyRegistry(TTP):
    attack_id = "T1112"
    name = "Modify Registry (sim)"
    description = "Writes a REG_DWORD to an isolated test key"
    tactic = "defense_evasion"
    supported_platforms = ("windows",)

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(ok=False, error="windows-only TTP", started_at=started, finished_at=time.time())
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return TTPResult(ok=False, error="winreg unavailable", started_at=started, finished_at=time.time())
        winreg_api = cast(Any, winreg)
        value_name = str(params.get("value_name", DEFAULT_VALUE_NAME))
        value = int(params.get("value", 1))
        try:
            key = winreg_api.CreateKeyEx(winreg_api.HKEY_CURRENT_USER, SAFE_KEY_PATH, 0, winreg_api.KEY_SET_VALUE)
            winreg_api.SetValueEx(key, value_name, 0, winreg_api.REG_DWORD, value)
            winreg_api.CloseKey(key)
            return TTPResult(
                ok=True,
                output=f"set HKCU\\{SAFE_KEY_PATH}\\{value_name}={value}",
                artifacts=[f"HKCU\\{SAFE_KEY_PATH}\\{value_name}"],
                started_at=started,
                finished_at=time.time(),
            )
        except OSError as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if platform.system().lower() != "windows":
            return TTPResult(ok=True, output="not windows", started_at=started, finished_at=time.time())
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return TTPResult(ok=True, output="winreg unavailable", started_at=started, finished_at=time.time())
        winreg_api = cast(Any, winreg)
        value_name = str(params.get("value_name", DEFAULT_VALUE_NAME))
        try:
            key = winreg_api.OpenKey(winreg_api.HKEY_CURRENT_USER, SAFE_KEY_PATH, 0, winreg_api.KEY_SET_VALUE)
            try:
                winreg_api.DeleteValue(key, value_name)
            finally:
                winreg_api.CloseKey(key)
            return TTPResult(ok=True, output=f"removed HKCU\\{SAFE_KEY_PATH}\\{value_name}", started_at=started, finished_at=time.time())
        except FileNotFoundError:
            return TTPResult(ok=True, output="already gone", started_at=started, finished_at=time.time())
        except OSError as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Registry DWORD Write (APT Simulator T1112)",
            "id": "a1112000-0000-0000-0000-000000001112",
            "status": "experimental",
            "description": "Detects DWORD writes under the simulator test key.",
            "references": ["https://attack.mitre.org/techniques/T1112"],
            "tags": ["attack.defense_evasion", "attack.t1112"],
            "logsource": {"category": "registry_set", "product": "windows"},
            "detection": {
                "selection": {
                    "TargetObject|contains": ["\\Software\\AptSimulator\\Test\\Modify"],
                    "Type": "DWORD (0x00000004)",
                },
                "condition": "selection",
            },
            "falsepositives": ["Simulator self-test cleanup"],
            "level": "medium",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        value_name = params.get("value_name", DEFAULT_VALUE_NAME)
        return [
            {
                "category": "registry_set",
                "TargetObject": f"HKCU\\{SAFE_KEY_PATH}\\{value_name}",
                "Type": "DWORD (0x00000004)",
            }
        ]


registry.register(T1112ModifyRegistry())
