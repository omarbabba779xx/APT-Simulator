"""T1003 — OS Credential Dumping (TARGET ENUMERATION ONLY, no memory access).

Strict simulation: lists which credential-storage processes are running on the
host (lsass.exe, ssh-agent, gnome-keyring, Keychain Access). NEVER reads memory,
NEVER calls MiniDumpWriteDump, NEVER opens those processes with PROCESS_VM_READ.

The defensive value: a process that even *enumerates* lsass and similar targets
should be auditable. Real T1003 implementations follow this exact recon step
before the dump itself.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


WINDOWS_TARGETS = {"lsass.exe", "winlogon.exe", "vaultsvc.exe", "lsaiso.exe"}
LINUX_TARGETS = {"ssh-agent", "gnome-keyring-d", "polkitd", "sssd"}
DARWIN_TARGETS = {"securityd", "Keychain Access", "loginwindow"}


def _running_processes() -> list[str]:
    if platform.system().lower() == "windows":
        out = subprocess.run(["tasklist"], capture_output=True, text=True, check=False, timeout=60)
        return [line.split()[0] for line in out.stdout.splitlines() if line and line[0].isalpha()]
    out = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True, check=False, timeout=60)
    return [line.strip() for line in out.stdout.splitlines()[1:] if line.strip()]


class T1003CredentialTargetEnum(TTP):
    attack_id = "T1003"
    name = "Credential Storage Target Enumeration (sim)"
    description = "Enumerates which credential-store processes are running. Read-only — never accesses memory."
    tactic = "credential_access"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        plat = platform.system().lower()
        if plat == "windows":
            targets = WINDOWS_TARGETS
        elif plat == "darwin":
            targets = DARWIN_TARGETS
        else:
            targets = LINUX_TARGETS
        try:
            procs = _running_processes()
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

        found = sorted({p for p in procs if any(t.lower() in p.lower() for t in targets)})
        return TTPResult(
            ok=True,
            output=f"identified {len(found)} credential-store target(s): {', '.join(found) or 'none'}",
            artifacts=found,
            started_at=started,
            finished_at=time.time(),
            extra={"platform": plat, "candidates": list(targets)},
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Credential Storage Process Enumeration (APT Simulator T1003)",
            "id": "a1003000-0000-0000-0000-000000001003",
            "status": "experimental",
            "description": "Detects process listing followed by reference to lsass/ssh-agent/keychain — a recon precursor to credential dumping.",
            "references": ["https://attack.mitre.org/techniques/T1003"],
            "tags": ["attack.credential_access", "attack.t1003"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "CommandLine|contains": ["lsass", "vaultsvc"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["ssh-agent", "gnome-keyring", "securityd"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["EDR / monitoring agents"],
            "level": "high",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        return [
            {"category": "process_creation", "CommandLine": "tasklist | findstr lsass"},
            {"category": "process_creation", "CommandLine": "ps -ef | grep ssh-agent"},
        ]


registry.register(T1003CredentialTargetEnum())
