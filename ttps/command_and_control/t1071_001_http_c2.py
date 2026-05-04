"""T1071.001 — Application Layer Protocol: Web Protocols (HTTP C2 simulation).

Simulates beaconing traffic to a configured C2 URL with adversary-realistic
patterns:

  - jitter_mode: uniform | exponential | normal — controls delay distribution
  - sleep_window: optional [start_hour, end_hour] (24h, local time) — beacon
    only inside the window, idle outside
  - profile: default | stealth | noisy — selects User-Agent pool

The URL MUST point at a lab loopback or private network address; production
hosts are rejected before any traffic is sent.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from ..base import TTP, TTPResult, registry


SAFE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

UA_PROFILES: dict[str, list[str]] = {
    "default": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/8.0.1",
        "python-requests/2.31",
        "Go-http-client/2.0",
    ],
    "stealth": [
        # Browser-only — blends into normal traffic.
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/124.0",
    ],
    "noisy": [
        # Tooling-flavored — easier for SIEM to flag.
        "curl/8.0.1",
        "python-requests/2.31",
        "PowerShell/7.4",
        "Wget/1.21",
        "axios/1.6",
    ],
}


def _is_lab_target(url: str) -> bool:
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
        except (socket.gaierror, ValueError):
            return False
    return any(ip in net for net in SAFE_NETS)


def _jittered_delay(base: float, jitter: float, mode: str, attempt: int) -> float:
    if jitter <= 0:
        return base
    if mode == "exponential":
        return base + random.expovariate(1.0 / max(jitter, 1e-6))
    if mode == "normal":
        return max(0.0, base + random.gauss(0, jitter / 2))
    # uniform default
    return base + random.uniform(0, jitter)


def _within_window(window: list[int] | tuple[int, int] | None) -> bool:
    if not window or len(window) != 2:
        return True
    start, end = int(window[0]), int(window[1])
    hour = datetime.now().hour
    if start <= end:
        return start <= hour < end
    # wraps midnight
    return hour >= start or hour < end


class T1071HttpC2(TTP):
    attack_id = "T1071.001"
    name = "HTTP C2 Beaconing (sim)"
    description = "Beacon to lab loopback URL with configurable jitter modes, sleep windows, and UA profiles"
    tactic = "command_and_control"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        url = str(params.get("url", "http://127.0.0.1:8765/healthz"))
        beacons = int(params.get("beacons", 5))
        interval = float(params.get("interval_seconds", 1.0))
        jitter = float(params.get("jitter_seconds", 0.5))
        jitter_mode = str(params.get("jitter_mode", "uniform")).lower()
        timeout = float(params.get("request_timeout", 5.0))
        max_total_seconds = float(params.get("max_total_seconds", 30.0))
        profile = str(params.get("profile", "default")).lower()
        sleep_window = params.get("sleep_window")  # [start_hour, end_hour] or None

        if jitter_mode not in {"uniform", "exponential", "normal"}:
            return TTPResult(
                ok=False,
                error=f"unknown jitter_mode '{jitter_mode}'",
                started_at=started,
                finished_at=time.time(),
            )

        if profile not in UA_PROFILES:
            return TTPResult(
                ok=False,
                error=f"unknown profile '{profile}', expected one of {sorted(UA_PROFILES)}",
                started_at=started,
                finished_at=time.time(),
            )

        if not _is_lab_target(url):
            return TTPResult(
                ok=False,
                error=f"target {url} is not in lab CIDR allowlist",
                started_at=started,
                finished_at=time.time(),
            )

        if not _within_window(sleep_window):
            return TTPResult(
                ok=True,
                output=f"outside sleep_window {sleep_window}; no beacons sent",
                started_at=started,
                finished_at=time.time(),
                extra={"skipped": True, "window": sleep_window},
            )

        ua_pool = UA_PROFILES[profile]
        results: list[dict[str, Any]] = []
        deadline = started + max_total_seconds
        with httpx.Client(timeout=timeout) as client:
            for i in range(beacons):
                if time.time() > deadline:
                    break
                ua = random.choice(ua_pool)
                t0 = time.time()
                try:
                    resp = client.get(url, headers={"User-Agent": ua})
                    results.append(
                        {"i": i, "status": resp.status_code, "elapsed_ms": int((time.time() - t0) * 1000), "ua": ua}
                    )
                except httpx.HTTPError as exc:
                    results.append({"i": i, "error": str(exc)[:200]})
                if i + 1 < beacons:
                    time.sleep(_jittered_delay(interval, jitter, jitter_mode, i))

        ok_count = sum(1 for r in results if r.get("status", 0) == 200)
        return TTPResult(
            ok=ok_count > 0,
            output=f"sent {len(results)} beacons, {ok_count} ok (mode={jitter_mode}, profile={profile})",
            started_at=started,
            finished_at=time.time(),
            extra={"results": results, "url": url, "jitter_mode": jitter_mode, "profile": profile},
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Periodic HTTP Beaconing With Rotating User-Agent (APT Simulator T1071.001)",
            "id": "a1071001-0000-0000-0000-000000001071",
            "status": "experimental",
            "description": "Detects regular-interval HTTP requests from one process with varied User-Agent strings.",
            "references": ["https://attack.mitre.org/techniques/T1071/001"],
            "tags": ["attack.command_and_control", "attack.t1071.001"],
            "logsource": {"category": "proxy"},
            "detection": {
                "selection": {
                    "cs-method": "GET",
                    "cs-user-agent|contains|all": ["curl/", "python-requests/"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Monitoring agents", "API polling scripts"],
            "level": "medium",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        ua = "curl/8.0.1 python-requests/2.31"
        return [{"category": "proxy", "cs-method": "GET", "cs-user-agent": ua}]


registry.register(T1071HttpC2())
