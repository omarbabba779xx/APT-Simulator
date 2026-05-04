"""Pre-flight safety checks. Agent must pass these before any TTP runs."""
from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Any

import yaml


def host_in_whitelist(whitelist_path: str | Path = "config/lab_whitelist.yaml") -> tuple[bool, str]:
    """Return (allowed, reason). Reason is empty when allowed.

    Env override APT_SIM_LAB_OVERRIDE=1 bypasses the whitelist for containerized
    lab use only; never set this on a host you do not own.
    """
    if os.environ.get("APT_SIM_LAB_OVERRIDE") == "1":
        return True, ""
    p = Path(whitelist_path)
    if not p.exists():
        return False, f"whitelist file missing: {whitelist_path}"
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if raw.get("allow_any"):
        return True, ""

    hostname = socket.gethostname().lower()
    matched_host = any(h.lower() in hostname for h in raw.get("hostnames", []))

    matched_ip = False
    try:
        local_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        local_ips = {"127.0.0.1"}
    for cidr in raw.get("cidrs", []):
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in local_ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    matched_ip = True
                    break
            except ValueError:
                continue
        if matched_ip:
            break

    if matched_host or matched_ip:
        return True, ""
    return False, f"host '{hostname}' / ips {local_ips} not in lab whitelist"


def killswitch_engaged(local_flag: str = "data/STOP") -> tuple[bool, str | None]:
    if os.environ.get("APT_SIM_STOP") == "1":
        return True, "env APT_SIM_STOP=1"
    if Path(local_flag).exists():
        return True, f"local flag {local_flag}"
    return False, None
