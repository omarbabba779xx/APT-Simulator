"""TTP execution runtime on the agent side.

Loads the registered TTP for an attack_id and runs it. If a payload signature
is supplied, verifies it against the orchestrator's public key.
"""
from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import ttps  # noqa: F401  (triggers TTP self-registration)
from orchestrator.core import signer as signer_mod
from ttps.base import TTPResult, registry


def load_public_key(pem_text: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("orchestrator key is not Ed25519")
    return key


def verify_task(task_dict: dict[str, Any], pub: Ed25519PublicKey | None) -> bool:
    sig = task_dict.pop("payload_signature", None)
    if pub is None:
        return sig is None
    if sig is None:
        return False
    canonical = json.dumps(task_dict, sort_keys=True, separators=(",", ":")).encode()
    return signer_mod.verify(canonical, sig, pub)


def execute(attack_id: str, params: dict[str, Any]) -> TTPResult:
    ttp = registry.get(attack_id)
    if ttp is None:
        return TTPResult(ok=False, error=f"unknown attack_id: {attack_id}")
    if not ttp.supports():
        return TTPResult(ok=False, error=f"TTP {attack_id} not supported on this platform")
    return ttp.run(params)
