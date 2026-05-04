from __future__ import annotations

from pathlib import Path

from orchestrator.core import signer


def test_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    signer.generate_keypair(priv, pub)
    privkey = signer.load_private(priv)
    pubkey = signer.load_public(pub)

    msg = b"test-payload"
    sig = signer.sign(msg, privkey)
    assert signer.verify(msg, sig, pubkey)
    assert not signer.verify(b"tampered", sig, pubkey)
