"""Ed25519 payload signer. Agents verify before executing TTP payloads."""
from __future__ import annotations

import base64
from pathlib import Path

import typer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair(priv_path: str | Path, pub_path: str | Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    Path(priv_path).parent.mkdir(parents=True, exist_ok=True)
    Path(priv_path).write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    Path(pub_path).write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private(priv_path: str | Path) -> Ed25519PrivateKey:
    data = Path(priv_path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return key


def load_public(pub_path: str | Path) -> Ed25519PublicKey:
    data = Path(pub_path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Expected Ed25519 public key")
    return key


def sign(message: bytes, priv: Ed25519PrivateKey) -> str:
    sig = priv.sign(message)
    return base64.b64encode(sig).decode("ascii")


def verify(message: bytes, signature_b64: str, pub: Ed25519PublicKey) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), message)
        return True
    except InvalidSignature:
        return False


# CLI entry: `python -m orchestrator.core.signer init`
app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Ed25519 signing key management."""


@app.command()
def init(
    priv: str = "keys/ed25519_private.pem",
    pub: str = "keys/ed25519_public.pem",
) -> None:
    """Generate a new Ed25519 keypair."""
    if Path(priv).exists() or Path(pub).exists():
        typer.echo("Keys already exist. Refusing to overwrite. Delete first if intentional.")
        raise typer.Exit(code=1)
    generate_keypair(priv, pub)
    typer.echo(f"Keypair generated:\n  private: {priv}\n  public:  {pub}")


if __name__ == "__main__":
    app()
