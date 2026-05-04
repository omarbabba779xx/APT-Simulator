"""Token issuance CLI.

Usage:
    python -m orchestrator.auth_cli issue --role admin --subject alice
    python -m orchestrator.auth_cli verify --token <token>
"""
from __future__ import annotations

import json
from pathlib import Path

import typer

from .core.auth import ROLES, decode_token, issue_token, load_or_generate_secret
from .core.config import load_config


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """JWT auth helper for APT Simulator orchestrator."""


@app.command()
def issue(
    role: str = typer.Option(..., "--role", help=f"one of {list(ROLES)}"),
    subject: str = typer.Option(..., "--subject", help="subject claim (e.g. user name)"),
    ttl_seconds: int = typer.Option(3600, "--ttl-seconds"),
    config: str = "config/default.yaml",
) -> None:
    cfg = load_config(config)
    secret = load_or_generate_secret(cfg.security.jwt_secret_path)
    token = issue_token(
        secret,
        role=role,
        subject=subject,
        ttl_seconds=ttl_seconds,
        algorithm=cfg.security.jwt_algorithm,
    )
    typer.echo(token)


@app.command()
def verify(
    token: str = typer.Option(..., "--token"),
    config: str = "config/default.yaml",
) -> None:
    cfg = load_config(config)
    secret_path = Path(cfg.security.jwt_secret_path)
    if not secret_path.exists():
        typer.echo(f"secret not found at {secret_path}", err=True)
        raise typer.Exit(code=1)
    secret = secret_path.read_bytes()
    try:
        claims = decode_token(token, secret, algorithm=cfg.security.jwt_algorithm)
    except Exception as exc:
        typer.echo(f"invalid: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(json.dumps(claims, indent=2))


if __name__ == "__main__":
    app()
