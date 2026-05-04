"""Export one Sigma YAML rule per registered TTP.

Each TTP that defines `sigma_rule()` contributes a file to detection/sigma/.
A coverage index (coverage.json) summarizes which ATT&CK IDs have rules.
"""
from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

import ttps  # noqa: F401  (triggers registration)
from ttps.base import registry


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Sigma rule generation for registered TTPs."""


@app.command()
def export(out_dir: str = "detection/sigma") -> None:
    """Write one Sigma YAML per TTP and a coverage index."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    coverage: dict[str, dict[str, str]] = {}
    written = 0
    for attack_id, ttp in sorted(registry.all().items()):
        rule = ttp.sigma_rule()
        if rule is None:
            coverage[attack_id] = {"status": "no_rule", "name": ttp.name}
            continue
        slug = attack_id.lower().replace(".", "_")
        path = out / f"{slug}.yml"
        path.write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
        coverage[attack_id] = {
            "status": "exported",
            "name": ttp.name,
            "path": str(path).replace("\\", "/"),
            "level": rule.get("level", "informational"),
        }
        written += 1

    (out / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    typer.echo(f"Wrote {written} Sigma rule(s) to {out}/")
    typer.echo(f"Coverage index: {out}/coverage.json")


if __name__ == "__main__":
    app()
