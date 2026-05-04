"""Transpile Sigma rules to SIEM-specific query languages.

Reads detection/sigma/*.yml and emits:

  detection/transpiled/splunk/<id>.spl     (Splunk SPL)
  detection/transpiled/elastic/<id>.lucene (Elastic Lucene)

Uses pysigma + pysigma-backend-splunk + pysigma-backend-elasticsearch.
Install with: pip install -e ".[transpile]"
"""
from __future__ import annotations

from pathlib import Path

import typer


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Transpile Sigma rules to Splunk SPL / Elastic Lucene."""


def _try_import_backends():
    try:
        from sigma.backends.elasticsearch import LuceneBackend  # type: ignore[import-not-found]
        from sigma.backends.splunk import SplunkBackend  # type: ignore[import-not-found]
        from sigma.collection import SigmaCollection  # type: ignore[import-not-found]
    except ImportError as exc:
        return None, None, None, exc
    return SigmaCollection, SplunkBackend, LuceneBackend, None


@app.command()
def transpile(
    sigma_dir: str = "detection/sigma",
    out_dir: str = "detection/transpiled",
) -> None:
    """Convert every Sigma YAML to Splunk SPL and Elastic Lucene."""
    SigmaCollection, SplunkBackend, LuceneBackend, err = _try_import_backends()
    if err is not None:
        typer.echo(
            f"transpile backends missing ({err}). Install with: pip install -e \".[transpile]\"",
            err=True,
        )
        raise typer.Exit(code=1)

    sigma_path = Path(sigma_dir)
    if not sigma_path.exists():
        typer.echo(f"sigma dir not found: {sigma_dir}", err=True)
        raise typer.Exit(code=1)

    splunk_out = Path(out_dir) / "splunk"
    elastic_out = Path(out_dir) / "elastic"
    splunk_out.mkdir(parents=True, exist_ok=True)
    elastic_out.mkdir(parents=True, exist_ok=True)

    splunk = SplunkBackend()
    lucene = LuceneBackend()

    converted = 0
    for yml in sorted(sigma_path.glob("*.yml")):
        try:
            rules = SigmaCollection.from_yaml(yml.read_text(encoding="utf-8"))
        except Exception as exc:
            typer.echo(f"  skip {yml.name}: parse failed ({exc})", err=True)
            continue
        slug = yml.stem

        try:
            spl = splunk.convert(rules)
            (splunk_out / f"{slug}.spl").write_text("\n\n".join(spl), encoding="utf-8")
        except Exception as exc:
            (splunk_out / f"{slug}.error").write_text(str(exc), encoding="utf-8")

        try:
            luc = lucene.convert(rules)
            (elastic_out / f"{slug}.lucene").write_text("\n\n".join(luc), encoding="utf-8")
        except Exception as exc:
            (elastic_out / f"{slug}.error").write_text(str(exc), encoding="utf-8")

        converted += 1

    typer.echo(f"Transpiled {converted} Sigma rule(s):")
    typer.echo(f"  Splunk SPL : {splunk_out}/")
    typer.echo(f"  Elastic    : {elastic_out}/")


if __name__ == "__main__":
    app()
