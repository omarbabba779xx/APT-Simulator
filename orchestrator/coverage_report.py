"""Static HTML coverage report.

Combines:
  - registered TTPs (per tactic)
  - Sigma rule presence (from detection/sigma/coverage.json)
  - Most recent run status per TTP (from data/apt_sim.db)

Writes a self-contained HTML file. No external assets.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

import typer

import ttps  # noqa: F401  (registers TTPs)
from ttps.base import registry

from .storage.db import Repository, init_engine


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Coverage matrix HTML generator."""


def _last_status_per_ttp(db_path: Path) -> dict[str, str]:
    if not db_path.exists():
        return {}
    engine = init_engine(db_path)
    repo = Repository(engine)
    out: dict[str, str] = {}
    for run in repo.list_runs():
        for step in repo.steps_for_run(run.id):
            out[step.attack_id] = step.status
    return out


def _build_html(
    ttp_by_tactic: dict[str, list],
    sigma_coverage: dict[str, dict[str, str]],
    last_status: dict[str, str],
) -> str:
    tactics = sorted(ttp_by_tactic.keys())
    rows: list[str] = []
    rows.append("<table class='matrix'><thead><tr>")
    for t in tactics:
        rows.append(f"<th>{html.escape(t)}</th>")
    rows.append("</tr></thead><tbody>")

    max_rows = max(len(v) for v in ttp_by_tactic.values())
    for i in range(max_rows):
        rows.append("<tr>")
        for t in tactics:
            techs = ttp_by_tactic[t]
            if i < len(techs):
                ttp = techs[i]
                has_rule = sigma_coverage.get(ttp.attack_id, {}).get("status") == "exported"
                last = last_status.get(ttp.attack_id, "—")
                cls = "has-rule" if has_rule else "no-rule"
                cls += f" status-{last}"
                rows.append(
                    f"<td class='{cls}' title='{html.escape(ttp.description)}'>"
                    f"<div class='ttp-id'>{html.escape(ttp.attack_id)}</div>"
                    f"<div class='ttp-name'>{html.escape(ttp.name)}</div>"
                    f"<div class='ttp-meta'>sigma:{'✓' if has_rule else '✗'} · last:{html.escape(last)}</div>"
                    f"</td>"
                )
            else:
                rows.append("<td></td>")
        rows.append("</tr>")
    rows.append("</tbody></table>")
    matrix_html = "".join(rows)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>APT Simulator — Coverage Report</title>
<style>
body {{ font-family: ui-monospace, Consolas, monospace; background: #0e1116; color: #d6deeb; margin: 24px; }}
h1 {{ color: #58a6ff; }}
table.matrix {{ border-collapse: collapse; width: 100%; }}
.matrix th, .matrix td {{ border: 1px solid #2a313a; padding: 8px; text-align: left; vertical-align: top; min-width: 120px; }}
.matrix th {{ background: #161b22; color: #58a6ff; text-transform: uppercase; font-size: 11px; }}
.matrix td.has-rule {{ background: rgba(63, 185, 80, 0.07); border-color: #3fb950; }}
.matrix td.no-rule {{ background: rgba(248, 81, 73, 0.05); }}
.matrix td.status-success {{ outline: 2px solid #3fb950; outline-offset: -2px; }}
.matrix td.status-failed {{ outline: 2px solid #f85149; outline-offset: -2px; }}
.matrix td.status-aborted {{ outline: 2px solid #d29922; outline-offset: -2px; }}
.ttp-id {{ font-weight: bold; color: #d6deeb; }}
.ttp-name {{ font-size: 11px; color: #6e7a8a; margin-top: 2px; }}
.ttp-meta {{ font-size: 10px; color: #6e7a8a; margin-top: 4px; }}
.legend {{ margin: 16px 0; font-size: 12px; color: #6e7a8a; }}
.legend span {{ display: inline-block; padding: 2px 8px; margin-right: 8px; border: 1px solid #2a313a; }}
</style>
</head>
<body>
<h1>APT Simulator — MITRE ATT&amp;CK Coverage</h1>
<p class="legend">
  <span class="has-rule">Sigma rule exported</span>
  <span class="no-rule">No Sigma rule</span>
  <span style="outline: 2px solid #3fb950;">Last run: success</span>
  <span style="outline: 2px solid #f85149;">Last run: failed</span>
</p>
{matrix_html}
<p style="margin-top: 24px; color: #6e7a8a; font-size: 11px;">
Generated from registered TTPs + detection/sigma/coverage.json + data/apt_sim.db.
</p>
</body>
</html>
"""


@app.command()
def generate(
    out: str = "detection/coverage_report.html",
    sigma_coverage: str = "detection/sigma/coverage.json",
    db_path: str = "data/apt_sim.db",
) -> None:
    """Write the coverage report HTML."""
    by_tactic: dict[str, list] = {}
    for ttp in registry.all().values():
        by_tactic.setdefault(ttp.tactic or "uncategorized", []).append(ttp)

    sigma_data: dict[str, dict[str, str]] = {}
    sp = Path(sigma_coverage)
    if sp.exists():
        sigma_data = json.loads(sp.read_text(encoding="utf-8"))

    last_status = _last_status_per_ttp(Path(db_path))

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_build_html(by_tactic, sigma_data, last_status), encoding="utf-8")
    typer.echo(f"Wrote coverage report to {out_path}")


if __name__ == "__main__":
    app()
