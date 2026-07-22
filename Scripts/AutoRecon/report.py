"""
Structured result model for AutoRecon.

Pure and dependency-free (stdlib only, no tkinter/network) so it can be
unit-tested in isolation. A run produces a machine-readable manifest
(run.json) and a flat step log (steps.csv) that downstream tooling — or the
Phase 3 client report renderer — can consume without scraping terminal output.
"""
from __future__ import annotations

import csv
import html
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

# Canonical step outcomes.
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"
STATUS_NOT_FOUND = "not_found"   # tool binary missing (rc 127)
STATUS_SKIPPED = "skipped"       # e.g. out of scope
STATUS_DRY_RUN = "dry_run"

SCHEMA_VERSION = 1


def classify(returncode: int) -> str:
    """Map a process return code to a canonical status string."""
    if returncode == 0:
        return STATUS_OK
    if returncode == 124:
        return STATUS_TIMEOUT
    if returncode == 127:
        return STATUS_NOT_FOUND
    return STATUS_ERROR


@dataclass
class StepResult:
    tool: str
    command: str
    status: str
    returncode: Optional[int] = None
    started: Optional[str] = None
    finished: Optional[str] = None
    duration_s: Optional[float] = None
    host: Optional[str] = None
    lines_out: int = 0
    note: str = ""


@dataclass
class RunManifest:
    job_id: str
    target: str
    scope_source: str
    workflow: str
    dry_run: bool
    started: str
    finished: Optional[str] = None
    schema_version: int = SCHEMA_VERSION
    steps: List[StepResult] = field(default_factory=list)
    discovered: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # summary counts are convenient for consumers / dashboards
        counts: dict = {}
        for s in self.steps:
            counts[s.status] = counts.get(s.status, 0) + 1
        d["summary"] = {
            "steps_total": len(self.steps),
            "status_counts": counts,
            "discovered_total": len(self.discovered),
        }
        return d


def write_json(manifest: RunManifest, path) -> None:
    Path(path).write_text(json.dumps(manifest.to_dict(), indent=2))


def write_steps_csv(steps: List[StepResult], path) -> None:
    fields = ["tool", "host", "status", "returncode", "started", "finished",
              "duration_s", "lines_out", "note", "command"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for s in steps:
            row = asdict(s)
            w.writerow({k: row.get(k, "") for k in fields})


# ----------------------------
# Engagement-ready HTML report
# ----------------------------
_STATUS_COLOR = {
    STATUS_OK: "#1a7f37",
    STATUS_ERROR: "#b42318",
    STATUS_TIMEOUT: "#b54708",
    STATUS_NOT_FOUND: "#6941c6",
    STATUS_SKIPPED: "#475467",
    STATUS_DRY_RUN: "#175cd3",
}


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def render_html(manifest: RunManifest) -> str:
    """
    Render a self-contained (no external assets) HTML report suitable for an
    engagement deliverable: scope, methodology, timing, discovered assets, and
    a per-step table that visibly distinguishes 'no findings' from tool errors.
    """
    d = manifest.to_dict()
    summary = d["summary"]
    counts = summary["status_counts"]
    errors = [s for s in manifest.steps
              if s.status in (STATUS_ERROR, STATUS_TIMEOUT, STATUS_NOT_FOUND)]

    def chip(label, value, color="#475467"):
        return (f'<span class="chip" style="border-color:{color};color:{color}">'
                f'{_esc(label)}: <b>{_esc(value)}</b></span>')

    chips = [
        chip("Steps", summary["steps_total"]),
        chip("Discovered", summary["discovered_total"], "#1a7f37"),
    ]
    for st, n in counts.items():
        chips.append(chip(st, n, _STATUS_COLOR.get(st, "#475467")))

    methodology_rows = "".join(
        f"<tr><td>{i + 1}</td><td><code>{_esc(s.tool)}</code></td>"
        f"<td>{_esc(s.host or '')}</td>"
        f'<td><span style="color:{_STATUS_COLOR.get(s.status, "#475467")}">'
        f"{_esc(s.status)}</span></td>"
        f"<td>{_esc(s.duration_s if s.duration_s is not None else '')}</td>"
        f"<td>{_esc(s.lines_out)}</td>"
        f"<td><code>{_esc(s.command)}</code></td>"
        f"<td>{_esc(s.note)}</td></tr>"
        for i, s in enumerate(manifest.steps)
    )

    discovered_html = (
        "<p class='muted'>No hosts discovered.</p>" if not manifest.discovered
        else "<ul class='hosts'>" + "".join(f"<li>{_esc(h)}</li>"
                                             for h in manifest.discovered) + "</ul>"
    )

    if errors:
        err_html = "<ul>" + "".join(
            f"<li><code>{_esc(s.tool)}</code> "
            f"({_esc(s.host or 'target')}) — <b>{_esc(s.status)}</b>: {_esc(s.note)}</li>"
            for s in errors) + "</ul>"
        err_banner = (f'<div class="banner err">{len(errors)} step(s) need attention '
                      f'(tool error / timeout / missing binary). See below.</div>')
    else:
        err_html = "<p class='muted'>No tool errors, timeouts, or missing binaries.</p>"
        err_banner = '<div class="banner ok">All steps completed without tool errors.</div>'

    dry = ('<div class="banner dry">DRY RUN — no traffic was sent to the target. '
           'This report reflects the planned actions only.</div>'
           if manifest.dry_run else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoRecon Report — {_esc(manifest.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         margin: 0; padding: 0 0 4rem; color: #101828; background: #f9fafb; }}
  header {{ background: #101828; color: #fff; padding: 1.5rem 2rem; }}
  header h1 {{ margin: 0 0 .25rem; font-size: 1.4rem; }}
  header .sub {{ color: #98a2b3; font-size: .9rem; }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 0 1.5rem; }}
  section {{ background: #fff; border: 1px solid #eaecf0; border-radius: 10px;
            padding: 1.25rem 1.5rem; margin-top: 1.25rem; }}
  h2 {{ font-size: 1.05rem; margin: 0 0 .75rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .85rem; }}
  th, td {{ border-bottom: 1px solid #eaecf0; padding: .5rem .6rem; text-align: left;
           vertical-align: top; }}
  th {{ background: #f2f4f7; }}
  code {{ background: #f2f4f7; padding: .05rem .3rem; border-radius: 4px;
         font-size: .8rem; word-break: break-all; }}
  .chip {{ display: inline-block; border: 1px solid; border-radius: 999px;
          padding: .15rem .6rem; margin: .15rem .3rem .15rem 0; font-size: .8rem; }}
  .kv {{ display: grid; grid-template-columns: 160px 1fr; gap: .35rem 1rem; font-size: .9rem; }}
  .kv div:nth-child(odd) {{ color: #475467; }}
  .banner {{ padding: .6rem .9rem; border-radius: 8px; margin-top: 1rem; font-size: .9rem; }}
  .banner.ok {{ background: #ecfdf3; color: #1a7f37; }}
  .banner.err {{ background: #fef3f2; color: #b42318; }}
  .banner.dry {{ background: #eff8ff; color: #175cd3; }}
  .muted {{ color: #667085; }}
  ul.hosts {{ columns: 3; font-size: .85rem; }}
  .table-wrap {{ overflow-x: auto; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0c111d; color:#e4e7ec; }}
    section {{ background:#161b26; border-color:#333b4a; }}
    th {{ background:#1d2433; }} code,.chip {{ background:transparent; }}
    th,td {{ border-color:#333b4a; }}
  }}
</style></head>
<body>
<header>
  <h1>AutoRecon — Reconnaissance Report</h1>
  <div class="sub">Target: <b>{_esc(manifest.target)}</b> &nbsp;·&nbsp; Job: {_esc(manifest.job_id)}</div>
</header>
<main>
  {dry}
  <section>
    <h2>Engagement summary</h2>
    <div class="kv">
      <div>Target</div><div><b>{_esc(manifest.target)}</b></div>
      <div>Authorized scope</div><div><code>{_esc(manifest.scope_source)}</code></div>
      <div>Workflow</div><div>{_esc(manifest.workflow)}</div>
      <div>Started</div><div>{_esc(manifest.started)}</div>
      <div>Finished</div><div>{_esc(manifest.finished)}</div>
      <div>Mode</div><div>{'DRY RUN (no traffic)' if manifest.dry_run else 'Live'}</div>
    </div>
    <div style="margin-top:1rem">{''.join(chips)}</div>
    {err_banner}
  </section>
  <section>
    <h2>Discovered assets ({summary['discovered_total']})</h2>
    {discovered_html}
  </section>
  <section>
    <h2>Attention required</h2>
    {err_html}
  </section>
  <section>
    <h2>Methodology &amp; step log</h2>
    <div class="table-wrap"><table>
      <tr><th>#</th><th>Tool</th><th>Host</th><th>Status</th><th>Dur (s)</th>
          <th>Lines</th><th>Command</th><th>Note</th></tr>
      {methodology_rows}
    </table></div>
  </section>
  <section class="muted" style="font-size:.8rem">
    Generated by AutoRecon. This report is for authorized security testing only.
    Machine-readable data: <code>run.json</code>, <code>steps.csv</code> (same directory).
  </section>
</main>
</body></html>"""


def write_html(manifest: RunManifest, path) -> None:
    Path(path).write_text(render_html(manifest), encoding="utf-8")
