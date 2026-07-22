"""
Structured result model for AutoRecon.

Pure and dependency-free (stdlib only, no tkinter/network) so it can be
unit-tested in isolation. A run produces a machine-readable manifest
(run.json) and a flat step log (steps.csv) that downstream tooling — or the
Phase 3 client report renderer — can consume without scraping terminal output.
"""
from __future__ import annotations

import csv
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
