"""End-to-end pipeline test in dry-run mode.

Exercises the whole JobRunner pipeline WITHOUT sending any traffic or invoking
any external tool: dry-run short-circuits every network step. This is the safe
substitute for pointing the tool at a live host in CI.

For real validation against live tooling, run the headless CLI against a lab
you control (e.g. a VM / Docker range) — never an external target.
"""
import asyncio

import main
from scope import parse_scope_lines


def test_dry_run_pipeline_sends_no_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "RESULTS_DIR", tmp_path / "results")
    scope = parse_scope_lines(["example.com"])
    job_id = "itest_" + tmp_path.name[-8:]
    runner = main.JobRunner(
        job_id=job_id, target="app.example.com",
        workflow=main.DEFAULT_WORKFLOW, scope=scope, dry_run=True,
    )
    asyncio.run(runner.run_pipeline())

    base = runner.base_dir
    assert (base / "run.json").exists()
    assert (base / "steps.csv").exists()
    assert (base / "report.html").exists()

    # Nothing but dry-run previews and the local (traffic-free) permutation step.
    assert runner.manifest.steps, "expected steps to be recorded"
    for s in runner.manifest.steps:
        assert s.status in ("dry_run", "ok")
        if s.status == "ok":
            assert s.tool == "permutation"  # local generation only, no network


def test_out_of_scope_target_is_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(main, "RESULTS_DIR", tmp_path / "results")
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")

    class Args:
        scope = str(scope_file)
        target = "evil.com"
        workflow = "default_basic"
        dry_run = True
        yes = True
        cmd_timeout = 60

    rc = main.run_headless(Args())
    assert rc == 2  # refused, non-zero exit
    assert "not in scope" in capsys.readouterr().err.lower()
