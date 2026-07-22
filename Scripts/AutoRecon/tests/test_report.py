"""Unit tests for the structured result model and report renderers."""
import json

from report import (
    RunManifest, StepResult, classify, render_html, write_json,
    write_steps_csv, STATUS_OK, STATUS_ERROR, STATUS_TIMEOUT, STATUS_NOT_FOUND,
)


def test_classify():
    assert classify(0) == STATUS_OK
    assert classify(124) == STATUS_TIMEOUT
    assert classify(127) == STATUS_NOT_FOUND
    assert classify(3) == STATUS_ERROR


def _manifest():
    m = RunManifest(job_id="j1", target="app.example.com", scope_source="scope.txt",
                    workflow="default_basic", dry_run=False, started="2026-01-01T00:00:00",
                    finished="2026-01-01T00:01:00")
    m.steps = [
        StepResult(tool="subfinder", command="subfinder -d x", status=STATUS_OK,
                   returncode=0, lines_out=3),
        StepResult(tool="nmap", command="nmap x", status=STATUS_TIMEOUT, returncode=124,
                   host="app.example.com", note="timed out"),
    ]
    m.discovered = ["app.example.com", "api.example.com"]
    return m


def test_manifest_summary_counts():
    d = _manifest().to_dict()
    assert d["summary"]["steps_total"] == 2
    assert d["summary"]["status_counts"] == {STATUS_OK: 1, STATUS_TIMEOUT: 1}
    assert d["summary"]["discovered_total"] == 2


def test_write_json_roundtrip(tmp_path):
    p = tmp_path / "run.json"
    write_json(_manifest(), p)
    d = json.loads(p.read_text())
    assert d["target"] == "app.example.com"
    assert d["schema_version"] == 1
    assert len(d["steps"]) == 2


def test_write_csv(tmp_path):
    p = tmp_path / "steps.csv"
    write_steps_csv(_manifest().steps, p)
    text = p.read_text()
    assert "tool,host,status" in text.splitlines()[0]
    assert "subfinder" in text and "nmap" in text


def test_render_html_is_self_contained_and_escaped():
    m = _manifest()
    # inject something that must be HTML-escaped
    m.discovered.append("<script>alert(1)</script>")
    out = render_html(m)
    assert out.startswith("<!doctype html>")
    assert "http://" not in out.split("<style>")[0]  # no external asset link in head
    assert "<script>alert(1)</script>" not in out       # raw payload must be escaped
    assert "&lt;script&gt;" in out
    assert "app.example.com" in out
    # error step surfaces in the attention section
    assert "attention" in out.lower()


def test_render_html_dry_run_banner():
    m = _manifest()
    m.dry_run = True
    assert "DRY RUN" in render_html(m)
