"""Unit tests for the pure BACProxy core (no mitmproxy, no network)."""
import os
import stat

import pytest

import core


# ---- config ----
def test_merge_config_defaults_safe_methods():
    cfg = core.merge_config(None)
    assert cfg["replay_methods"] == ["GET", "HEAD", "OPTIONS"]
    assert cfg["verify_tls"] is False


def test_merge_config_uppercases_methods_and_overlays():
    cfg = core.merge_config({"replay_methods": ["get", "post"], "timeout": 5})
    assert cfg["replay_methods"] == ["GET", "POST"]
    assert cfg["timeout"] == 5


# ---- scope / method gating ----
def test_in_scope_prefix_and_exclude():
    scope = ["https://app.example.com/api/"]
    exclude = ["https://app.example.com/api/logout"]
    assert core.in_scope("https://app.example.com/api/orders/1", scope, exclude)
    assert not core.in_scope("https://app.example.com/api/logout", scope, exclude)
    assert not core.in_scope("https://evil.com/api/", scope, exclude)


def test_method_allowed():
    assert core.method_allowed("get", ["GET"])
    assert not core.method_allowed("POST", ["GET", "HEAD"])


def test_state_changing_enabled_flags_risky_methods():
    assert core.state_changing_enabled(["GET", "POST", "DELETE"]) == ["POST", "DELETE"]
    assert core.state_changing_enabled(["GET", "HEAD"]) == []


def test_strip_replay_headers_drops_hop_by_hop():
    h = {"Host": "x", "Content-Length": "5", "Authorization": "a", "X-Custom": "1"}
    out = core.strip_replay_headers(h)
    assert "Host" not in out and "Content-Length" not in out
    assert out["Authorization"] == "a" and out["X-Custom"] == "1"


# ---- classification (the core BAC signal) ----
@pytest.mark.parametrize("s1,b1,s2,b2,expected", [
    (200, "same", 200, "same", "MATCH"),      # user2 saw identical data -> likely BAC
    (200, "a", 200, "b", "SIMILAR"),          # same status, different body
    (200, "x", 403, "denied", "NOPE"),        # user2 blocked -> good
    (0, "", 200, "x", "ERROR"),               # replay failed
    (200, "x", 0, "", "ERROR"),
])
def test_classify(s1, b1, s2, b2, expected):
    assert core.classify(s1, b1, s2, b2) == expected


# ---- body preparation ----
def test_prepare_body_truncates():
    out = core.prepare_body("A" * 5000, max_chars=100)
    assert out.startswith("A" * 100)
    assert "truncated" in out


def test_prepare_body_redacts_when_enabled():
    body = '{"password": "hunter2", "id": 5}'
    out = core.prepare_body(body, max_chars=1000, redact=True)
    assert "hunter2" not in out and "<redacted>" in out


def test_prepare_body_no_redact_by_default():
    body = '{"password": "hunter2"}'
    assert "hunter2" in core.prepare_body(body, max_chars=1000)


# ---- report rendering / writing ----
def test_render_report_escapes_and_summarizes():
    records = [{
        "endpoint": "https://x/api/1", "user1_header": "t1", "user2_header": "t2",
        "status": "MATCH", "user1_response": "<b>hi</b>", "user2_response": "<b>hi</b>",
    }]
    html = core.render_report(records)
    assert "<b>hi</b>" not in html and "&lt;b&gt;hi&lt;/b&gt;" in html
    assert "MATCH: 1" in html


def test_write_report_is_0600(tmp_path):
    p = tmp_path / "sub" / "bac_report.html"
    core.write_report([], p)
    assert p.exists()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
