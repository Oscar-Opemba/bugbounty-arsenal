"""Unit tests for secure session persistence."""
import json
import os
import stat

import session_store


def test_save_history_redacts_tokens_and_sets_0600(tmp_path):
    hist = [{"url": "https://x/", "auth_token": "SECRET", "method": "GET"}]
    p = tmp_path / "sub" / "last_session.json"
    session_store.save_history(hist, p)  # redact defaults True

    data = json.loads(p.read_text())
    assert data[0]["auth_token"] == "<redacted>"
    assert "SECRET" not in p.read_text()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600


def test_save_history_can_keep_secrets_on_explicit_export(tmp_path):
    hist = [{"url": "https://x/", "auth_token": "SECRET"}]
    p = tmp_path / "export.json"
    session_store.save_history(hist, p, redact=False)
    assert json.loads(p.read_text())[0]["auth_token"] == "SECRET"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600  # still owner-only


def test_load_history_missing_returns_empty(tmp_path):
    assert session_store.load_history(tmp_path / "nope.json") == []


def test_load_history_corrupt_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert session_store.load_history(p) == []


def test_config_dir_respects_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert session_store.config_dir() == tmp_path / "ratapichat"
