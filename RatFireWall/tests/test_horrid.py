"""Tests for the Horrid API Response Firewall's inspection + proxy behavior."""
import importlib.util
from pathlib import Path

# Load the Horrid firewall module by path (sibling package dir).
_spec = importlib.util.spec_from_file_location(
    "horrid_firewall",
    Path(__file__).resolve().parent.parent / "HorridAPIResponseFirewall" / "firewall.py",
)
horrid = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(horrid)


def test_inspect_response_flags_secrets():
    assert horrid.inspect_response({"password": "x"}) is True
    assert horrid.inspect_response({"data": {"api-key": "abc"}}) is True
    assert horrid.inspect_response("private_key here") is True


def test_inspect_response_allows_clean():
    assert horrid.inspect_response({"name": "alice", "id": 3}) is False


def test_binds_localhost_by_default():
    # Hardened default: not 0.0.0.0
    assert horrid.BIND_HOST == "127.0.0.1"


def test_missing_content_type_does_not_crash(monkeypatch):
    """A response with no Content-Type header must not raise KeyError."""
    class FakeResp:
        status_code = 200
        headers = {}  # no Content-Type
        content = b"raw"

        def json(self):
            return {}

    monkeypatch.setattr(horrid.requests, "request", lambda *a, **k: FakeResp())
    client = horrid.app.test_client()
    r = client.get("/anything")
    assert r.status_code == 200  # falls through to raw passthrough, no crash
