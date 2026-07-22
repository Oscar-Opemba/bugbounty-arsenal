"""Unit tests for the RatFireWall rule engine (no mitmproxy, no network)."""
import rules
from rules import RequestCtx, ResponseCtx, evaluate


def _req(url="http://x/", body="", headers=None, method="GET"):
    return RequestCtx(method=method, url=url, headers=headers or {}, body=body)


REQ_RULES = rules.default_request_rules(max_body=100)
RESP_RULES = rules.default_response_rules()


def test_blocks_script_in_body():
    assert evaluate(_req(body="<script>alert(1)</script>"), REQ_RULES) is not None


def test_blocks_sqli_in_url():
    hit = evaluate(_req(url="http://x/item?id=1' OR 1=1"), REQ_RULES)
    assert hit and "SQLi" in hit


def test_blocks_path_traversal():
    assert evaluate(_req(url="http://x/../../etc/passwd"), REQ_RULES) is not None


def test_blocks_command_injection():
    assert evaluate(_req(body="q=; cat /etc/passwd"), REQ_RULES) is not None


def test_blocks_xxe():
    assert evaluate(_req(body='<!ENTITY xxe SYSTEM "file:///etc/passwd">'), REQ_RULES) is not None


def test_blocks_scanner_user_agent():
    hit = evaluate(_req(headers={"user-agent": "sqlmap/1.5"}), REQ_RULES)
    assert hit and "sqlmap" in hit


def test_blocks_oversized_body():
    assert evaluate(_req(body="A" * 101), REQ_RULES) is not None


def test_allows_benign_request():
    assert evaluate(_req(url="http://x/api/users?page=2", body="hello"), REQ_RULES) is None


def test_response_blocks_secret_leak():
    ctx = ResponseCtx(status=200, headers={}, body='{"password": "hunter2"}')
    assert evaluate(ctx, RESP_RULES) is not None


def test_response_allows_clean_body():
    ctx = ResponseCtx(status=200, headers={}, body='{"name": "alice"}')
    assert evaluate(ctx, RESP_RULES) is None


def test_faulty_rule_does_not_crash():
    def boom(ctx):
        raise RuntimeError("bad rule")
    r = rules.Rule("boom", "request", boom)
    assert r.blocks(_req()) is False  # swallowed, treated as no-match
