"""
Pure, testable core for BACProxy.

No mitmproxy, no network, no yaml — just the config merge, scope/method gating,
response classification, body preparation and HTML report rendering. This is
where the safety-critical decisions live so they can be unit-tested without a
proxy or a live target.
"""
from __future__ import annotations

import html as _html
import os
import re
from pathlib import Path

# Only idempotent/safe methods are replayed by default. Replaying a POST/DELETE
# as a second identity would duplicate (potentially destructive) side effects,
# so state-changing methods must be opted in explicitly via config.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

DEFAULT_CONFIG = {
    "scope": [],
    "exclude_endpoints": [],
    "replay_methods": list(SAFE_METHODS),
    "verify_tls": False,       # BAC testing is usually via a self-signed proxy
    "timeout": 30,
    "max_body_chars": 2000,    # cap stored response text so reports stay sane
    "redact": False,           # off by default: confirming BAC needs the body
    "output": "bac_report.html",
    "user2_header_name": "Authorization",
    "user2_header_value": "",
}

# Headers that must not be forwarded on a requests-library replay.
_DROP_HEADERS = {"content-length", "host", "accept-encoding", "connection",
                 "transfer-encoding"}

_REDACT_KEYS = ("password", "passwd", "token", "secret", "authorization",
                "api_key", "apikey", "cookie", "session")


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


def merge_config(user: dict | None) -> dict:
    """Overlay user config on defaults; normalize method casing."""
    cfg = dict(DEFAULT_CONFIG)
    if user:
        cfg.update({k: v for k, v in user.items() if v is not None})
    cfg["replay_methods"] = [str(m).upper() for m in cfg.get("replay_methods", [])]
    return cfg


def in_scope(url: str, scope, exclude) -> bool:
    """True if *url* prefix-matches a scope entry and no exclude entry."""
    if not any(url.startswith(s) for s in (scope or [])):
        return False
    if any(url.startswith(e) for e in (exclude or [])):
        return False
    return True


def method_allowed(method: str, replay_methods) -> bool:
    return method.upper() in {str(m).upper() for m in (replay_methods or [])}


def state_changing_enabled(replay_methods) -> list:
    """Return any non-safe methods the user opted into (for a startup warning)."""
    return [m for m in (replay_methods or []) if str(m).upper() not in SAFE_METHODS]


def strip_replay_headers(headers: dict) -> dict:
    """Drop hop-by-hop / length headers that would break a requests replay."""
    return {k: v for k, v in headers.items() if k.lower() not in _DROP_HEADERS}


def classify(status1: int, body1: str, status2: int, body2: str) -> str:
    """
    Classify a user1-vs-user2 comparison:

      ERROR   - a replay failed (status 0)
      NOPE    - different status codes (user2 likely blocked -> no BAC)
      MATCH   - same status AND identical body (user2 saw user1's data -> likely BAC)
      SIMILAR - same status, different body (worth a manual look)
    """
    if status1 == 0 or status2 == 0:
        return "ERROR"
    if status1 != status2:
        return "NOPE"
    return "MATCH" if body1 == body2 else "SIMILAR"


def prepare_body(text: str, max_chars: int, redact: bool = False) -> str:
    """Truncate (and optionally redact) a response body for the report."""
    text = text or ""
    if redact:
        for k in _REDACT_KEYS:
            text = re.sub(rf'("?{k}"?\s*[:=]\s*"?)([^"\s,}}]+)',
                          r"\1<redacted>", text, flags=re.IGNORECASE)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n...[truncated, {len(text)} chars total]"
    return text


def _esc(x) -> str:
    return _html.escape(str(x if x is not None else ""))


def render_report(records, max_chars: int = 2000, redact: bool = False) -> str:
    """Render the BAC report as self-contained, HTML-escaped HTML."""
    counts: dict = {}
    for r in records:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    summary = " · ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "no records"

    rows = ""
    for d in records:
        rows += f"""
        <tr class="{_esc(d['status'])}">
            <td>{_esc(d['endpoint'])}</td>
            <td><pre>{_esc(d['user1_header'])}</pre></td>
            <td><pre>{_esc(d['user2_header'])}</pre></td>
            <td>{_esc(d['status'])}</td>
            <td><pre>{_esc(prepare_body(d['user1_response'], max_chars, redact))}</pre></td>
            <td><pre>{_esc(prepare_body(d['user2_response'], max_chars, redact))}</pre></td>
        </tr>"""

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>BACProxy Report</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#f0f0f0; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border:1px solid #ddd; padding:8px; text-align:left; vertical-align:top; }}
  th {{ background:#4CAF50; color:#fff; }}
  tr.MATCH {{ background:#d4edda; }} tr.SIMILAR {{ background:#fff3cd; }}
  tr.NOPE {{ background:#f8d7da; }} tr.ERROR {{ background:#e2e3e5; }}
  pre {{ white-space: pre-wrap; word-wrap: break-word; max-height:16em; overflow:auto; }}
  .banner {{ background:#fff3cd; border:1px solid #e0c000; padding:.6rem; margin:.5rem 0; }}
</style></head><body>
  <h1>BACProxy — Broken Access Control Report</h1>
  <p><b>Summary:</b> {_esc(summary)}</p>
  <div class="banner">This report may contain sensitive response data
  (tokens, PII). It is written owner-only (0600) and is git-ignored — handle
  and share it accordingly.</div>
  <table>
    <tr><th>Endpoint</th><th>User1 Header</th><th>User2 Header</th>
        <th>Status</th><th>User1 Response</th><th>User2 Response</th></tr>
    {rows}
  </table>
</body></html>"""


def write_report(records, path, max_chars: int = 2000, redact: bool = False) -> None:
    """Render and write the report with owner-only (0600) permissions."""
    html = render_report(records, max_chars, redact)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
