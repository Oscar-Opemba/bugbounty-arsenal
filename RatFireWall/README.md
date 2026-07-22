# RatFireWall — Rule-Based Blocking Proxies

Two small **defensive** proxies for lab/testing use:

1. **`firewall.py`** — a [mitmproxy](https://mitmproxy.org/) addon that inspects
   requests/responses against a rule engine (`rules.py`) and returns `403` on a
   match (XSS/SQLi/traversal/command-injection/XXE signatures, scanner
   user-agents, oversized bodies, and secret-leaking responses).
2. **`HorridAPIResponseFirewall/firewall.py`** — a Flask reverse proxy that
   blocks upstream JSON responses containing forbidden keywords (leaked secrets).

> ## ⚠️ Lab / teaching tool — not a production WAF
> The signatures are intentionally simple and are trivially bypassable (e.g. an
> `<img onerror=...>` instead of `<script>`, or header casing tricks). Use this
> to learn and to test detection, **not** to protect real systems. Authorized
> use only — see [`../LEGAL.md`](../LEGAL.md).

## What was fixed

All three original variants were broken:
- `firewall.py` referenced `http` and `Rule` without importing them and called
  the removed `http.HTTPResponse.make` API → **NameError / AttributeError**.
- `moreSecureButNotFullySecure/rules.py` called the `Rule` constructor with
  arguments it didn't accept → **TypeError on import**. (Removed; consolidated.)
- The Flask variant did `response.headers['Content-Type']` (KeyError on missing
  header) and bound to `0.0.0.0`.

Now: one working mitmproxy addon on the modern `http.Response.make` API, a pure
tested rule engine, and a hardened Flask proxy (localhost bind, timeout, no
KeyError, env-configurable upstream).

## Usage

**mitmproxy blocking proxy:**
```bash
pip install -r requirements.txt
mitmdump -s firewall.py            # then point your client at mitmproxy
```

**Flask response firewall:**
```bash
PROXY_API_BASE_URL=https://api.example.com python3 HorridAPIResponseFirewall/firewall.py
# BIND_HOST (default 127.0.0.1), BIND_PORT (8080), PROXY_TIMEOUT (30) are env-configurable
```

## Rules

Edit `rules.py`. Each `Rule` has a name, a scope (`request`/`response`), and a
predicate (`ctx -> block?`). Builders provided: `header_contains`,
`missing_header`, `request_matches`, `response_matches`, `body_larger_than`. A
predicate that raises is treated as "no match" so a bad rule can't crash the proxy.

## Testing

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q     # 15 tests (rule engine + Flask inspection), no network
python3 -m ruff check .
```
