# RatAPIChat — API Request & Fuzzing Tool

A Tkinter GUI for crafting HTTP requests against an API — send single requests
or throttled parameter-fuzzing runs, with Basic/Bearer/OAuth auth, a Burp proxy,
Swagger/OpenAPI import, request history, and CSV export. Think "small Repeater +
Intruder" with safe defaults.

> ## ⚠️ Authorized use only
> This tool sends live HTTP requests (and, when fuzzing, many of them) to
> whatever you point it at. Use it **only** against systems you are explicitly
> authorized to test. See [`../../LEGAL.md`](../../LEGAL.md).

## Features

- Send `GET`/`POST`/`PUT`/`DELETE`/`PATCH` with Basic, Bearer, or OAuth 2.0 auth.
- **Throttled fuzzing:** replace `FUZZ` in the body with each value from a list,
  rate-limited (requests/sec) and gated by a confirmation showing the target
  host, request count, and estimated duration.
- Pre-populated fuzz lists from `./PREPOPLISTS/*.txt`.
- Swagger/OpenAPI import to auto-fill endpoints and example bodies.
- Burp Suite proxy + certificate support.
- Request history, session save/load, CSV export.

## Safety & data handling

- **Rate limiting actually works.** (In the original, a duplicate function
  silently bypassed the throttle, so fuzzing fired as fast as the network
  allowed — fixed.)
- **Request timeout** (30s) so a slow/tarpitting host can't hang the UI.
- **Secrets are not written to world-readable `/tmp`.** Session/preferences live
  under `${XDG_CONFIG_HOME:-~/.config}/ratapichat/` with `0600` permissions, and
  the auto-saved session **redacts auth tokens/passwords** by default. "Save
  Session" asks before including secrets; those files are also `0600`.
- **TLS verification stays on by default;** it only relaxes to a pinned Burp
  certificate you explicitly import.

## Setup (under 5 commands)

```bash
sudo apt-get install -y python3-tk         # Tkinter (Debian/Kali)
cd Scripts/RatAPIChat
pip install -r requirements.txt            # just: requests
python3 main.py
```

## Usage

1. **Base URL** + **API Endpoint** (they're concatenated).
2. Pick **Authentication** and enter the token/credentials.
3. Choose **Method**, set **Content Type**, and fill the **Request Body**.
4. **Send Request**, or put `FUZZ` in the body, add values under **Fuzz Values**
   (or load a prepopulated list), set **Fuzz rate (req/sec)**, and
   **Fuzz Parameters** → confirm the run.
5. Optional: **Proxy URL** (e.g. `http://127.0.0.1:8080` for Burp) and
   **File → Import Burp Cert** for HTTPS.

## Testing

The fiddly logic (request building, rate limiting, URL splitting, redaction,
Swagger parsing, secure persistence) is factored into `ratcore.py` and
`session_store.py` and unit-tested with no network and no display:

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q     # 27 tests
python3 -m ruff check .
```

## Architecture

```
main.py           Tkinter GUI + request/fuzz orchestration
ratcore.py        pure logic: RateLimiter, build_request, split_url, redaction, swagger
session_store.py  secure (0600, redacted) session/preferences persistence
SQLiByAPISpec.py  OpenAPI-driven SQLi probe GUI (bounded pool, signature detection)
sqli_core.py      pure logic for the SQLi probe (payloads, URL build, error signatures)
tests/            pytest suite (pure, no network/display)
```

The SQLi probe (`SQLiByAPISpec.py`) is also hardened: bounded worker pool
(was one unbounded thread per endpoint), thread-safe GUI updates via a queue,
request timeouts, a confirmation gate, and DBMS-signature-based detection instead
of the old `"error" in body` check. Its pure logic lives in `sqli_core.py`.

**Flagged, not changed:** both GUIs are built from module-level globals, so
`main.py` / `SQLiByAPISpec.py` aren't importable for unit testing (their logic is
covered via the extracted pure modules instead). Splitting the GUIs into classes
is a larger refactor deferred to keep this pass reviewable.

---

_Original concept: The XSS Rat. Hardened for engagement use (working rate limit,
secret-safe storage, request timeouts, tests, CI)._
