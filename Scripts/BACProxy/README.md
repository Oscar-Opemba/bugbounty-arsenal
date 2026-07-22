# BACProxy — Broken Access Control / IDOR Detector

A [mitmproxy](https://mitmproxy.org/) addon. As you browse an app as **user1**,
BACProxy replays each in-scope request once as **user2** and compares the
responses. If user2 gets an identical response (**MATCH**), user2 could likely
access user1's data — a broken-access-control / IDOR finding.

> ## ⚠️ Authorized use only
> BACProxy sends extra requests to the target as a second identity. Use it only
> against systems you are authorized to test. See [`../../LEGAL.md`](../../LEGAL.md).

## Safety model

- **Idempotent methods only by default.** Only `GET`/`HEAD`/`OPTIONS` are
  replayed, so BACProxy never silently repeats a state-changing action
  (`POST`/`DELETE`/…) as another user. Enabling those in config prints a loud
  warning — do it only when you understand the side effects.
- **Uses the real user1 response** (from the intercepted flow) and sends **one**
  user2 replay — half the added traffic of a naive double-replay, and an
  accurate user1 baseline.
- **Scope-gated.** Only URLs matching a `scope` prefix (and not an
  `exclude_endpoints` prefix) are tested.
- **Report is treated as sensitive:** written owner-only (`0600`), body sizes
  capped, optional redaction, and git-ignored.
- **Per-replay timeout**; TLS verification is configurable.

## Setup (under 5 commands)

```bash
pip install -r requirements.txt          # mitmproxy, requests, pyyaml
cd Scripts/BACProxy
cp config.example.yaml config.yaml && $EDITOR config.yaml   # set scope + user2 token
mitmdump -s bacproxy.py
```

Then point your browser (or Burp) at mitmproxy's listener and browse the app as
**user1**. On shutdown, `bac_report.html` is written.

## Configuration

Edit `config.yaml` (see `config.example.yaml` for the annotated template):

| Key | Meaning |
|-----|---------|
| `scope` | URL prefixes to test (your authorization boundary) |
| `exclude_endpoints` | URL prefixes to never test |
| `replay_methods` | methods replayed as user2 (default safe methods only) |
| `user2_header_name` / `user2_header_value` | the second identity's header (or env `USER2_HEADER_NAME` / `USER2_HEADER_VALUE`) |
| `verify_tls` | verify upstream TLS (false when testing via a self-signed proxy) |
| `timeout`, `max_body_chars`, `redact`, `output` | replay timeout, report body cap, redaction, output path |

## Reading the report

| Status | Meaning |
|--------|---------|
| **MATCH** | Same status **and identical body** → user2 saw user1's data → **likely BAC/IDOR** |
| **SIMILAR** | Same status, different body → worth a manual look |
| **NOPE** | Different status (user2 blocked) → access control probably working |
| **ERROR** | The user2 replay failed (network/timeout) |

## Testing

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q      # 16 tests, no proxy/network
python3 -m ruff check .
```

The safety-critical logic (scope/method gating, classification, redaction,
report rendering, 0600 writing) lives in `core.py` and is fully unit-tested. The
thin `bacproxy.py` addon wires it into mitmproxy.
