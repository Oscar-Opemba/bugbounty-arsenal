# AutoRecon — Subdomain Recon Orchestrator

A scope-aware orchestrator that chains passive subdomain enumeration → DNS brute
force → permutation → content discovery → port scanning into one repeatable job,
with a Tkinter GUI **and** a headless CLI. Every run produces a structured,
engagement-ready report (`report.html` + `run.json` + `steps.csv`).

It drives standard tools you already use — `subfinder`, `amass`, `assetfinder`,
`findomain`, `gobuster`, `ffuf`, `nmap`, `masscan` — and adds the safety rails,
logging, and reporting that a real engagement needs.

> ## ⚠️ Authorized use only
> This tool sends reconnaissance and scanning traffic to whatever you point it
> at. Use it **only** against systems you are explicitly authorized to test
> (signed engagement, bug-bounty program in scope, or your own lab). You are
> responsible for staying within scope and within the law. See
> [`../../LEGAL.md`](../../LEGAL.md).

---

## Safety model (why this is different from a raw script)

- **Scope is mandatory.** A job will not start without a scope file. The target
  *and every discovered/permuted host* is checked against it before any command
  runs against that host. Out-of-scope hosts are skipped and logged. Matching is
  suffix-confusion-safe (`notexample.com` does **not** match `example.com`),
  supports apex/subdomain/IP/CIDR rules and `!` exclusions, and fails closed.
- **Dry-run by default.** The GUI's "Dry run" box is checked on launch, and
  `--dry-run` on the CLI prints the exact resolved commands while sending
  **zero traffic**.
- **Explicit confirmation** before any live run.
- **Anti-DoS defaults.** Global concurrency ceiling, per-run host caps, and
  throttled rates (`nmap --max-rate 500`, `masscan --rate 300`). Full port
  coverage is preserved.
- **Timeouts.** Every command has a wall-clock timeout so an unreachable or
  tarpitting host can't hang the job.

## Setup (under 5 commands)

```bash
# 1. System deps (Debian/Kali): Tkinter + the recon tools you want to use
sudo apt-get install -y python3-tk nmap masscan gobuster ffuf
#    (subfinder / amass / assetfinder / findomain: install per their own docs)

# 2. Create your scope file from the template
cd Scripts/AutoRecon && cp scope.example.txt scope.txt && $EDITOR scope.txt

# 3. Preview a run against your lab — no traffic is sent
python3 main.py --no-gui --target lab.example.com --scope scope.txt --dry-run
```

No third-party pip packages are required to run AutoRecon (stdlib only).

## Usage

### Headless CLI (scriptable, CI-friendly)

```bash
# Dry run — prints the plan and every resolved command, sends nothing
python3 main.py --no-gui --target lab.example.com --scope scope.txt --dry-run

# Live run against an in-scope target (prompts for confirmation)
python3 main.py --no-gui --target lab.example.com --scope scope.txt

# Non-interactive live run (e.g. from a wrapper) — use with care
python3 main.py --no-gui --target lab.example.com --scope scope.txt --yes
```

| Flag | Meaning |
|------|---------|
| `--target` | Target apex/host (also triggers headless mode) |
| `--scope` | Path to scope file (**required** to run a job) |
| `--dry-run` | Print plan + commands, send no traffic |
| `--no-gui` | Force headless mode |
| `--workflow` | Workflow name from `workflows.json` (default `default_basic`) |
| `--cmd-timeout` | Per-command timeout in seconds (default 1800) |
| `--yes` | Skip the live-run confirmation |

Exit codes: `0` success · `1` user-aborted · `2` refused (bad/out-of-scope target,
missing scope, unknown workflow).

### GUI

```bash
python3 main.py
```

Pick a workflow, enter the target, **select your scope file** (required), leave
"Dry run" checked to preview, then uncheck and confirm to run live. Jobs run
concurrently with live per-job logs; results land in `results/<timestamp_job>/`.

## Scope file format

```text
example.com          # apex AND any subdomain (*.example.com)
app.example.com      # this host and its subdomains only
!secret.example.com  # exclusion — never in scope (exclusions always win)
203.0.113.0/24       # a CIDR range
203.0.113.10         # a single IP
```

`scope.txt` is git-ignored so a live engagement's targets never get committed —
only the `*.example.txt` template is tracked.

## Output

Each job writes to `results/<timestamp>_<job_id>/`:

| File | Purpose |
|------|---------|
| `report.html` | Engagement-ready report: scope, timing, discovered assets, per-step methodology table, and an "attention required" section separating clean results from tool errors/timeouts/missing binaries |
| `run.json` | Machine-readable manifest (schema-versioned, with summary counts) for feeding other tooling |
| `steps.csv` | Flat per-step log (tool, host, status, rc, duration, command) |
| `job.log` | Timestamped, levelled log of the run |
| `<tool>.txt`, `combined.txt`, `permutations.txt` | Raw tool output and merged host list |

## Testing

Core logic (scope matching, target normalization, report model, and a full
dry-run pipeline) is unit-tested and runs **without a display, network, or any
external tool**:

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q      # 39 tests
python3 -m ruff check .   # lint
```

For real validation against live tooling, run the headless CLI against a **lab
you control** (a VM or Docker range / intentionally-vulnerable target). Never
validate against external infrastructure.

## Architecture

```
main.py       GUI + headless CLI + JobRunner pipeline orchestration
scope.py      pure scope engine + target normalizer (no I/O)
report.py     pure result model + JSON/CSV/HTML renderers
logsetup.py   stdlib logging (stdout + per-job job.log)
tests/        pytest suite (pure + dry-run integration)
```

**Known limitation / flagged for a future pass:** `JobRunner` still lives inside
`main.py` alongside the GUI. Splitting it into its own module would let a third
front-end (or a service) reuse the pipeline without importing Tkinter. It's a
moderate refactor with no behavioural change, deferred to keep this hardening
pass reviewable. The GUI "Stop job" remains best-effort (it can't reliably kill
already-spawned external tool processes).

---

_Original concept: The XSS Rat. Hardened for engagement use (scope enforcement,
dry-run, structured reporting, tests, CI)._
