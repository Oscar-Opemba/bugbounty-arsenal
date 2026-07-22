#!/usr/bin/env python3
"""
Subdomain Orchestrator GUI — Full version

Features:
- GUI (Tkinter) to run multiple scan jobs concurrently
- Workflows (save/load) define combinations of tools, flags, and default worker counts
- Steps: passive enumeration -> DNS brute force (gobuster) -> permutation brute force (internal) -> dedupe -> ffuf probe -> portscan (nmap/masscan)
- Per-job overrides for workers per tool
- Live logging per-job and job manager
- Results saved to results/<job_id>/

Author: The XSS Rat (style)
"""

import os
import sys
import json
import argparse
import asyncio
import threading
import subprocess
import shlex
import time
import uuid
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# Scope enforcement / target validation (pure, testable, no network).
# main.py is run as a script, so its own directory is on sys.path[0].
from scope import load_scope, normalize_target, ScopeError
from logsetup import get_job_logger
import report as report_mod
from report import RunManifest, StepResult, classify, STATUS_DRY_RUN

# ----------------------------
# Configuration / Defaults
# ----------------------------
APP_DIR = Path(__file__).parent.resolve()
RESULTS_DIR = APP_DIR / "results"
WORKFLOWS_FILE = APP_DIR / "workflows.json"
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"  # user should change if needed
DEFAULT_DNS_WORDLIST = "/usr/share/wordlists/subdomains-top1million-5000.txt"  # example for dns bruteforce

# Default tool templates - user may edit when saving workflows
# Note: these templates can include placeholders: {target}, {wordlist}, {threads}, {output}
DEFAULT_TOOLS = {
    "subfinder": {
        "cmd": "subfinder -d {target} -silent",
        "default_workers": 4
    },
    "amass": {
        "cmd": "amass enum -d {target} -passive -norecursive",
        "default_workers": 4
    },
    "assetfinder": {
        "cmd": "assetfinder --subs-only {target}",
        "default_workers": 2
    },
    "findomain": {
        "cmd": "findomain -t {target} --quiet",
        "default_workers": 4
    },
    # DNS brute with gobuster dns
    "gobuster_dns": {
        "cmd": "gobuster dns -d {target} -w {wordlist} -t {threads} -q",
        "default_workers": 20
    },
    # ffuf content discovery (simple)
    "ffuf": {
        "cmd": "ffuf -u http://{host}/FUZZ -w {wordlist} -t {threads} -mc 200 -s -o {output}",
        "default_workers": 10
    },
    # nmap scan (full TCP ports with -Pn). Rate throttled for safety:
    # --max-rate caps packets/sec so we don't behave like an accidental DoS
    # against fragile hosts. Full port coverage (-p-) is preserved.
    "nmap": {
        "cmd": "nmap -Pn -sV -p- --max-rate 500 -oA {output} {host}",
        "default_workers": 1
    },
    # masscan quick scan (optional, may require root). Rate lowered from 1000
    # to 300 pps by default; raise deliberately per-engagement if the target
    # can take it. Full port range preserved.
    "masscan": {
        "cmd": "masscan -p1-65535 {host} --rate 300 -oG {output}",
        "default_workers": 1
    }
}

# ----------------------------
# Safety defaults (Phase 1 hardening)
# ----------------------------
# Per-command wall-clock timeout (seconds). Stops a slow / tarpitting / WAF-
# blocked host from hanging a job forever. Set to 0 to disable (not advised).
DEFAULT_CMD_TIMEOUT = 1800
# Hard ceiling on concurrent external processes within a single job, regardless
# of per-tool worker counts. This is the main guard against an over-aggressive
# workflow turning into an accidental DoS.
GLOBAL_MAX_CONCURRENCY = 10
# Caps on how many discovered hosts a single job will actively probe / scan.
# Discovery can balloon into thousands of hosts; these keep active traffic sane.
MAX_FFUF_HOSTS = 75
MAX_PORTSCAN_HOSTS = 50
# Retry policy for transient failures (e.g. passive-enum APIs rate-limiting or
# a flaky resolver). A missing tool (rc 127) is never retried.
DEFAULT_RETRIES = 2
RETRY_BACKOFF_BASE = 3.0  # seconds; delay = base * 2**attempt

# Permutation generator settings (internal simple permuter)
PERMUTATION_SUFFIXES = ["dev", "test", "staging", "stage", "www", "beta", "old"]
PERMUTATION_PREFIXES = ["dev", "test", "beta", "stg", "old"]

# ----------------------------
# Utilities
# ----------------------------
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def now_str():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def run_subprocess_sync(cmd, cwd=None):
    """Run a command synchronously and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        out, err = proc.communicate()
        return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")
    except FileNotFoundError as e:
        return 127, "", str(e)

async def run_subprocess_async(cmd, cwd=None, timeout=DEFAULT_CMD_TIMEOUT):
    """
    Run a command as an asyncio subprocess and return (rc, stdout, stderr).

    Enforces a wall-clock timeout so an unreachable or deliberately slow target
    cannot hang the job. On timeout the process is killed and rc 124 is returned
    (matching GNU `timeout` convention). A missing tool surfaces as rc 127.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except FileNotFoundError as e:
        return 127, "", str(e)
    try:
        if timeout and timeout > 0:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        else:
            out, err = await proc.communicate()
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.communicate()
        except Exception:
            pass
        return 124, "", f"command timed out after {timeout}s"
    return proc.returncode, (out.decode(errors="ignore") if out else ""), (err.decode(errors="ignore") if err else "")

def safe_read_lines(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

# ----------------------------
# Workflow & Job Models
# ----------------------------
def load_workflows():
    if WORKFLOWS_FILE.exists():
        try:
            return json.loads(WORKFLOWS_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_workflows(workflows):
    WORKFLOWS_FILE.write_text(json.dumps(workflows, indent=2))

# Default single workflow (if none exist)
DEFAULT_WORKFLOW = {
    "name": "default_basic",
    "steps": [
        {"tool": "subfinder", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["subfinder"]["default_workers"]},
        {"tool": "amass", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["amass"]["default_workers"]},
        {"tool": "assetfinder", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["assetfinder"]["default_workers"]},
        {"tool": "gobuster_dns", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["gobuster_dns"]["default_workers"], "wordlist": DEFAULT_DNS_WORDLIST},
        {"tool": "permutation", "enabled": True, "flags": "", "workers": 10, "wordlist": DEFAULT_WORDLIST},
        {"tool": "ffuf", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["ffuf"]["default_workers"], "wordlist": "/usr/share/wordlists/common.txt"},
        {"tool": "nmap", "enabled": True, "flags": "", "workers": DEFAULT_TOOLS["nmap"]["default_workers"]}
    ],
    "notes": "passive -> brute -> permute -> probe -> portscan"
}

# ----------------------------
# Permutation generator (internal, simple)
# ----------------------------
def generate_permutations(base_subs, wordlist_path, max_per_domain=2000):
    """
    Very simple permuter:
    - For each discovered subdomain root (e.g. test.example.com -> test, example.com -> example)
    - For each word in small wordlist, produce prefix/suffix variants: word + base, base + word
    - Also add common prefixes/suffixes.
    This is intentionally conservative and local; replace with dnsgen/altdns for heavy lifting.
    """
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= 2000:  # limit read on big wordlists
                        break
                    w = line.strip()
                    if w:
                        words.append(w)
        except Exception:
            words = []
    else:
        words = ["dev","test","stage","beta","www","admin","portal"]

    out = set()
    for s in base_subs:
        # base without domain: take first label
        labels = s.split(".")
        if len(labels) < 2:
            continue
        base = labels[0]
        domain = ".".join(labels[1:])
        # add prefix/suffix quick combos
        for p in PERMUTATION_PREFIXES:
            out.add(f"{p}-{base}.{domain}")
            out.add(f"{p}{base}.{domain}")
        for su in PERMUTATION_SUFFIXES:
            out.add(f"{base}-{su}.{domain}")
            out.add(f"{base}{su}.{domain}")
        # words from provided list (limited)
        for w in words[:200]:  # limit to first 200 words to avoid explosion
            out.add(f"{w}-{base}.{domain}")
            out.add(f"{base}-{w}.{domain}")
            out.add(f"{w}{base}.{domain}")
            if len(out) >= max_per_domain:
                break
        if len(out) >= max_per_domain:
            break

    return sorted(out)

# ----------------------------
# Job Runner
# ----------------------------
class JobRunner:
    """
    Represents a job scan pipeline for a single target.
    Each job has its own directory in results and its own semaphores per tool based on workers.
    """

    def __init__(self, job_id, target, workflow, scope, per_tool_overrides=None,
                 gui_log_callback=None, dry_run=False, cmd_timeout=DEFAULT_CMD_TIMEOUT):
        """
        :param job_id: unique id
        :param target: domain (will be normalized and scope-checked by the caller)
        :param workflow: workflow dict (with steps)
        :param scope: Scope object; mandatory. Every host is checked against it
                      before any command runs against that host.
        :param per_tool_overrides: dict tool->workers override
        :param gui_log_callback: function(msg) for GUI logging
        :param dry_run: if True, no external command is executed — commands are
                        logged only. Used for previewing a job with zero traffic.
        :param cmd_timeout: per-command wall-clock timeout in seconds.
        """
        if scope is None:
            raise ValueError("JobRunner requires a Scope (safe-by-default)")
        self.job_id = job_id
        # Normalize defensively; the caller is expected to have validated already.
        self.target = normalize_target(target)
        self.workflow = workflow
        self.scope = scope
        self.dry_run = dry_run
        self.cmd_timeout = cmd_timeout
        self.overrides = per_tool_overrides or {}
        self.base_dir = RESULTS_DIR / f"{now_str()}_{job_id}"
        ensure_dir(self.base_dir)
        # Structured logging: stdout + per-job file, plus an optional GUI sink.
        self._gui_log = gui_log_callback
        self.logger = get_job_logger(job_id, self.base_dir)
        self.tool_semaphores = {}  # tool -> asyncio.Semaphore based on workers
        # Global concurrency ceiling across ALL tools in this job.
        self.global_sem = asyncio.Semaphore(GLOBAL_MAX_CONCURRENCY)
        self._build_semaphores()

        # internal sets
        self.discovered = set()
        self.combined_file = self.base_dir / "combined.txt"
        # Structured run record (written as run.json + steps.csv at the end).
        self.manifest = RunManifest(
            job_id=job_id, target=self.target,
            scope_source=getattr(scope, "source", "<memory>"),
            workflow=workflow.get("name", "<unnamed>"),
            dry_run=dry_run, started=datetime.now().isoformat(),
        )

    def log(self, msg):
        """Emit a line to the structured logger and the optional GUI sink."""
        self.logger.info(msg)
        if self._gui_log:
            try:
                self._gui_log(msg)
            except Exception:
                pass

    def _record(self, step: StepResult):
        self.manifest.steps.append(step)

    def _in_scope(self, host):
        """True if *host* is in scope; logs and returns False otherwise."""
        if self.scope.is_in_scope(host):
            return True
        self.log(f"[SCOPE-BLOCK] Skipping out-of-scope host: {host}")
        return False

    def _scoped_hosts(self, hosts):
        """Filter a host list down to in-scope hosts (with logging)."""
        hosts = list(hosts)
        allowed = [h for h in hosts if self._in_scope(h)]
        blocked = len(hosts) - len(allowed)
        if blocked > 0:
            self.log(f"[SCOPE] {blocked} host(s) filtered out as out-of-scope.")
        return allowed

    def plan_summary(self):
        """Human-readable preview of exactly what this job will do (no traffic)."""
        lines = [
            f"Target      : {self.target}",
            f"Scope file  : {self.scope.source}",
            f"Dry-run     : {self.dry_run}",
            f"Cmd timeout : {self.cmd_timeout}s",
            f"Caps        : max_concurrency={GLOBAL_MAX_CONCURRENCY}, "
            f"ffuf_hosts<={MAX_FFUF_HOSTS}, portscan_hosts<={MAX_PORTSCAN_HOSTS}",
            "Enabled steps:",
        ]
        for step in self.workflow.get("steps", []):
            if not step.get("enabled"):
                continue
            tool = step.get("tool")
            tmpl = DEFAULT_TOOLS.get(tool, {}).get("cmd", "(internal step)")
            lines.append(f"  - {tool:<13} {tmpl}")
        return "\n".join(lines)

    def _build_semaphores(self):
        # per-step workers
        for step in self.workflow.get("steps", []):
            tool_name = step.get("tool")
            workers = int(step.get("workers", DEFAULT_TOOLS.get(tool_name, {}).get("default_workers", 1)))
            # override by job-level overrides
            if tool_name in self.overrides:
                try:
                    workers = int(self.overrides[tool_name])
                except (ValueError, TypeError):
                    pass
            # minimum 1
            if workers < 1:
                workers = 1
            self.tool_semaphores[tool_name] = asyncio.Semaphore(workers)

    async def _run_tool_cmd(self, cmd, out_path=None, tool_name=None,
                            retries=0, host=None):
        """
        Run a single shell command, save stdout to out_path if provided, log,
        and append a structured StepResult to the run manifest.

        Retries: on a transient failure (non-zero rc that is NOT 127 "not
        found") the command is retried up to *retries* times with exponential
        backoff. A missing tool is never retried.
        """
        self.log(f"[{tool_name}] CMD: {cmd}")
        started = datetime.now()
        if self.dry_run:
            self.log("[DRY-RUN] Not executing (preview only).")
            self._record(StepResult(tool=tool_name, command=cmd, status=STATUS_DRY_RUN,
                                     started=started.isoformat(), host=host,
                                     finished=datetime.now().isoformat(), duration_s=0.0))
            return []

        attempt = 0
        rc, out, err = 127, "", ""
        while True:
            async with self.global_sem:
                rc, out, err = await run_subprocess_async(cmd, timeout=self.cmd_timeout)
            # Retry only transient failures (not a missing binary, not success).
            if rc in (0, 127) or attempt >= retries:
                break
            delay = RETRY_BACKOFF_BASE * (2 ** attempt)
            self.log(f"[{tool_name}] rc={rc}, retry {attempt + 1}/{retries} after {delay:.0f}s")
            await asyncio.sleep(delay)
            attempt += 1

        finished = datetime.now()
        if out_path:
            try:
                with open(out_path, "w", errors="ignore") as f:
                    f.write(out)
            except Exception as e:
                self.log(f"[!] Failed saving output {out_path}: {e}")
        if rc == 124:
            self.log(f"[!] {tool_name} timed out after {self.cmd_timeout}s and was killed.")
        elif rc == 127:
            self.log(f"[!] Tool not found or command failed: {err.strip()[:200]}")
        elif rc != 0:
            self.log(f"[!] {tool_name} returned code {rc}. stderr: {err.strip()[:400]}")
        else:
            self.log(f"[{tool_name}] finished, wrote {len(out.splitlines())} lines to "
                     f"{out_path if out_path else '<stdout>'}")

        self._record(StepResult(
            tool=tool_name, command=cmd, status=classify(rc), returncode=rc,
            started=started.isoformat(), finished=finished.isoformat(),
            duration_s=round((finished - started).total_seconds(), 2),
            host=host, lines_out=len(out.splitlines()) if out else 0,
            note=(err.strip()[:200] if rc not in (0,) else ""),
        ))
        return out.splitlines() if out else []

    async def run_passive_tools(self):
        """Run passive enumeration tools configured in workflow concurrently (bounded by semaphores)."""
        tasks = []
        for step in self.workflow.get("steps", []):
            if not step.get("enabled"):
                continue
            tool = step.get("tool")
            if tool in ("subfinder", "amass", "assetfinder", "findomain"):
                sem = self.tool_semaphores.get(tool, asyncio.Semaphore(1))
                # build command
                template = DEFAULT_TOOLS.get(tool, {}).get("cmd", "").strip()
                cmd = f"{template} {step.get('flags','')}".strip()
                cmd = cmd.format(target=self.target)
                out_path = self.base_dir / f"{tool}.txt"
                # create coroutine wrapper to respect semaphore
                async def run_with_sem(cmd=cmd, out_path=out_path, tool=tool, sem=sem):
                    async with sem:
                        return await self._run_tool_cmd(cmd, str(out_path), tool,
                                                        retries=DEFAULT_RETRIES)
                tasks.append(run_with_sem())
        results = []
        if tasks:
            results = await asyncio.gather(*tasks)
        # collect discovered subdomains
        for step in self.workflow.get("steps", []):
            tool = step.get("tool")
            if tool in ("subfinder", "amass", "assetfinder", "findomain"):
                path = self.base_dir / f"{tool}.txt"
                for line in safe_read_lines(path):
                    if line:
                        self.discovered.add(line.strip())
        self.log(f"[+] Passive enumeration total found: {len(self.discovered)}")
        return results

    async def run_gobuster_dns(self, step):
        """Run DNS brute force via gobuster (if enabled)"""
        tool = "gobuster_dns"
        if not step.get("enabled"):
            return []
        sem = self.tool_semaphores.get(tool, asyncio.Semaphore(1))
        wordlist = step.get("wordlist") or DEFAULT_DNS_WORDLIST
        threads = int(step.get("workers", 20))
        template = DEFAULT_TOOLS.get(tool, {}).get("cmd", "")
        cmd = template.format(target=self.target, wordlist=wordlist, threads=threads)
        out_path = self.base_dir / f"{tool}.txt"
        async with sem:
            lines = await self._run_tool_cmd(cmd, str(out_path), tool)
        # add to discovered
        for line in safe_read_lines(out_path):
            self.discovered.add(line.strip())
        self.log(f"[+] After gobuster_dns discovered: {len(self.discovered)}")
        return lines

    async def run_permutation(self, step):
        """Run permutation brute force (internal)"""
        tool = "permutation"
        if not step.get("enabled"):
            return []
        sem = self.tool_semaphores.get(tool, asyncio.Semaphore(1))
        wordlist = step.get("wordlist") or DEFAULT_WORDLIST
        # this is CPU/light IO bound - we'll just run the generator synchronously inside semaphore
        async with sem:
            sources = sorted(self.discovered)[:1000]  # limit to first 1000 discovered subdomains to avoid explosion
            self.log(f"[permutation] Generating permutations from {len(sources)} base subs (wordlist: {wordlist})")
            generated = generate_permutations(sources, wordlist, max_per_domain=1000)
            perm_path = self.base_dir / "permutations.txt"
            with open(perm_path, "w", errors="ignore") as f:
                for p in generated:
                    f.write(p + "\n")
            # we may attempt DNS resolve / check later, for now just add to discovered
            for p in generated:
                self.discovered.add(p)
            self.log(f"[permutation] Generated {len(generated)} permutations, combined total now {len(self.discovered)}")
            self._record(StepResult(
                tool="permutation", command=f"(internal permuter, wordlist={wordlist})",
                status="ok", returncode=0, lines_out=len(generated),
                finished=datetime.now().isoformat(), duration_s=0.0,
                note="local generation, no network traffic",
            ))
            return generated

    async def run_ffuf_probe(self, step):
        """
        For each discovered host (or a filtered subset), run ffuf to probe for content.
        We'll run ffuf jobs concurrently but bounded by tool semaphore.
        """
        tool = "ffuf"
        if not step.get("enabled"):
            return []
        sem = self.tool_semaphores.get(tool, asyncio.Semaphore(1))
        ffuf_wordlist = step.get("wordlist") or DEFAULT_WORDLIST
        threads = int(step.get("workers", 10))
        template = DEFAULT_TOOLS.get(tool, {}).get("cmd", "")
        # choose hosts to probe - dedupe, then enforce scope, then cap volume
        hosts = self._scoped_hosts(sorted(self.discovered))
        hosts = hosts[:MAX_FFUF_HOSTS]
        self.log(f"[ffuf] Probing {len(hosts)} in-scope hosts with ffuf (cap={MAX_FFUF_HOSTS}, wordlist={ffuf_wordlist})")
        async def run_ffuf_on_host(host):
            async with sem:
                output_name = self.base_dir / f"ffuf_{host.replace('/','_').replace(':','_')}.json"
                cmd = template.format(host=host, wordlist=ffuf_wordlist, threads=threads, output=str(output_name))
                await self._run_tool_cmd(cmd, str(output_name), "ffuf")
        tasks = [run_ffuf_on_host(h) for h in hosts]
        if tasks:
            await asyncio.gather(*tasks)
        return hosts

    async def run_portscan(self, step):
        """
        Perform a fast portscan per discovered host. Try masscan first (if present), then nmap.
        We'll run at most N concurrent portscans (controlled by semaphore).
        """
        tool_m = "masscan"
        tool_n = "nmap"
        sem_m = self.tool_semaphores.get(tool_m, asyncio.Semaphore(1))
        sem_n = self.tool_semaphores.get(tool_n, asyncio.Semaphore(1))
        workers_m = int(next((s for s in self.workflow.get("steps", []) if s.get("tool")==tool_m), {}).get("workers", 1) or 1)
        workers_n = int(next((s for s in self.workflow.get("steps", []) if s.get("tool")==tool_n), {}).get("workers", 1) or 1)

        # hosts to scan - dedupe, enforce scope, then cap volume
        hosts = self._scoped_hosts(sorted(self.discovered))
        hosts = hosts[:MAX_PORTSCAN_HOSTS]
        self.log(f"[portscan] Scanning {len(hosts)} in-scope hosts (cap={MAX_PORTSCAN_HOSTS}, "
                 f"masscan workers={workers_m}, nmap workers={workers_n})")

        async def scan_host(host):
            # Defence in depth: re-check scope right before firing at this host.
            if not self._in_scope(host):
                return
            if self.dry_run:
                self.log(f"[DRY-RUN] Would portscan {host} (masscan/nmap)")
                return
            # attempt masscan quickly (if available)
            masscan_template = DEFAULT_TOOLS.get("masscan", {}).get("cmd")
            nmap_template = DEFAULT_TOOLS.get("nmap", {}).get("cmd")
            if masscan_template:
                out_path_m = self.base_dir / f"masscan_{host}.grep"
                _t0 = datetime.now()
                async with sem_m, self.global_sem:
                    cmd_m = masscan_template.format(host=host, output=str(out_path_m))
                    rc, out, err = await run_subprocess_async(cmd_m, timeout=self.cmd_timeout)
                    if rc == 127:
                        self.log("[masscan] not installed or failed, skipping masscan")
                    elif rc == 124:
                        self.log(f"[masscan] {host} timed out after {self.cmd_timeout}s")
                    elif rc == 0 and os.path.exists(out_path_m):
                        lines = safe_read_lines(out_path_m)
                        # if masscan found open ports we can feed to nmap; else fallback to nmap full
                        self.log(f"[masscan] {host} scan wrote {len(lines)} lines")
                self._record(StepResult(
                    tool="masscan", command=cmd_m, status=classify(rc), returncode=rc,
                    started=_t0.isoformat(), finished=datetime.now().isoformat(),
                    duration_s=round((datetime.now() - _t0).total_seconds(), 2), host=host,
                    note=(err.strip()[:200] if rc not in (0,) else "")))
            # always run nmap (some hosts may not require masscan)
            out_path_n = self.base_dir / f"nmap_{host}"
            _t1 = datetime.now()
            async with sem_n, self.global_sem:
                cmd_n = nmap_template.format(output=str(out_path_n), host=host)
                rc, out, err = await run_subprocess_async(cmd_n, timeout=self.cmd_timeout)
                if rc == 127:
                    self.log("[nmap] not installed or failed")
                elif rc == 124:
                    self.log(f"[nmap] {host} timed out after {self.cmd_timeout}s")
                else:
                    self.log(f"[nmap] scanned {host} (rc={rc})")
            self._record(StepResult(
                tool="nmap", command=cmd_n, status=classify(rc), returncode=rc,
                started=_t1.isoformat(), finished=datetime.now().isoformat(),
                duration_s=round((datetime.now() - _t1).total_seconds(), 2), host=host,
                note=(err.strip()[:200] if rc not in (0,) else "")))
        # run with concurrency limited by semaphores controlling masscan/nmap combined
        tasks = [scan_host(h) for h in hosts]
        if tasks:
            await asyncio.gather(*tasks)
        return hosts

    def write_combined_results(self):
        ensure_dir(self.base_dir)
        with open(self.combined_file, "w", errors="ignore") as f:
            for s in sorted(self.discovered):
                f.write(s + "\n")
        self.log(f"[+] Combined results saved to {self.combined_file} ({len(self.discovered)} unique)")

    async def run_pipeline(self):
        """
        Full pipeline orchestration.
        Steps in order: passive -> gobuster_dns -> permutation -> dedupe (write) -> ffuf -> portscan
        """
        try:
            self.log(f"=== START JOB {self.job_id} target={self.target} at {datetime.now().isoformat()} ===")

            # passive enumeration
            await self.run_passive_tools()

            # DNS brute force / gobuster
            gob_step = next((s for s in self.workflow.get("steps", []) if s.get("tool")=="gobuster_dns"), None)
            if gob_step:
                await self.run_gobuster_dns(gob_step)

            # permutation
            perm_step = next((s for s in self.workflow.get("steps", []) if s.get("tool")=="permutation"), None)
            if perm_step:
                await self.run_permutation(perm_step)

            # write combined
            self.write_combined_results()

            # ffuf probing
            ffuf_step = next((s for s in self.workflow.get("steps", []) if s.get("tool")=="ffuf"), None)
            if ffuf_step:
                await self.run_ffuf_probe(ffuf_step)

            # portscan
            port_step = next((s for s in self.workflow.get("steps", []) if s.get("tool") in ("masscan","nmap")), None)
            if port_step:
                await self.run_portscan(port_step)

            self.log(f"=== JOB {self.job_id} COMPLETE: {len(self.discovered)} unique subdomains. Results: {self.base_dir} ===")
        except Exception as e:
            self.log(f"[!!!] Job {self.job_id} failed: {e}")
        finally:
            self._finalize_manifest()

    def _finalize_manifest(self):
        """Write the structured run.json + steps.csv for this job."""
        try:
            self.manifest.finished = datetime.now().isoformat()
            self.manifest.discovered = sorted(self.discovered)
            report_mod.write_json(self.manifest, self.base_dir / "run.json")
            report_mod.write_steps_csv(self.manifest.steps, self.base_dir / "steps.csv")
            report_mod.write_html(self.manifest, self.base_dir / "report.html")
            self.log(f"[+] Wrote reports: run.json, steps.csv, report.html in {self.base_dir}")
        except Exception as e:
            self.log(f"[!] Failed writing run manifest: {e}")

# ----------------------------
# GUI
# ----------------------------
class OrchestratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Subdomain Orchestrator — The XSS Rat")
        self.workflows = load_workflows() or {"default_basic": DEFAULT_WORKFLOW}
        if not self.workflows:
            self.workflows = {"default_basic": DEFAULT_WORKFLOW}
        self._jobs = {}  # job_id -> dict with runner, thread, status
        self._build_ui()

    def _build_ui(self):
        # top frame: workflow selection
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=6, pady=6)

        ttk.Label(top, text="Workflow:").grid(row=0, column=0, sticky="w")
        self.workflow_combo = ttk.Combobox(top, values=list(self.workflows.keys()))
        self.workflow_combo.grid(row=0, column=1, sticky="ew", padx=4)
        self.workflow_combo.set(list(self.workflows.keys())[0])
        ttk.Button(top, text="Edit Workflow", command=self.edit_workflow).grid(row=0, column=2, padx=4)
        ttk.Button(top, text="Save Workflow As...", command=self.save_workflow_as).grid(row=0, column=3, padx=4)
        ttk.Button(top, text="Reload Workflows", command=self.reload_workflows).grid(row=0, column=4, padx=4)

        # middle: target input and per-tool worker overrides
        mid = ttk.Frame(self.root)
        mid.pack(fill="x", padx=6, pady=6)

        ttk.Label(mid, text="Target domain:").grid(row=0, column=0, sticky="w")
        self.target_entry = ttk.Entry(mid)
        self.target_entry.grid(row=0, column=1, sticky="ew", columnspan=3, padx=4)

        ttk.Label(mid, text="Job name (optional):").grid(row=1, column=0, sticky="w")
        self.jobname_entry = ttk.Entry(mid)
        self.jobname_entry.grid(row=1, column=1, sticky="ew", columnspan=3, padx=4)

        # per-tool overrides
        ttk.Label(mid, text="Per-tool worker overrides (tool:workers comma-separated):").grid(row=2, column=0, columnspan=4, sticky="w")
        self.overrides_entry = ttk.Entry(mid)
        self.overrides_entry.grid(row=3, column=0, columnspan=4, sticky="ew", padx=4)

        # scope file (REQUIRED — no job runs without it)
        ttk.Label(mid, text="Scope file (required):").grid(row=4, column=0, sticky="w")
        self.scope_entry = ttk.Entry(mid)
        self.scope_entry.grid(row=4, column=1, columnspan=2, sticky="ew", padx=4)
        ttk.Button(mid, text="Browse...", command=self.browse_scope).grid(row=4, column=3, padx=4)
        # default to a scope.txt next to this script if present
        default_scope = APP_DIR / "scope.txt"
        if default_scope.exists():
            self.scope_entry.insert(0, str(default_scope))

        # job control buttons
        controls = ttk.Frame(self.root)
        controls.pack(fill="x", padx=6, pady=6)
        ttk.Button(controls, text="Start Job", command=self.start_job).pack(side="left")
        ttk.Button(controls, text="Start Multiple Jobs (batch from file)", command=self.start_jobs_from_file).pack(side="left", padx=4)
        ttk.Button(controls, text="Stop Selected Job", command=self.stop_selected_job).pack(side="left", padx=4)
        ttk.Button(controls, text="Open Results Dir", command=self.open_results_dir).pack(side="left", padx=4)
        # Dry-run defaults ON: safe-by-default, sends zero traffic until unchecked.
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Dry run (preview only, no traffic)",
                        variable=self.dry_run_var).pack(side="left", padx=12)

        # bottom: job list and logs
        bottom = ttk.PanedWindow(self.root, orient="horizontal")
        bottom.pack(fill="both", expand=True, padx=6, pady=6)

        # left: job table
        left = ttk.Frame(bottom)
        bottom.add(left, weight=1)
        ttk.Label(left, text="Jobs:").pack(anchor="w")
        self.jobs_tree = ttk.Treeview(left, columns=("id","target","status","started"), show="headings", selectmode="browse")
        for c in ("id","target","status","started"):
            self.jobs_tree.heading(c, text=c)
            self.jobs_tree.column(c, width=150, anchor="w")
        self.jobs_tree.pack(fill="both", expand=True)
        self.jobs_tree.bind("<<TreeviewSelect>>", self.on_job_select)

        # right: log output
        right = ttk.Frame(bottom)
        bottom.add(right, weight=3)
        ttk.Label(right, text="Log:").pack(anchor="w")
        self.log_text = tk.Text(right, height=30, bg="#111", fg="#0f0", insertbackground="white")
        self.log_text.pack(fill="both", expand=True)

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        print(msg)

    def reload_workflows(self):
        self.workflows = load_workflows() or {"default_basic": DEFAULT_WORKFLOW}
        self.workflow_combo['values'] = list(self.workflows.keys())
        self.log("[+] Workflows reloaded.")

    def edit_workflow(self):
        name = self.workflow_combo.get()
        if name not in self.workflows:
            messagebox.showerror("Error", "Workflow not found")
            return
        wf = self.workflows[name]
        # open a simple editor dialog (JSON)
        txt = json.dumps(wf, indent=2)
        editor = tk.Toplevel(self.root)
        editor.title(f"Edit workflow: {name}")
        text = tk.Text(editor, width=100, height=40)
        text.pack(fill="both", expand=True)
        text.insert("1.0", txt)
        def save_and_close():
            try:
                new = json.loads(text.get("1.0","end"))
                self.workflows[name] = new
                save_workflows(self.workflows)
                self.reload_workflows()
                editor.destroy()
                self.log(f"[+] Workflow {name} updated.")
            except Exception as e:
                messagebox.showerror("JSON error", str(e))
        ttk.Button(editor, text="Save", command=save_and_close).pack()

    def save_workflow_as(self):
        # save current selected workflow under a new name (file dialog)
        name = self.workflow_combo.get()
        if name not in self.workflows:
            messagebox.showerror("Error", "Workflow not found")
            return
        wf = self.workflows[name]
        newname = simpledialog.askstring("Save Workflow As", "New workflow name:")
        if not newname:
            return
        wf_copy = dict(wf)
        wf_copy["name"] = newname
        self.workflows[newname] = wf_copy
        save_workflows(self.workflows)
        self.reload_workflows()
        self.log(f"[+] Workflow saved as {newname}")

    def parse_overrides(self, text):
        """Parse 'tool:workers,tool2:workers' style input into dict."""
        out = {}
        if not text:
            return out
        parts = text.split(",")
        for p in parts:
            if ":" in p:
                t,w = p.split(":",1)
                try:
                    out[t.strip()] = int(w.strip())
                except (ValueError, TypeError):
                    pass
        return out

    def browse_scope(self):
        path = filedialog.askopenfilename(
            title="Select scope file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.scope_entry.delete(0, "end")
            self.scope_entry.insert(0, path)

    def start_job(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter a target domain")
            return

        # --- Scope is mandatory (safe-by-default) ---
        scope_path = self.scope_entry.get().strip()
        if not scope_path:
            messagebox.showerror(
                "Scope required",
                "A scope file is required before any job can run.\n\n"
                "Copy scope.example.txt to scope.txt, add your authorized "
                "targets, and select it here.",
            )
            return
        try:
            scope = load_scope(scope_path)
        except ScopeError as e:
            messagebox.showerror("Invalid scope file", str(e))
            return

        # --- Validate + normalize the target, and confirm it is in scope ---
        try:
            target = normalize_target(target)
        except ValueError as e:
            messagebox.showerror("Invalid target", f"{e}")
            return
        if not scope.is_in_scope(target):
            messagebox.showerror(
                "Target out of scope",
                f"Target '{target}' does not match any include rule in\n"
                f"{scope.source}.\n\nRefusing to run.",
            )
            return

        workflow_name = self.workflow_combo.get()
        if workflow_name not in self.workflows:
            messagebox.showerror("Error", "Select a valid workflow")
            return
        workflow = self.workflows[workflow_name]
        job_id = (self.jobname_entry.get().strip() or f"job_{uuid.uuid4().hex[:6]}")
        overrides = self.parse_overrides(self.overrides_entry.get().strip())
        dry_run = bool(self.dry_run_var.get())
        # create runner
        job_runner = JobRunner(job_id=job_id, target=target, workflow=workflow, scope=scope,
                               per_tool_overrides=overrides, dry_run=dry_run,
                               gui_log_callback=lambda m, jid=job_id: self.job_log(jid, m))

        # --- Explicit confirmation before sending any live traffic ---
        if not dry_run:
            proceed = messagebox.askokcancel(
                "Confirm LIVE run",
                job_runner.plan_summary()
                + "\n\nThis will send LIVE traffic to the target above.\nProceed?",
                icon="warning",
            )
            if not proceed:
                self.log(f"[i] Job for {target} cancelled by user at confirmation.")
                return
        # create asyncio thread to run pipeline (wrap in thread to not block)
        def run_in_thread(runner: JobRunner):
            asyncio.run(runner.run_pipeline())
            self._jobs[job_id]["status"] = "finished"
            self.update_job_row(job_id)
        # insert job into table
        started = datetime.now().isoformat()
        self._jobs[job_id] = {"runner": job_runner, "thread": None, "status": "running", "started": started}
        self.jobs_tree.insert("", "end", iid=job_id, values=(job_id, target, "running", started))
        # start thread
        t = threading.Thread(target=run_in_thread, args=(job_runner,), daemon=True)
        self._jobs[job_id]["thread"] = t
        t.start()
        self.log(f"[+] Job {job_id} started for {target}")

    def start_jobs_from_file(self):
        """
        Accept a simple text file where each line is:
        target,workflow_name,overrides
        overrides example: gobuster_dns:30,ffuf:8
        """
        path = filedialog.askopenfilename(title="Select batch file (.txt)", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path:
            return
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                target = parts[0]
                workflow_name = parts[1] if len(parts) > 1 else self.workflow_combo.get()
                overrides = parts[2] if len(parts) > 2 else ""
                self.target_entry.delete(0, "end")
                self.target_entry.insert(0, target)
                self.workflow_combo.set(workflow_name)
                self.overrides_entry.delete(0, "end")
                self.overrides_entry.insert(0, overrides)
                self.start_job()
                time.sleep(0.2)

    def stop_selected_job(self):
        sel = self.jobs_tree.selection()
        if not sel:
            messagebox.showerror("Error", "Select a job in the list")
            return
        jid = sel[0]
        job = self._jobs.get(jid)
        if not job:
            messagebox.showerror("Error", "Job not found")
            return
        # we cannot reliably kill asyncio tasks started in subprocesses from python without tracking PIDs.
        # as a best-effort, mark as stopping and attempt to join thread (user may have to manually kill tool processes)
        job["status"] = "stopping"
        self.update_job_row(jid)
        self.log(f"[!] Stopping job {jid} — best effort (may not kill external tool processes).")

    def open_results_dir(self):
        ensure_dir(RESULTS_DIR)
        # open file explorer - platform-specific
        import webbrowser
        import sys
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", str(RESULTS_DIR)])
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", str(RESULTS_DIR)])
        elif sys.platform.startswith("win"):
            os.startfile(str(RESULTS_DIR))
        else:
            webbrowser.open(str(RESULTS_DIR))

    def on_job_select(self, event):
        sel = self.jobs_tree.selection()
        if not sel:
            return
        jid = sel[0]
        self.show_job_logs(jid)

    def update_job_row(self, job_id):
        job = self._jobs.get(job_id)
        if not job:
            return
        status = job.get("status","running")
        self.jobs_tree.item(job_id, values=(job_id, job["runner"].target if job.get("runner") else "", status, job.get("started","")))

    def job_log(self, job_id, msg):
        self.log(f"[{job_id}] {msg}")

    def show_job_logs(self, job_id):
        # show combined file if exists
        job = self._jobs.get(job_id)
        if not job:
            return
        runner = job.get("runner")
        if not runner:
            return
        self.log_text.delete("1.0","end")
        self.log_text.insert("end", f"==== Logs for job {job_id} (target: {runner.target}) ====\n")
        # show files present in results dir
        for path in sorted(runner.base_dir.glob("*")):
            self.log_text.insert("end", f"-- {path.name} --\n")
            # show small files
            if path.is_file() and path.stat().st_size < 200000:
                try:
                    with open(path, "r", errors="ignore") as f:
                        data = f.read()
                    self.log_text.insert("end", data + "\n\n")
                except Exception as e:
                    self.log_text.insert("end", f"[Could not read file: {e}]\n")
            else:
                self.log_text.insert("end", "[File too large to display or not readable]\n\n")
        self.log_text.see("end")

# ----------------------------
# CLI (headless) entrypoint
# ----------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="autorecon",
        description="AutoRecon — subdomain recon orchestrator (GUI by default; "
                    "headless with --target/--scope).",
    )
    p.add_argument("--target", help="Target apex domain or host (headless mode).")
    p.add_argument("--scope", help="Path to scope file. REQUIRED to run a job.")
    p.add_argument("--workflow", default="default_basic",
                   help="Workflow name from workflows.json (default: default_basic).")
    p.add_argument("--dry-run", action="store_true",
                   help="Preview the plan and resolved commands without sending any traffic.")
    p.add_argument("--no-gui", action="store_true",
                   help="Force headless mode (requires --target and --scope).")
    p.add_argument("--cmd-timeout", type=int, default=DEFAULT_CMD_TIMEOUT,
                   help=f"Per-command timeout in seconds (default: {DEFAULT_CMD_TIMEOUT}).")
    p.add_argument("--yes", action="store_true",
                   help="Skip the interactive live-run confirmation (use with care).")
    return p


def run_headless(args):
    """Run a single job without the GUI. Returns a process exit code."""
    try:
        scope = load_scope(args.scope)
    except ScopeError as e:
        print(f"[SCOPE] {e}", file=sys.stderr)
        return 2
    try:
        target = normalize_target(args.target)
    except ValueError as e:
        print(f"[TARGET] invalid target: {e}", file=sys.stderr)
        return 2
    if not scope.is_in_scope(target):
        print(f"[SCOPE] Refusing: target '{target}' is not in scope ({scope.source}).",
              file=sys.stderr)
        return 2

    workflows = load_workflows() or {"default_basic": DEFAULT_WORKFLOW}
    workflow = workflows.get(args.workflow)
    if workflow is None:
        print(f"[WORKFLOW] unknown workflow '{args.workflow}'. "
              f"Available: {', '.join(workflows)}", file=sys.stderr)
        return 2

    job_id = f"cli_{uuid.uuid4().hex[:6]}"
    runner = JobRunner(job_id=job_id, target=target, workflow=workflow, scope=scope,
                       dry_run=args.dry_run, cmd_timeout=args.cmd_timeout)
    print(runner.plan_summary())

    if not args.dry_run and not args.yes:
        try:
            resp = input("\nSend LIVE traffic to the target above? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp != "y":
            print("Aborted (no confirmation).")
            return 1

    asyncio.run(runner.run_pipeline())
    return 0


# ----------------------------
# Main
# ----------------------------
def main():
    args = build_arg_parser().parse_args()
    ensure_dir(RESULTS_DIR)
    # ensure workflows file exists
    if not load_workflows():
        save_workflows({"default_basic": DEFAULT_WORKFLOW})

    # Headless if explicitly requested or a target was given on the CLI.
    if args.no_gui or args.target:
        if not args.target or not args.scope:
            print("Headless mode requires both --target and --scope.", file=sys.stderr)
            sys.exit(2)
        sys.exit(run_headless(args))

    root = tk.Tk()
    OrchestratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
