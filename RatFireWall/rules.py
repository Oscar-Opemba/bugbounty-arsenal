"""
RatFireWall rule engine (pure, testable — no mitmproxy, no network).

A small request/response inspection engine for the RatFireWall blocking proxy.
This is a *starter / lab* WAF: the signatures are deliberately simple and are
trivially bypassable (see the README). Its value is as a teaching/testing proxy,
not a production web application firewall.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional


@dataclass
class RequestCtx:
    method: str
    url: str
    headers: dict   # keys should be lowercased by the caller
    body: str


@dataclass
class ResponseCtx:
    status: int
    headers: dict   # keys should be lowercased by the caller
    body: str


@dataclass
class Rule:
    name: str
    scope: str                    # "request" or "response"
    predicate: Callable           # ctx -> truthy means BLOCK

    def blocks(self, ctx) -> bool:
        try:
            return bool(self.predicate(ctx))
        except Exception:
            # A faulty rule must never crash the proxy; treat as "no match".
            return False


# ---- predicate builders ----
def header_contains(header: str, needle: str) -> Callable:
    h, n = header.lower(), needle.lower()
    return lambda ctx: n in str(ctx.headers.get(h, "")).lower()


def missing_header(header: str) -> Callable:
    h = header.lower()
    return lambda ctx: h not in ctx.headers


def request_matches(pattern: str) -> Callable:
    """Match a regex against the request URL and body together."""
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda ctx: bool(rx.search(ctx.url or "")) or bool(rx.search(ctx.body or ""))


def response_matches(pattern: str) -> Callable:
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda ctx: bool(rx.search(ctx.body or ""))


def body_larger_than(n: int) -> Callable:
    return lambda ctx: len(ctx.body or "") > n


# ---- signature patterns (simple, lab-grade) ----
XSS_RE = r"<script\b|onerror\s*=|javascript:"
SQLI_RE = r"(?:'|%27)\s*(?:or|and)\s+\d|union\s+select|;\s*drop\s+table\b"
TRAVERSAL_RE = r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/"
CMDI_RE = r";\s*(?:cat|ls|whoami|id|uname)\b|\|\s*(?:nc|bash|sh|curl|wget)\b"
XXE_RE = r"<!ENTITY\b|SYSTEM\s+[\"']file:"


def default_request_rules(max_body: int = 1_000_000,
                          blocked_user_agents=("sqlmap", "nikto", "nmap")) -> List[Rule]:
    rules = [
        Rule("Block <script>/XSS in request", "request", request_matches(XSS_RE)),
        Rule("Block SQLi patterns", "request", request_matches(SQLI_RE)),
        Rule("Block path traversal", "request", request_matches(TRAVERSAL_RE)),
        Rule("Block command-injection patterns", "request", request_matches(CMDI_RE)),
        Rule("Block XXE patterns", "request", request_matches(XXE_RE)),
        Rule("Block oversized request body", "request", body_larger_than(max_body)),
    ]
    for ua in blocked_user_agents:
        rules.append(Rule(f"Block scanner UA: {ua}", "request", header_contains("user-agent", ua)))
    return rules


def default_response_rules() -> List[Rule]:
    # Prevent obvious secret leakage in responses (mirrors the original intent).
    return [
        Rule("Block secret-leaking response", "response",
             response_matches(r"\b(password|api[-_]?key|secret|private[-_]?key)\b")),
    ]


def evaluate(ctx, rules: List[Rule]) -> Optional[str]:
    """Return the name of the first rule that blocks *ctx*, else None."""
    for rule in rules:
        if rule.blocks(ctx):
            return rule.name
    return None
