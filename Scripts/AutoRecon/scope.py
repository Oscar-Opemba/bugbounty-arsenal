"""
Scope enforcement and target validation for AutoRecon.

Safe-by-default design: a recon job cannot run unless every host it would touch
matches an entry in an explicit scope file. This module is deliberately *pure* —
no tkinter, no network, no subprocess — so it can be unit-tested without a
display and without touching live infrastructure.

Scope file format (one rule per line; '#' starts a comment, inline or full-line):

    example.com          # this apex AND any subdomain (*.example.com)
    .example.com         # same as above (explicit leading-dot form)
    app.example.com      # this host and its subdomains
    !test.example.com    # EXCLUSION: never in scope, even if a broader rule matches
    203.0.113.10         # a single IP address
    203.0.113.0/24       # a CIDR range

Matching is case-insensitive. Exclusions (lines starting with '!') always win.
A scope with no positive (non-exclusion) entries is rejected — an all-exclude
file would authorize nothing and is almost certainly a mistake.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# RFC 1035-style label: 1-63 chars, no leading/trailing hyphen.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^({_LABEL}\.)+{_LABEL}$")


class ScopeError(Exception):
    """Raised when a scope file is missing, empty, or malformed."""


def is_valid_hostname(name: str) -> bool:
    """True if *name* is a syntactically valid multi-label hostname."""
    if not name or len(name) > 253:
        return False
    return bool(_HOSTNAME_RE.match(name))


def normalize_target(raw: str) -> str:
    """
    Reduce a user-supplied target to a bare hostname or IP.

    Strips scheme, port, path/query, surrounding whitespace and any trailing
    dot, and lowercases the result. Raises ValueError if what remains is not a
    valid hostname or IP address — this is the first line of defence against
    typos and copy-paste accidents firing traffic at the wrong host.
    """
    if raw is None:
        raise ValueError("empty target")
    t = raw.strip().lower()
    if not t:
        raise ValueError("empty target")
    # strip URL scheme (http://, https://, ftp://, ...)
    t = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", t)
    # drop path and query
    t = t.split("/", 1)[0].split("?", 1)[0]
    # drop a trailing :port for the simple host:port case (bracketed IPv6 unsupported)
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    t = t.rstrip(".")
    if not t:
        raise ValueError("target reduced to empty after normalization")
    # Is it an IP literal?
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if is_valid_hostname(t):
        return t
    raise ValueError(f"not a valid hostname or IP: {raw!r}")


@dataclass
class _Rule:
    raw: str
    exclude: bool
    kind: str  # 'host' | 'net'
    host: Optional[str] = None
    net: Optional[object] = None  # ipaddress.ip_network

    def matches(self, host: str) -> bool:
        if self.kind == "net":
            try:
                return ipaddress.ip_address(host) in self.net
            except ValueError:
                return False
        h = host.lower().rstrip(".")
        base = self.host
        # exact host, or a subdomain of the rule
        return h == base or h.endswith("." + base)


@dataclass
class Scope:
    rules: List[_Rule] = field(default_factory=list)
    source: str = "<memory>"

    @property
    def includes(self) -> List[_Rule]:
        return [r for r in self.rules if not r.exclude]

    def is_in_scope(self, target: str) -> bool:
        """
        True only if *target* normalizes cleanly AND matches at least one
        include rule AND matches no exclude rule. Anything that fails to
        normalize is treated as out of scope (fail closed).
        """
        try:
            host = normalize_target(target)
        except ValueError:
            return False
        for r in self.rules:  # exclusions win
            if r.exclude and r.matches(host):
                return False
        for r in self.rules:
            if not r.exclude and r.matches(host):
                return True
        return False


def _parse_rule(line: str) -> _Rule:
    raw = line.strip()
    exclude = raw.startswith("!")
    body = raw[1:].strip() if exclude else raw
    body = body.lstrip(".")  # ".example.com" -> "example.com"
    # CIDR range
    if "/" in body:
        try:
            net = ipaddress.ip_network(body, strict=False)
        except ValueError as e:
            raise ScopeError(f"invalid CIDR in scope entry {line!r}: {e}") from e
        return _Rule(raw=raw, exclude=exclude, kind="net", net=net)
    # bare IP -> host-net for uniform matching
    try:
        ip = ipaddress.ip_address(body)
        prefix = 32 if ip.version == 4 else 128
        net = ipaddress.ip_network(f"{body}/{prefix}", strict=False)
        return _Rule(raw=raw, exclude=exclude, kind="net", net=net)
    except ValueError:
        pass
    if not is_valid_hostname(body):
        raise ScopeError(f"invalid scope entry: {line!r}")
    return _Rule(raw=raw, exclude=exclude, kind="host", host=body.lower())


def parse_scope_lines(lines) -> Scope:
    """Parse an iterable of scope-file lines into a Scope. Raises ScopeError."""
    rules: List[_Rule] = []
    for line in lines:
        s = line.split("#", 1)[0].strip()  # strip inline/full comments
        if not s:
            continue
        rules.append(_parse_rule(s))
    if not any(not r.exclude for r in rules):
        raise ScopeError("scope contains no in-scope entries (only comments/exclusions)")
    return Scope(rules=rules)


def load_scope(path) -> Scope:
    """Load and validate a scope file from *path*. Raises ScopeError."""
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file not found: {path}")
    scope = parse_scope_lines(p.read_text(errors="ignore").splitlines())
    scope.source = str(p)
    return scope
