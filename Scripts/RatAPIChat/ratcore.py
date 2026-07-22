"""
Pure, testable core for RatAPIChat.

No tkinter, no live network — just the request-building, rate-limiting, URL,
redaction and Swagger-parsing logic. Keeping this separate lets the fiddly bits
be unit-tested without a display or hitting a real target.
"""
from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlparse

# Keys whose values must never be written to disk in cleartext.
SENSITIVE_KEYS = {"auth_token", "authorization", "password", "token", "cookie", "api_key"}

REDACTED = "<redacted>"


class RateLimiter:
    """
    Enforce a minimum interval between calls (a requests-per-second cap).

    Deterministic and injectable (sleep/clock) so throttling can be unit-tested.
    This is the throttle the original tool advertised but never actually applied.
    """

    def __init__(self, rate_per_sec: float = 1.0, sleep=time.sleep, clock=time.monotonic):
        self._sleep = sleep
        self._clock = clock
        self._last = None
        self.set_rate(rate_per_sec)

    def set_rate(self, rate_per_sec) -> None:
        try:
            r = float(rate_per_sec)
        except (TypeError, ValueError):
            r = 1.0
        if r <= 0:
            r = 1.0
        self.rate = r
        self.min_interval = 1.0 / r

    def wait(self) -> float:
        """Block until the next call is allowed. Returns the slept duration."""
        now = self._clock()
        slept = 0.0
        if self._last is not None:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                slept = remaining
                now = self._clock()
        self._last = now
        return slept


def split_url(full_url: str):
    """
    Split a full URL into (base, endpoint) where base + endpoint == full_url.

    Robust against a missing scheme (the original string-split crashed / mangled
    URLs without 'http://').
    """
    p = urlparse(full_url)
    if p.scheme and p.netloc:
        base = f"{p.scheme}://{p.netloc}"
        return base, full_url[len(base):]
    return full_url, ""


def host_of(url: str) -> str:
    """Return the lowercase hostname of a URL (no port, no userinfo)."""
    netloc = urlparse(url).netloc or urlparse("//" + url).netloc
    return netloc.split("@")[-1].split(":")[0].lower()


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


class BodyParseError(ValueError):
    """Raised when a request body cannot be parsed for the chosen content type."""


def build_request(method: str, base_url: str, endpoint: str, *,
                  auth_type=None, token=None, username=None, password=None,
                  content_type="JSON", body="", fuzz_value=None) -> dict:
    """
    Build the kwargs for requests.request from raw field values. Pure.

    Returns {full_url, headers, data, json}. Raises BodyParseError on invalid
    JSON so the caller can surface a clean message instead of a stack trace.
    """
    full_url = base_url + endpoint
    headers: dict = {}

    if auth_type == "Basic":
        headers["Authorization"] = basic_auth_header(username or "", password or "")
    elif auth_type in ("Bearer", "OAuth 2.0"):
        if token:
            headers["Authorization"] = f"Bearer {token}"

    if fuzz_value is not None:
        body = body.replace("FUZZ", fuzz_value)

    data = None
    json_data = None
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        if content_type == "JSON":
            headers["Content-Type"] = "application/json"
            if body.strip():
                try:
                    json_data = json.loads(body)
                except json.JSONDecodeError as e:
                    raise BodyParseError(f"Invalid JSON body: {e}") from e
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            # split on the FIRST '=' only so values containing '=' survive
            data = dict(item.split("=", 1) for item in body.split("&") if "=" in item)

    return {"full_url": full_url, "headers": headers, "data": data, "json": json_data}


def redact_entry(entry: dict, redact: bool = True) -> dict:
    """Return a shallow copy of *entry* with sensitive values masked (if redact)."""
    e = dict(entry)
    if redact:
        for k in list(e.keys()):
            if k.lower() in SENSITIVE_KEYS and e[k]:
                e[k] = REDACTED
    return e


def parse_swagger_endpoints(swagger: dict):
    """Return (endpoints, endpoint_data) from an OpenAPI/Swagger dict. Pure."""
    endpoints = []
    data = {}
    for path, methods in (swagger.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            key = f"{method.upper()} {path}"
            endpoints.append(key)
            data[key] = details
    return endpoints, data
