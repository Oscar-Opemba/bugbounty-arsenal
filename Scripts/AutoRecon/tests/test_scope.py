"""Unit tests for scope enforcement and target normalization.

Pure logic — no network, no display, no external tools.
"""
import pytest

from scope import (
    normalize_target,
    parse_scope_lines,
    is_valid_hostname,
    ScopeError,
)


# ---- normalize_target ----
@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://app.example.com/login?x=1", "app.example.com"),
    ("http://app.example.com:8443", "app.example.com"),
    ("app.example.com.", "app.example.com"),
    ("  example.com  ", "example.com"),
    ("203.0.113.10", "203.0.113.10"),
])
def test_normalize_ok(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", None, "not a host", "http:// /x", "a_b.example.com"])
def test_normalize_rejects_garbage(bad):
    with pytest.raises(ValueError):
        normalize_target(bad)


def test_valid_hostname():
    assert is_valid_hostname("a.example.com")
    assert not is_valid_hostname("-bad.example.com")
    assert not is_valid_hostname("example")  # single label


# ---- scope matching ----
def _scope():
    return parse_scope_lines([
        "example.com",
        "!secret.example.com",
        "203.0.113.0/24",
        "10.0.0.5",
    ])


@pytest.mark.parametrize("host,want", [
    ("example.com", True),
    ("app.example.com", True),
    ("a.b.example.com", True),
    ("secret.example.com", False),       # excluded
    ("sub.secret.example.com", False),   # excluded subtree
    ("evil.com", False),
    ("notexample.com", False),           # suffix confusion MUST fail
    ("xexample.com", False),
    ("203.0.113.55", True),
    ("203.0.114.1", False),
    ("10.0.0.5", True),
    ("10.0.0.6", False),
    ("https://app.example.com:443/x", True),  # normalized before matching
])
def test_in_scope(host, want):
    assert _scope().is_in_scope(host) is want


def test_exclusion_beats_include_regardless_of_order():
    s = parse_scope_lines(["!secret.example.com", "example.com"])
    assert s.is_in_scope("secret.example.com") is False
    assert s.is_in_scope("other.example.com") is True


def test_comments_and_blank_lines_ignored():
    s = parse_scope_lines([
        "# a comment", "", "   ",
        "example.com   # inline comment",
    ])
    assert s.is_in_scope("x.example.com") is True


def test_all_exclusions_is_error():
    with pytest.raises(ScopeError):
        parse_scope_lines(["!a.example.com", "# nothing positive"])


def test_invalid_entry_raises():
    with pytest.raises(ScopeError):
        parse_scope_lines(["not a hostname!!"])


def test_unparseable_host_is_out_of_scope():
    # fail-closed: anything that won't normalize is not in scope
    assert _scope().is_in_scope("::::") is False
