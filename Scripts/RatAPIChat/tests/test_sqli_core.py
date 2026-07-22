"""Unit tests for the OpenAPI SQLi probe core (no network, no display)."""
import sqli_core


def test_extract_paths():
    spec = {"paths": {"/users": {}, "/orders/{id}": {}}}
    assert sqli_core.extract_paths(spec) == ["/users", "/orders/{id}"]
    assert sqli_core.extract_paths({}) == []


def test_build_test_url_encodes_payload():
    url = sqli_core.build_test_url("https://api.example.com/", "v1/users", "id", "' OR '1'='1")
    assert url.startswith("https://api.example.com/v1/users?id=")
    assert " " not in url and "'" not in url  # payload is URL-encoded


def test_build_test_url_normalizes_slashes():
    assert sqli_core.build_test_url("https://x", "/a", "p", "1") == "https://x/a?p=1"
    assert sqli_core.build_test_url("https://x/", "a", "p", "1") == "https://x/a?p=1"


def test_looks_like_sql_error_detects_signatures():
    assert sqli_core.looks_like_sql_error("You have an error in your SQL syntax near ...")
    assert sqli_core.looks_like_sql_error("Warning: mysqli_query() failed")
    assert sqli_core.looks_like_sql_error("ORA-01756: quoted string not properly terminated")


def test_looks_like_sql_error_ignores_generic_error_text():
    # The original flagged ANY response containing "error" — this must not.
    assert not sqli_core.looks_like_sql_error('{"error": "invalid credentials"}')
    assert not sqli_core.looks_like_sql_error("404 Not Found")
    assert not sqli_core.looks_like_sql_error("")


def test_total_requests():
    assert sqli_core.total_requests(3, 6) == 18
