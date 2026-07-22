"""Unit tests for the pure RatAPIChat core (no network, no display)."""
import pytest

import ratcore
from ratcore import RateLimiter, build_request, BodyParseError


# ---- RateLimiter (the throttle the original tool never applied) ----
def test_rate_limiter_sleeps_to_meet_interval():
    slept = []
    clock = {"t": 0.0}
    rl = RateLimiter(2.0, sleep=lambda s: slept.append(s), clock=lambda: clock["t"])
    rl.wait()          # first call: no wait
    assert slept == []
    rl.wait()          # immediately after: must sleep ~0.5s (2 rps -> 0.5s interval)
    assert slept and abs(slept[0] - 0.5) < 1e-9


def test_rate_limiter_no_sleep_if_enough_time_passed():
    slept = []
    clock = {"t": 0.0}
    rl = RateLimiter(1.0, sleep=lambda s: slept.append(s), clock=lambda: clock["t"])
    rl.wait()
    clock["t"] = 5.0   # plenty of time later
    rl.wait()
    assert slept == []


@pytest.mark.parametrize("bad", [0, -3, "x", None])
def test_rate_limiter_bad_rate_defaults_to_1(bad):
    rl = RateLimiter(bad)
    assert rl.rate == 1.0 and rl.min_interval == 1.0


# ---- split_url / host_of ----
@pytest.mark.parametrize("url,base,ep", [
    ("https://api.example.com/v1/users", "https://api.example.com", "/v1/users"),
    ("http://h:8080/x?y=1", "http://h:8080", "/x?y=1"),
    ("no-scheme.example.com/x", "no-scheme.example.com/x", ""),
])
def test_split_url(url, base, ep):
    assert ratcore.split_url(url) == (base, ep)


def test_split_url_roundtrip():
    b, e = ratcore.split_url("https://api.example.com/a/b")
    assert b + e == "https://api.example.com/a/b"


def test_host_of():
    assert ratcore.host_of("https://user:pw@API.Example.com:443/x") == "api.example.com"


# ---- build_request ----
def test_build_request_bearer_and_json_body():
    r = build_request("POST", "https://api.example.com", "/login",
                      auth_type="Bearer", token="abc", content_type="JSON",
                      body='{"a": 1}')
    assert r["full_url"] == "https://api.example.com/login"
    assert r["headers"]["Authorization"] == "Bearer abc"
    assert r["headers"]["Content-Type"] == "application/json"
    assert r["json"] == {"a": 1}


def test_build_request_basic_auth():
    r = build_request("GET", "https://x", "/", auth_type="Basic",
                      username="u", password="p")
    # base64("u:p") == "dTpw"
    assert r["headers"]["Authorization"] == "Basic dTpw"


def test_build_request_form_data_preserves_equals_in_value():
    r = build_request("POST", "https://x", "/", content_type="Form Data",
                      body="token=a=b=c&x=1")
    assert r["data"] == {"token": "a=b=c", "x": "1"}


def test_build_request_empty_json_body_is_not_parsed():
    r = build_request("POST", "https://x", "/", content_type="JSON", body="   ")
    assert r["json"] is None  # no crash on empty body


def test_build_request_invalid_json_raises_clean_error():
    with pytest.raises(BodyParseError):
        build_request("POST", "https://x", "/", content_type="JSON", body="{not json}")


def test_build_request_fuzz_substitution():
    r = build_request("POST", "https://x", "/", content_type="JSON",
                      body='{"q": "FUZZ"}', fuzz_value="payload")
    assert r["json"] == {"q": "payload"}


def test_get_with_no_token_has_no_auth_header():
    r = build_request("GET", "https://x", "/", auth_type="Bearer", token="")
    assert "Authorization" not in r["headers"]


# ---- redaction ----
def test_redact_entry_masks_secrets():
    e = {"url": "https://x/", "auth_token": "supersecret", "method": "GET"}
    red = ratcore.redact_entry(e)
    assert red["auth_token"] == ratcore.REDACTED
    assert red["url"] == "https://x/"
    # original not mutated
    assert e["auth_token"] == "supersecret"


def test_redact_entry_can_be_disabled():
    e = {"auth_token": "s"}
    assert ratcore.redact_entry(e, redact=False)["auth_token"] == "s"


# ---- swagger ----
def test_parse_swagger_endpoints():
    spec = {"paths": {"/users": {"get": {"x": 1}, "post": {"y": 2}}}}
    eps, data = ratcore.parse_swagger_endpoints(spec)
    assert "GET /users" in eps and "POST /users" in eps
    assert data["POST /users"] == {"y": 2}


def test_parse_swagger_handles_missing_paths():
    assert ratcore.parse_swagger_endpoints({}) == ([], {})
