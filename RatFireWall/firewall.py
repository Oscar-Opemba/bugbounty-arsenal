"""
RatFireWall — a rule-based blocking proxy (mitmproxy addon).

Inspects each request/response against the rule engine in rules.py and returns a
403 when a rule matches. This consolidates the three earlier broken variants
(missing imports, a Rule constructor that raised TypeError, and the removed
mitmproxy `http.HTTPResponse.make` API) into one working, tested implementation.

Run:
    mitmdump -s firewall.py

This is a lab / teaching WAF, not a production firewall — the signatures are
simple and bypassable. Authorized use only. See ../LEGAL.md.
"""
import logging

from mitmproxy import http

import rules

log = logging.getLogger("ratfirewall")


def _lower_headers(headers) -> dict:
    return {k.lower(): v for k, v in headers.items()}


class RatFireWall:
    def __init__(self):
        self.request_rules = rules.default_request_rules()
        self.response_rules = rules.default_response_rules()
        log.info("RatFireWall loaded: %d request rules, %d response rules",
                 len(self.request_rules), len(self.response_rules))

    def _block(self, flow: http.HTTPFlow, rule_name: str):
        log.warning("BLOCKED %s %s — rule: %s",
                    flow.request.method, flow.request.pretty_url, rule_name)
        flow.response = http.Response.make(
            403,
            f"Blocked by RatFireWall rule: {rule_name}".encode(),
            {"Content-Type": "text/plain"},
        )

    def request(self, flow: http.HTTPFlow):
        ctx = rules.RequestCtx(
            method=flow.request.method,
            url=flow.request.pretty_url,
            headers=_lower_headers(flow.request.headers),
            body=flow.request.get_text(strict=False) or "",
        )
        hit = rules.evaluate(ctx, self.request_rules)
        if hit:
            self._block(flow, hit)

    def response(self, flow: http.HTTPFlow):
        if flow.response is None:
            return
        ctx = rules.ResponseCtx(
            status=flow.response.status_code,
            headers=_lower_headers(flow.response.headers),
            body=flow.response.get_text(strict=False) or "",
        )
        hit = rules.evaluate(ctx, self.response_rules)
        if hit:
            self._block(flow, hit)


addons = [RatFireWall()]
