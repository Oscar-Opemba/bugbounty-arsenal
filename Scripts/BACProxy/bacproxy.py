"""
BACProxy — mitmproxy addon for detecting broken access control / IDOR.

For each in-scope request your browser makes, BACProxy replays it once as a
second identity (user2) and compares user2's response to the genuine user1
response. Identical responses (MATCH) suggest user2 could access user1's data.

Run:
    mitmdump -s bacproxy.py
Config is read from ./config.yaml (or $BACPROXY_CONFIG). Copy config.example.yaml
to start. The second identity's header is set in config or via the
USER2_HEADER_NAME / USER2_HEADER_VALUE environment variables.

Safety: only idempotent methods (GET/HEAD/OPTIONS) are replayed by default, so
BACProxy never silently repeats a state-changing action as another user. Enable
other methods in config only when you understand the side effects.

Authorized testing only — see ../../LEGAL.md.
"""
import logging
import os
import threading

import requests
import urllib3
import yaml
from mitmproxy import http

import core

log = logging.getLogger("bacproxy")


class AuthHeaderReplacer:
    def __init__(self):
        cfg_path = os.environ.get("BACPROXY_CONFIG", "config.yaml")
        if not os.path.exists(cfg_path):
            raise RuntimeError(
                f"BACProxy config not found: {cfg_path}. "
                "Copy config.example.yaml to config.yaml and set your scope + user2 header."
            )
        with open(cfg_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        self.cfg = core.merge_config(user_cfg)

        # Env vars override config for the second identity's header/value.
        self.user2_header_name = os.environ.get(
            "USER2_HEADER_NAME", self.cfg.get("user2_header_name", "Authorization"))
        self.user2_header_value = os.environ.get(
            "USER2_HEADER_VALUE", self.cfg.get("user2_header_value", ""))

        self.report_data = []
        self.lock = threading.Lock()

        if not self.cfg["verify_tls"]:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Startup banner so the operator sees exactly what will happen.
        log.info("BACProxy config: scope=%s exclude=%s methods=%s verify_tls=%s output=%s",
                 self.cfg["scope"], self.cfg["exclude_endpoints"],
                 self.cfg["replay_methods"], self.cfg["verify_tls"], self.cfg["output"])
        risky = core.state_changing_enabled(self.cfg["replay_methods"])
        if risky:
            log.warning("BACProxy will replay STATE-CHANGING methods %s as user2 — "
                        "this can duplicate side effects. Ensure this is intended.", risky)
        if not self.user2_header_value:
            log.warning("USER2_HEADER_VALUE is empty — set the second identity's token "
                        "(env USER2_HEADER_VALUE or config user2_header_value).")
        if not self.cfg["scope"]:
            log.warning("Scope is empty — no requests will be tested. Set 'scope' in config.")

    def response(self, flow: http.HTTPFlow):
        """Compare the genuine (user1) response against a user2 replay."""
        url = flow.request.url
        if not core.in_scope(url, self.cfg["scope"], self.cfg["exclude_endpoints"]):
            return
        method = flow.request.method
        if not core.method_allowed(method, self.cfg["replay_methods"]):
            log.info("[skip] %s %s (method not in replay_methods)", method, url)
            return

        # user1 = the real, already-received response (no extra request needed).
        status1 = flow.response.status_code
        body1 = flow.response.get_text(strict=False) or ""
        user1_header = dict(flow.request.headers).get(self.user2_header_name, "None")

        # user2 = one replay with the auth header swapped.
        headers = core.strip_replay_headers(dict(flow.request.headers))
        headers[self.user2_header_name] = self.user2_header_value
        status2, body2 = self._send(method, url, headers, flow.request.get_content())

        status = core.classify(status1, body1, status2, body2)
        log.info("[%s] %s %s (user1=%s user2=%s)", status, method, url, status1, status2)

        with self.lock:
            self.report_data.append({
                "endpoint": url,
                "user1_header": user1_header,
                "user2_header": self.user2_header_value,
                "status": status,
                "user1_response": body1,
                "user2_response": body2,
            })

    def _send(self, method, url, headers, data):
        try:
            r = requests.request(method, url, headers=headers, data=data,
                                 verify=self.cfg["verify_tls"], timeout=self.cfg["timeout"])
            return r.status_code, r.text
        except requests.RequestException as e:
            log.warning("replay failed for %s: %s", url, e)
            return 0, ""

    def done(self):
        try:
            core.write_report(self.report_data, self.cfg["output"],
                              self.cfg["max_body_chars"], self.cfg["redact"])
            log.info("BACProxy report written to %s (%d records, 0600)",
                     self.cfg["output"], len(self.report_data))
        except OSError as e:
            log.error("failed writing report: %s", e)


addons = [AuthHeaderReplacer()]
