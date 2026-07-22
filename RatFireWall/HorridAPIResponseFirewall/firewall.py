"""
Horrid API Response Firewall — a Flask reverse proxy that blocks responses
containing forbidden keywords (e.g. leaked secrets).

Hardened: fixes the Content-Type KeyError, binds to localhost by default (not
0.0.0.0), adds a request timeout, and makes the upstream/host/port configurable
via environment variables.

Authorized use only. See ../../LEGAL.md.
"""
import os

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# Configuration (env-overridable). Default host is localhost — do NOT expose
# this proxy on 0.0.0.0 unless you understand the exposure.
PROXY_API_BASE_URL = os.environ.get("PROXY_API_BASE_URL", "https://api.example.com").rstrip("/")
BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "8080"))
TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", "30"))
FORBIDDEN_KEYWORDS = ["password", "api-key", "secret", "private_key"]


def inspect_response(json_data) -> bool:
    """True if the response appears to contain a forbidden keyword."""
    haystack = str(json_data).lower()
    return any(keyword in haystack for keyword in FORBIDDEN_KEYWORDS)


@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy_request(path):
    upstream = f"{PROXY_API_BASE_URL}/{path}"
    try:
        if request.method in ("GET", "DELETE"):
            resp = requests.request(request.method, upstream, params=request.args, timeout=TIMEOUT)
        else:
            resp = requests.request(request.method, upstream,
                                    json=request.get_json(silent=True), timeout=TIMEOUT)
    except requests.RequestException as e:
        return jsonify({"error": f"upstream request failed: {e}"}), 502

    content_type = resp.headers.get("Content-Type", "")
    if resp.status_code == 200 and content_type.startswith("application/json"):
        try:
            json_data = resp.json()
        except ValueError:
            return resp.content, resp.status_code
        if inspect_response(json_data):
            return jsonify({"error": "Forbidden content in response"}), 403
        return jsonify(json_data), 200

    return resp.content, resp.status_code


if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)
