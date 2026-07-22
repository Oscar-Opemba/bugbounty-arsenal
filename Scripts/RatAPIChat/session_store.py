"""
Secure session / preferences persistence for RatAPIChat.

The original tool wrote request history — including live auth tokens — to a
world-readable file in /tmp. This module instead:

- stores under the user's config dir (XDG_CONFIG_HOME or ~/.config/ratapichat),
- creates files with 0600 (owner-only) permissions,
- redacts secrets from the auto-saved session by default.

Pure enough to unit-test (only touches the filesystem paths you pass in).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import ratcore


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(Path.home(), ".config")
    return Path(base) / "ratapichat"


def secure_write_text(path, text: str) -> None:
    """Write *text* to *path* with 0600 perms, creating parents as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)  # tighten even if the file pre-existed
    except OSError:
        pass


def save_history(history, path, redact: bool = True) -> None:
    """Persist request history. Secrets are redacted unless redact=False."""
    safe = [ratcore.redact_entry(e, redact=redact) for e in history]
    secure_write_text(path, json.dumps(safe, indent=2))


def load_history(path):
    """Load request history; returns [] on missing/corrupt file (never raises)."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_json(obj, path) -> None:
    secure_write_text(path, json.dumps(obj, indent=2))


def load_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return default
