"""
Logging setup for AutoRecon.

Replaces scattered print() calls with the stdlib logging module: real levels,
consistent formatting, and a per-job log file written alongside that job's
results. Kept tiny and import-safe so both the GUI and the headless CLI share
one logging story.
"""
from __future__ import annotations

import logging
from pathlib import Path

_FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATEFMT = "%H:%M:%S"
_configured = False


def configure_root(level=logging.INFO) -> None:
    """Attach a single stdout handler to the 'autorecon' logger namespace."""
    global _configured
    if _configured:
        return
    root = logging.getLogger("autorecon")
    root.setLevel(level)
    root.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(_FMT, _DATEFMT))
    root.addHandler(handler)
    _configured = True


def get_job_logger(job_id: str, log_dir: Path) -> logging.Logger:
    """
    Return a logger for a single job, adding a FileHandler at
    <log_dir>/job.log. Idempotent: repeated calls won't stack handlers.
    """
    configure_root()
    logger = logging.getLogger(f"autorecon.{job_id}")
    logger.setLevel(logging.INFO)
    already = any(isinstance(h, logging.FileHandler) for h in logger.handlers)
    if not already:
        try:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / "job.log", encoding="utf-8")
            fh.setFormatter(logging.Formatter(_FMT, _DATEFMT))
            logger.addHandler(fh)
        except Exception:
            # Logging must never take down a scan; fall back to stdout only.
            pass
    return logger
