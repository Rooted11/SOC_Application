"""
Centralized Logging Configuration
==================================
All backend modules import their logger via:

    from app.logging_config import get_logger
    logger = get_logger(__name__)

Logs are written to:
    logs/app.log   — all levels (INFO+)
    logs/error.log — errors only (ERROR+)
    stdout         — for Docker container visibility

Rotation policy:
    - Max 5 MB per file, 3 backups (RotatingFileHandler)
    - Startup trim: if app.log exceeds ~10,000 lines, truncate to newest 5,000
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_DIR = os.getenv("LOG_DIR", "logs")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)

MAX_BYTES = 5 * 1024 * 1024   # 5 MB
BACKUP_COUNT = 3
MAX_LINES = 10_000
TRIM_TO = 5_000

_configured = False


# ---------------------------------------------------------------------------
# Directory & file bootstrap
# ---------------------------------------------------------------------------
def _ensure_log_dir():
    """Create the logs directory if it doesn't exist."""
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Startup trim — hard cap at ~10,000 lines
# ---------------------------------------------------------------------------
def trim_log_file(filepath: str, max_lines: int = MAX_LINES, keep: int = TRIM_TO):
    """
    If *filepath* exceeds *max_lines*, rewrite it with only the most recent
    *keep* lines.  Called once at startup.
    """
    try:
        path = Path(filepath)
        if not path.exists():
            return
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
        if len(lines) <= max_lines:
            return
        trimmed = lines[-keep:]
        with open(path, "w") as f:
            f.write(f"--- trimmed {len(lines) - keep} older entries at startup ---\n")
            f.writelines(trimmed)
        logging.getLogger("logging_config").info(
            "Trimmed %s from %d to %d lines", filepath, len(lines), len(trimmed) + 1
        )
    except OSError:
        pass  # non-fatal — container might not have the file yet


# ---------------------------------------------------------------------------
# One-time root logger setup
# ---------------------------------------------------------------------------
def setup_logging():
    """
    Configure the root logger with file + console handlers.
    Safe to call multiple times — only configures once.
    """
    global _configured
    if _configured:
        return
    _configured = True

    _ensure_log_dir()

    app_log = os.path.join(LOG_DIR, "app.log")
    error_log = os.path.join(LOG_DIR, "error.log")

    # Trim on startup
    trim_log_file(app_log)
    trim_log_file(error_log)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # -- File handler: app.log (INFO+) --
    app_handler = RotatingFileHandler(
        app_log, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8",
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(formatter)

    # -- File handler: error.log (ERROR+) --
    err_handler = RotatingFileHandler(
        error_log, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8",
    )
    err_handler.setLevel(logging.ERROR)
    err_handler.setFormatter(formatter)

    # -- Console handler: stdout (for Docker logs) --
    console = logging.StreamHandler()
    console.setLevel(LOG_LEVEL)
    console.setFormatter(formatter)

    # -- Root logger --
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # handlers filter their own levels
    root.addHandler(app_handler)
    root.addHandler(err_handler)
    root.addHandler(console)

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.  Ensures setup_logging() has been called.

    Usage:
        from app.logging_config import get_logger
        logger = get_logger(__name__)
    """
    setup_logging()
    return logging.getLogger(name)
