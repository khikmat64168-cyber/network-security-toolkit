"""
Logging subsystem for the Network Security Toolkit.

Design decisions
────────────────
* Two handlers are always installed:
    - RichHandler  → coloured, human-readable output to stderr
    - RotatingFileHandler → structured, machine-parseable records on disk
* A single global _initialized flag prevents duplicate handler
  registration when setup_logging() is called more than once (e.g.
  during a test run or when CLI options are re-applied).
* Modules call get_logger() at import time, which bootstraps logging
  with defaults before the CLI has read its config.  That implicit
  bootstrap is provisional: the first setup_logging() call that passes
  an explicit LoggingConfig replaces it, so --debug and the [logging]
  config section always take effect.
* Per-module log levels are loaded from the bundled
  nst/config/logging.yaml so that individual subsystems can be set to
  DEBUG without flooding the console — no code changes required.
* Relative log file paths resolve against the user state directory
  (~/.local/state/nst/), never the package directory.  If the log file
  cannot be written (e.g. created by an earlier sudo run) logging falls
  back to console-only with a warning instead of failing.
* get_logger() is the only symbol that callers should use.  It calls
  setup_logging() with defaults if the subsystem hasn't been initialised
  yet, so modules never have to worry about ordering.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from rich.console import Console
from rich.logging import RichHandler

from nst.core.config import LoggingConfig
from nst.core.paths import BUNDLED_LOGGING_FILE, ensure_dir, match_owner, resolve_state_path

_LOG_YAML = BUNDLED_LOGGING_FILE

_FILE_FORMAT = "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_initialized: bool = False
_explicit: bool = False   # True once a caller-supplied config has been applied
_stderr_console: Console = Console(stderr=True)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def setup_logging(config: Optional[LoggingConfig] = None) -> None:
    """
    Configure the application-wide logging subsystem.

    Safe to call multiple times — subsequent calls are no-ops unless
    _reset_logging_for_testing() has been called first.  The one
    exception: an explicit *config* replaces the implicit defaults
    installed by an earlier get_logger() bootstrap.

    Args:
        config: Logging settings.  Defaults to LoggingConfig() if None.
    """
    global _initialized, _explicit
    if _initialized and (_explicit or config is None):
        return

    if _initialized:
        _close_root_handlers()

    _explicit = config is not None
    if config is None:
        config = LoggingConfig()

    log_level = _parse_level(config.level)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)   # root must accept everything; handlers filter
    root.handlers.clear()

    # ── Console handler (Rich) ──────────────────────────────────────
    rich_handler = RichHandler(
        console=_stderr_console,
        level=log_level,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
        log_time_format="%H:%M:%S",
    )
    root.addHandler(rich_handler)

    # ── Rotating file handler ───────────────────────────────────────
    log_path = _prepare_log_file(resolve_state_path(config.file))
    if log_path is not None:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_path,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
            delay=True,   # don't open the file until the first write
        )
        file_handler.setLevel(logging.DEBUG)   # capture everything to disk
        file_handler.setFormatter(
            logging.Formatter(fmt=_FILE_FORMAT, datefmt=_DATE_FORMAT)
        )
        root.addHandler(file_handler)

    # ── Per-module overrides from nst/config/logging.yaml ───────────
    _apply_module_levels()

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger, initialising the subsystem with defaults if needed.

    Usage:
        logger = get_logger(__name__)
        logger.info("Capture started on %s", interface)
    """
    if not _initialized:
        setup_logging()
    return logging.getLogger(name)


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _prepare_log_file(log_path: Path) -> Optional[Path]:
    """
    Make sure *log_path* can be appended to.

    Creates the parent directory (and the empty file, owned like its
    directory so a sudo run doesn't lock the user out of their own log).
    Returns None — after printing a console warning — when the file is
    not writable, so the caller can continue with console-only logging.
    """
    try:
        ensure_dir(log_path.parent)
        if not log_path.exists():
            log_path.touch()
            parent = log_path.parent.stat()
            match_owner(log_path, parent.st_uid, parent.st_gid)
    except OSError as exc:
        _stderr_console.print(
            f"[yellow]Warning:[/yellow] cannot create log file {log_path}: {exc}. "
            "Logging to console only."
        )
        return None

    if not os.access(log_path, os.W_OK):
        _stderr_console.print(
            f"[yellow]Warning:[/yellow] log file {log_path} is not writable "
            "(was it created by a sudo run?).  Logging to console only."
        )
        return None
    return log_path


def _parse_level(level_str: str) -> int:
    """Convert a level name to its integer constant, defaulting to INFO."""
    level = getattr(logging, level_str.upper(), None)
    if not isinstance(level, int):
        return logging.INFO
    return level


def _apply_module_levels() -> None:
    """
    Apply per-module log levels from nst/config/logging.yaml.

    Errors are swallowed intentionally — a bad logging.yaml must
    never prevent the application from starting.
    """
    if not _LOG_YAML.exists():
        return

    try:
        with open(_LOG_YAML, encoding="utf-8") as fh:
            data: Dict[str, Any] = yaml.safe_load(fh) or {}

        module_levels: Dict[str, str] = data.get("module_levels") or {}
        for module_name, level_str in module_levels.items():
            level = _parse_level(str(level_str))
            logging.getLogger(module_name).setLevel(level)
    except Exception:   # noqa: BLE001
        pass


def _reset_logging_for_testing() -> None:
    """
    Reset the logging subsystem to an uninitialised state.

    FOR TEST USE ONLY.  Do not call this in production code.
    Closes all handlers currently attached to the root logger and
    clears the _initialized flag so that setup_logging() can be
    called again with a fresh configuration.
    """
    global _initialized, _explicit
    _initialized = False
    _explicit = False
    _close_root_handlers()


def _close_root_handlers() -> None:
    """Close and detach every handler on the root logger."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        try:
            handler.close()
        except Exception:   # noqa: BLE001
            pass
    root.handlers.clear()
