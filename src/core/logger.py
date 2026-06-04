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
* Per-module log levels are loaded from config/logging.yaml so that
  individual subsystems can be set to DEBUG without flooding the
  console — no code changes required.
* get_logger() is the only symbol that callers should use.  It calls
  setup_logging() with defaults if the subsystem hasn't been initialised
  yet, so modules never have to worry about ordering.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from rich.console import Console
from rich.logging import RichHandler

from src.core.config import LoggingConfig

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_LOG_YAML = _PROJECT_ROOT / "config" / "logging.yaml"

_FILE_FORMAT = "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_initialized: bool = False
_stderr_console: Console = Console(stderr=True)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def setup_logging(config: Optional[LoggingConfig] = None) -> None:
    """
    Configure the application-wide logging subsystem.

    Safe to call multiple times — subsequent calls are no-ops unless
    _reset_logging_for_testing() has been called first.

    Args:
        config: Logging settings.  Defaults to LoggingConfig() if None.
    """
    global _initialized
    if _initialized:
        return

    if config is None:
        config = LoggingConfig()

    log_level = _parse_level(config.level)

    # Create the log directory if it does not yet exist.
    log_path = Path(config.file)
    if not log_path.is_absolute():
        log_path = _PROJECT_ROOT / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

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
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_path,
        maxBytes=config.max_bytes,
        backupCount=config.backup_count,
        encoding="utf-8",
        delay=True,   # don't create the file until the first write
    )
    file_handler.setLevel(logging.DEBUG)   # capture everything to disk
    file_handler.setFormatter(
        logging.Formatter(fmt=_FILE_FORMAT, datefmt=_DATE_FORMAT)
    )
    root.addHandler(file_handler)

    # ── Per-module overrides from config/logging.yaml ───────────────
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

def _parse_level(level_str: str) -> int:
    """Convert a level name to its integer constant, defaulting to INFO."""
    level = getattr(logging, level_str.upper(), None)
    if not isinstance(level, int):
        return logging.INFO
    return level


def _apply_module_levels() -> None:
    """
    Apply per-module log levels from config/logging.yaml.

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
    global _initialized
    _initialized = False

    root = logging.getLogger()
    for handler in list(root.handlers):
        try:
            handler.close()
        except Exception:   # noqa: BLE001
            pass
    root.handlers.clear()
