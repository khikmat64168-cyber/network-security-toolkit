"""
pytest configuration and shared fixtures for the Network Security Toolkit test suite.
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Ensure the package is importable without `pip install -e .`
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Keep the test run away from the developer's real ~/.config/nst and
# ~/.local/state/nst.  This must happen before any `nst` module is
# imported: modules bootstrap logging (and create the log file) at
# import time.
_SANDBOX = Path(tempfile.mkdtemp(prefix="nst-tests-"))
os.environ["XDG_CONFIG_HOME"] = str(_SANDBOX / "config")
os.environ["XDG_STATE_HOME"] = str(_SANDBOX / "state")
os.environ.pop("NST_CONFIG", None)


@pytest.fixture()
def reset_logging() -> Generator[None, None, None]:
    """
    Isolate logging state between tests.

    Saves the current _initialized flag and root handlers before each
    test, then restores them after — so that tests calling setup_logging()
    with custom configs don't pollute subsequent tests.
    """
    import nst.core.logger as logger_module

    original_initialized = logger_module._initialized
    original_explicit = logger_module._explicit
    root = logging.getLogger()
    original_handlers = list(root.handlers)

    yield

    # Tear down any handlers added during the test
    for handler in list(root.handlers):
        if handler not in original_handlers:
            try:
                handler.close()
            except Exception:   # noqa: BLE001
                pass
    root.handlers = original_handlers

    logger_module._initialized = original_initialized
    logger_module._explicit = original_explicit
