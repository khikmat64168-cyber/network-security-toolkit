"""
Unit tests for the logging subsystem (src/core/logger.py).

Tests cover:
  - get_logger returns a correctly named Logger instance
  - get_logger called twice with the same name returns the same instance
  - setup_logging creates the log directory when it does not exist
  - setup_logging is idempotent (second call is a no-op)
  - _reset_logging_for_testing clears _initialized and handlers
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from src.core.config import LoggingConfig
from src.core.logger import (
    _reset_logging_for_testing,
    get_logger,
    setup_logging,
)


class TestGetLogger:
    def test_returns_logger_instance(self) -> None:
        logger = get_logger("nst.test.module")
        assert isinstance(logger, logging.Logger)

    def test_name_matches_argument(self) -> None:
        logger = get_logger("nst.unique.name.xyz")
        assert logger.name == "nst.unique.name.xyz"

    def test_same_name_returns_same_instance(self) -> None:
        logger1 = get_logger("nst.same.name")
        logger2 = get_logger("nst.same.name")
        assert logger1 is logger2


class TestSetupLogging:
    def test_creates_log_directory(
        self, tmp_path: Path, reset_logging: None
    ) -> None:
        """setup_logging must create the log directory if it is missing."""
        _reset_logging_for_testing()
        log_dir = tmp_path / "nested" / "log_dir"
        assert not log_dir.exists()

        config = LoggingConfig(
            level="DEBUG",
            file=str(log_dir / "test.log"),
            max_bytes=1024,
            backup_count=1,
        )
        setup_logging(config)
        assert log_dir.exists()

    def test_is_idempotent(self, reset_logging: None) -> None:
        """Calling setup_logging twice must not add duplicate handlers."""
        _reset_logging_for_testing()
        import src.core.logger as logger_module

        setup_logging()
        handlers_after_first = len(logging.getLogger().handlers)

        setup_logging()   # second call — should be a no-op
        handlers_after_second = len(logging.getLogger().handlers)

        assert handlers_after_first == handlers_after_second

    def test_reset_clears_initialized_flag(self, reset_logging: None) -> None:
        import src.core.logger as logger_module

        setup_logging()
        assert logger_module._initialized is True

        _reset_logging_for_testing()
        assert logger_module._initialized is False
