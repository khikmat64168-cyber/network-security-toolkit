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
from unittest.mock import patch

from nst.core.config import LoggingConfig
from nst.core.logger import (
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
        import nst.core.logger as logger_module

        setup_logging()
        handlers_after_first = len(logging.getLogger().handlers)

        setup_logging()   # second call — should be a no-op
        handlers_after_second = len(logging.getLogger().handlers)

        assert handlers_after_first == handlers_after_second

    def test_reset_clears_initialized_flag(self, reset_logging: None) -> None:
        import nst.core.logger as logger_module

        setup_logging()
        assert logger_module._initialized is True

        _reset_logging_for_testing()
        assert logger_module._initialized is False


class TestExplicitConfig:
    def test_explicit_config_replaces_implicit_bootstrap(
        self, tmp_path: Path, reset_logging: None
    ) -> None:
        """get_logger() at import time must not swallow the CLI's config."""
        _reset_logging_for_testing()
        get_logger("nst.bootstrap")            # implicit defaults
        setup_logging(LoggingConfig(level="DEBUG", file=str(tmp_path / "x.log")))

        rich = [h for h in logging.getLogger().handlers if type(h).__name__ == "RichHandler"]
        assert [h.level for h in rich] == [logging.DEBUG]

    def test_second_explicit_config_is_noop(
        self, tmp_path: Path, reset_logging: None
    ) -> None:
        _reset_logging_for_testing()
        setup_logging(LoggingConfig(level="WARNING", file=str(tmp_path / "a.log")))
        setup_logging(LoggingConfig(level="DEBUG", file=str(tmp_path / "b.log")))

        rich = [h for h in logging.getLogger().handlers if type(h).__name__ == "RichHandler"]
        assert [h.level for h in rich] == [logging.WARNING]
        assert not (tmp_path / "b.log").exists()

    def test_relative_file_goes_to_state_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reset_logging: None
    ) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        _reset_logging_for_testing()
        setup_logging(LoggingConfig(file="rel/nst.log"))
        assert (tmp_path / "nst" / "rel" / "nst.log").exists()

    def test_unwritable_log_falls_back_to_console(
        self, tmp_path: Path, reset_logging: None
    ) -> None:
        log_file = tmp_path / "locked.log"
        log_file.touch()
        _reset_logging_for_testing()
        with patch("os.access", return_value=False):
            setup_logging(LoggingConfig(file=str(log_file)))

        kinds = {type(h).__name__ for h in logging.getLogger().handlers}
        assert kinds == {"RichHandler"}

    def test_uncreatable_log_dir_falls_back_to_console(
        self, tmp_path: Path, reset_logging: None
    ) -> None:
        blocker = tmp_path / "file-not-dir"
        blocker.write_text("")
        _reset_logging_for_testing()
        setup_logging(LoggingConfig(file=str(blocker / "x.log")))

        kinds = {type(h).__name__ for h in logging.getLogger().handlers}
        assert kinds == {"RichHandler"}
