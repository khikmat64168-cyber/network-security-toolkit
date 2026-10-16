"""
Unit tests for filesystem locations (nst/core/paths.py).

Tests cover:
  - Bundled config files ship inside the package
  - XDG_CONFIG_HOME / XDG_STATE_HOME are honoured, with HOME fallbacks
  - resolve_state_path anchors relative paths, keeps absolute and ~ paths
  - ensure_dir hands created directories to the parent's owner under root
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from nst.core import paths


class TestBundledFiles:
    def test_default_config_ships_with_package(self) -> None:
        assert paths.BUNDLED_CONFIG_FILE.is_file()
        assert paths.BUNDLED_CONFIG_FILE.parent.parent == paths.PACKAGE_DIR

    def test_logging_config_ships_with_package(self) -> None:
        assert paths.BUNDLED_LOGGING_FILE.is_file()


class TestUserDirs:
    def test_config_dir_honours_xdg(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert paths.user_config_file() == tmp_path / "nst" / "config.yaml"

    def test_config_dir_falls_back_to_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert paths.user_config_dir() == tmp_path / ".config" / "nst"

    def test_state_dir_honours_xdg(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        assert paths.user_state_dir() == tmp_path / "nst"

    def test_state_dir_falls_back_to_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert paths.user_state_dir() == tmp_path / ".local" / "state" / "nst"


class TestResolveStatePath:
    def test_relative_path_goes_to_state_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        assert paths.resolve_state_path("a/b.log") == tmp_path / "nst" / "a" / "b.log"

    def test_absolute_path_unchanged(self, tmp_path: Path) -> None:
        target = tmp_path / "x.log"
        assert paths.resolve_state_path(str(target)) == target

    def test_home_path_expanded(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        assert paths.resolve_state_path("~/x.log") == tmp_path / "x.log"


class TestEnsureDir:
    def test_creates_nested_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c"
        paths.ensure_dir(target)
        assert target.is_dir()

    def test_existing_directory_is_noop(self, tmp_path: Path) -> None:
        with patch("os.chown") as chown:
            paths.ensure_dir(tmp_path)
        chown.assert_not_called()

    def test_non_root_never_chowns(self, tmp_path: Path) -> None:
        with patch("os.geteuid", return_value=1000), patch("os.chown") as chown:
            paths.ensure_dir(tmp_path / "new")
        chown.assert_not_called()

    def test_root_chowns_created_dirs_to_parent_owner(self, tmp_path: Path) -> None:
        owner = tmp_path.stat()
        with patch("os.geteuid", return_value=0), patch("os.chown") as chown:
            paths.ensure_dir(tmp_path / "a" / "b")
        chowned = [call.args for call in chown.call_args_list]
        assert chowned == [
            (tmp_path / "a", owner.st_uid, owner.st_gid),
            (tmp_path / "a" / "b", owner.st_uid, owner.st_gid),
        ]

    def test_chown_failure_is_ignored(self, tmp_path: Path) -> None:
        with patch("os.geteuid", return_value=0), \
             patch("os.chown", side_effect=PermissionError("nope")):
            paths.ensure_dir(tmp_path / "x")
        assert (tmp_path / "x").is_dir()
