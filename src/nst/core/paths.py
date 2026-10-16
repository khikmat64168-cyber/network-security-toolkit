"""
Filesystem locations used by the Network Security Toolkit.

Design decisions
────────────────
* Bundled defaults (config/default.yaml, config/logging.yaml) ship
  inside the package as package data, so an installed wheel is
  self-contained and never depends on the source checkout layout.
* Per-user overrides follow the XDG Base Directory spec:
    - config → $XDG_CONFIG_HOME/nst/config.yaml (~/.config/nst/…)
    - state  → $XDG_STATE_HOME/nst/             (~/.local/state/nst/)
  Writable runtime state (the log file) never lives inside the package:
  site-packages is frequently read-only and shared between users.
* Most subcommands run under sudo.  On macOS sudo keeps the invoking
  user's HOME, so anything created there as root would later be
  unwritable for that same user.  ensure_dir() therefore hands newly
  created directories to the owner of their nearest existing parent.
"""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "nst"

PACKAGE_DIR = Path(__file__).resolve().parent.parent
BUNDLED_CONFIG_DIR = PACKAGE_DIR / "config"
BUNDLED_CONFIG_FILE = BUNDLED_CONFIG_DIR / "default.yaml"
BUNDLED_LOGGING_FILE = BUNDLED_CONFIG_DIR / "logging.yaml"


def user_config_dir() -> Path:
    """Directory holding the optional per-user config.yaml."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_NAME


def user_config_file() -> Path:
    """Path of the optional per-user configuration override."""
    return user_config_dir() / "config.yaml"


def user_state_dir() -> Path:
    """Directory for writable runtime state such as log files."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / APP_NAME


def resolve_state_path(path: str | Path) -> Path:
    """
    Resolve *path* for writing.

    Absolute paths (and ~-prefixed paths) are returned unchanged;
    relative paths are anchored at user_state_dir().
    """
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    return user_state_dir() / candidate


def ensure_dir(path: Path) -> None:
    """
    Create *path* (and parents) if missing.

    When running as root, every directory this call creates is chowned
    to the owner of its nearest pre-existing ancestor, so `sudo nst …`
    never leaves root-owned directories inside a regular user's HOME.
    """
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent

    path.mkdir(parents=True, exist_ok=True)

    if not missing or not _is_root():
        return

    owner = current.stat()
    for created in reversed(missing):
        match_owner(created, owner.st_uid, owner.st_gid)


def match_owner(path: Path, uid: int, gid: int) -> None:
    """chown *path* to uid:gid when running as root; errors are ignored."""
    if not _is_root():
        return
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0
