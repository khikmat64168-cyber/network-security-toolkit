"""
HTML report storage for the web dashboard.

Reports are generated with the existing ReportBuilder / writer and kept
in the user state directory (~/.local/state/nst/reports/).  Only files
whose names match the pattern this module itself produces can be read
back, and every resolved path must stay inside the reports directory,
so a request can never be turned into an arbitrary file read.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nst.core.paths import ensure_dir, user_state_dir

_NAME_RE = re.compile(r"^nst_report_\d{8}_\d{6}(?:_\d{1,3})?\.html$")


class ReportStore:
    def __init__(self, directory: Optional[Path] = None) -> None:
        self.directory = directory or (user_state_dir() / "reports")

    def new_path(self, generated_at: datetime) -> Path:
        """A fresh, collision-free path for a report generated at *generated_at*."""
        ensure_dir(self.directory)
        stem = f"nst_report_{generated_at.strftime('%Y%m%d_%H%M%S')}"
        candidate = self.directory / f"{stem}.html"
        counter = 1
        while candidate.exists():
            candidate = self.directory / f"{stem}_{counter}.html"
            counter += 1
        return candidate

    def list(self) -> List[Dict[str, Any]]:
        if not self.directory.is_dir():
            return []
        items = []
        for path in self.directory.iterdir():
            if path.is_file() and _NAME_RE.match(path.name):
                stat = path.stat()
                items.append({
                    "name": path.name,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(),
                })
        return sorted(items, key=lambda r: r["name"], reverse=True)

    def resolve(self, name: str) -> Optional[Path]:
        """Return the path of report *name*, or None if it is not a valid stored report."""
        if not _NAME_RE.match(name):
            return None
        path = (self.directory / name).resolve()
        try:
            path.relative_to(self.directory.resolve())
        except ValueError:
            return None
        return path if path.is_file() else None
