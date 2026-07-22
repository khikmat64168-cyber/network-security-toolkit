"""
Write a rendered HTML report to disk and (optionally) open it in a browser.

Public API
──────────
    write(data, path, open_browser=False) → Path
"""
from __future__ import annotations

import webbrowser
from pathlib import Path

from src.reporter.models import ReportData
from src.reporter.renderer import render


def write(
    data: ReportData,
    output_path: Path,
    open_browser: bool = False,
) -> Path:
    """
    Render *data* to HTML and write it to *output_path*.

    If *open_browser* is True the file is opened in the system default
    browser immediately after writing.

    Returns the resolved absolute path of the written file.
    """
    html = render(data)
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    if open_browser:
        webbrowser.open(output_path.as_uri())

    return output_path


def default_output_path(data: ReportData) -> Path:
    """Return a timestamped default filename for the report."""
    ts = data.generated_at.strftime("%Y%m%d_%H%M%S")
    return Path(f"nst_report_{ts}.html")
