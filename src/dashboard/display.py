"""
DashboardDisplay — Rich Live context manager for the traffic dashboard.

Usage
─────
    display = DashboardDisplay()
    with display:
        # inside the packet callback:
        display.record(parsed_packet)
        display.record_alert()   # call whenever a security alert fires

The display owns a DashboardStats instance (written by the packet thread)
and a Rich Live object (refreshed at *refresh_rate* renders/second in its
own internal thread).  screen=True uses the terminal alternate buffer so
the dashboard takes over the full terminal and restores it on exit.
"""
from __future__ import annotations

from rich.console import Console
from rich.live import Live

from src.dashboard.renderer import render
from src.dashboard.stats import DashboardSnapshot, DashboardStats


class DashboardDisplay:
    """
    Ties DashboardStats to a Rich Live display.

    refresh_rate: how many times per second Rich redraws even without a
    new packet.  Each record() call also triggers an immediate update.
    """

    def __init__(self, refresh_rate: int = 4) -> None:
        self._stats = DashboardStats()
        self._console = Console()
        self._live = Live(
            console=self._console,
            refresh_per_second=refresh_rate,
            screen=True,
        )

    # ── Context manager ──────────────────────────────────────────────────

    def __enter__(self) -> "DashboardDisplay":
        self._live.__enter__()
        self._live.update(render(self._stats.get_snapshot()))
        return self

    def __exit__(self, *args: object) -> None:
        self._live.__exit__(*args)

    # ── Packet feed (called from the capture thread) ─────────────────────

    def record(self, parsed: object) -> None:
        """Record a parsed packet and push a fresh render to the Live view."""
        self._stats.record_packet(parsed)
        self._live.update(render(self._stats.get_snapshot()))

    def record_alert(self) -> None:
        """Increment the alert counter shown in the footer."""
        self._stats.record_alert()

    # ── Read ─────────────────────────────────────────────────────────────

    @property
    def stats(self) -> DashboardStats:
        return self._stats

    def snapshot(self) -> DashboardSnapshot:
        return self._stats.get_snapshot()
