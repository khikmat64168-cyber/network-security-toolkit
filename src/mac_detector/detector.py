"""
MAC flooding detection logic.

Detection methods
─────────────────
1. Flood rate    — If more than *threshold* new MAC addresses appear within
                   a *window_secs* sliding window, a FLOOD_DETECTED event is
                   emitted at "high" severity.  A cooldown prevents alert spam
                   when flooding is sustained.
2. Table overflow — When the total unique MAC count reaches *table_limit* a
                    single TABLE_OVERFLOW event is emitted at "critical".

Design notes
────────────
* analyze() accepts a MAC string and a monotonic timestamp.  The caller
  (MACMonitor) provides both from the captured packet, keeping the detector
  free of I/O.
* Broadcast / multicast MACs are filtered in MACTable.add(), so the
  detector never sees them.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import List, Optional

from src.mac_detector.events import MACEvent, MACEventType
from src.mac_detector.table import MACTable

_DEFAULT_THRESHOLD   = 50    # new MACs per window
_DEFAULT_WINDOW      = 5.0   # seconds
_DEFAULT_TABLE_LIMIT = 1000  # unique MACs before TABLE_OVERFLOW
_FLOOD_COOLDOWN      = 10.0  # seconds between repeated FLOOD alerts


class FloodDetector:
    """
    Analyses the rate of new MAC addresses and emits MACEvents when
    flooding or table-overflow conditions are detected.

    Usage
    ─────
        detector = FloodDetector(table)
        events = detector.analyze("aa:bb:cc:dd:ee:ff", time.monotonic())
    """

    def __init__(
        self,
        table: MACTable,
        threshold: int = _DEFAULT_THRESHOLD,
        window_secs: float = _DEFAULT_WINDOW,
        table_limit: int = _DEFAULT_TABLE_LIMIT,
    ) -> None:
        self._table = table
        self._threshold = threshold
        self._window = window_secs
        self._table_limit = table_limit
        self._last_flood_ts: Optional[float] = None
        self._overflow_alerted: bool = False

    def analyze(self, mac: str, timestamp: Optional[float] = None) -> List[MACEvent]:
        """
        Record *mac* and return any events triggered by the update.

        timestamp — monotonic clock value (defaults to time.monotonic()).
        Returns an empty list for known MACs and for broadcast/multicast.
        """
        if timestamp is None:
            timestamp = time.monotonic()

        is_new = self._table.add(mac, timestamp)
        if not is_new:
            return []

        events: List[MACEvent] = []

        # ── 1. Flood rate check ──────────────────────────────────────────
        new_count = self._table.new_in_window(self._window, timestamp)
        if new_count >= self._threshold:
            cooldown_expired = (
                self._last_flood_ts is None
                or timestamp - self._last_flood_ts >= _FLOOD_COOLDOWN
            )
            if cooldown_expired:
                self._last_flood_ts = timestamp
                events.append(MACEvent(
                    event_type=MACEventType.FLOOD_DETECTED,
                    mac=mac,
                    new_macs_in_window=new_count,
                    total_macs=self._table.total(),
                    timestamp=datetime.now(),
                    severity="high",
                    description=(
                        f"{new_count} new MAC addresses in {self._window:.0f}s window "
                        f"(threshold: {self._threshold})"
                    ),
                ))

        # ── 2. Table overflow check ──────────────────────────────────────
        total = self._table.total()
        if total >= self._table_limit and not self._overflow_alerted:
            self._overflow_alerted = True
            events.append(MACEvent(
                event_type=MACEventType.TABLE_OVERFLOW,
                mac=mac,
                new_macs_in_window=new_count,
                total_macs=total,
                timestamp=datetime.now(),
                severity="critical",
                description=(
                    f"MAC table overflow: {total} unique addresses seen "
                    f"(limit: {self._table_limit})"
                ),
            ))

        return events
