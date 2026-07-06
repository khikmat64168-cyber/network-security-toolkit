"""
MAC address table — tracks unique source MACs with first-seen timestamps.

MACTable is the data store for the flooding detector.  It records every
new MAC address seen on the wire and supports sliding-window queries so
the detector can measure the rate of new MAC appearances.

Broadcast (ff:ff:ff:ff:ff:ff) and IEEE 802 multicast MACs (first octet
with LSB set, e.g. 01:00:5e:…) are excluded — they are normal traffic
and would cause spurious flood alerts on busy networks.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class MACEntry:
    """One unique MAC address observed in the current session."""

    mac: str
    first_seen: float    # time.monotonic() timestamp
    packet_count: int = 1


def _is_broadcast_or_multicast(mac: str) -> bool:
    """Return True for ff:ff:ff:ff:ff:ff and multicast MACs (01:…)."""
    if mac.lower() == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x01)  # multicast bit
    except (ValueError, IndexError):
        return False


class MACTable:
    """
    Tracks unique source MAC addresses seen on the wire.

    Usage
    ─────
        table = MACTable()
        is_new = table.add("aa:bb:cc:dd:ee:ff", time.monotonic())
        count  = table.new_in_window(window_secs=5.0)
    """

    def __init__(self) -> None:
        self._entries: Dict[str, MACEntry] = {}

    def add(self, mac: str, timestamp: Optional[float] = None) -> bool:
        """
        Record a MAC address.  Returns True if this is the first time
        this MAC has been seen, False if it was already known.
        Broadcast and multicast MACs are silently ignored (returns False).
        """
        if _is_broadcast_or_multicast(mac):
            return False
        if timestamp is None:
            timestamp = time.monotonic()
        if mac in self._entries:
            self._entries[mac].packet_count += 1
            return False
        self._entries[mac] = MACEntry(mac=mac, first_seen=timestamp)
        return True

    def new_in_window(self, window_secs: float, now: Optional[float] = None) -> int:
        """Count MACs whose first appearance is within the last *window_secs*."""
        if now is None:
            now = time.monotonic()
        cutoff = now - window_secs
        return sum(1 for e in self._entries.values() if e.first_seen >= cutoff)

    def total(self) -> int:
        return len(self._entries)

    def all_entries(self) -> List[MACEntry]:
        return sorted(self._entries.values(), key=lambda e: e.first_seen)
