"""
MAC flooding event types and logging.

Design mirrors ARP and DNS detector event modules.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List


class MACEventType(str, Enum):
    FLOOD_DETECTED = "flood_detected"
    TABLE_OVERFLOW = "table_overflow"


@dataclass
class MACEvent:
    """Record of one MAC flooding anomaly."""

    event_type: MACEventType
    mac: str                  # MAC address that triggered the alert
    new_macs_in_window: int   # unique new MACs seen in the sliding window
    total_macs: int           # total unique MACs seen this session
    timestamp: datetime
    severity: str             # "high" | "critical"
    description: str

    def severity_level(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(self.severity, 0)


class EventLogger:
    """Append-only log of MACEvents for one mac-watch session."""

    def __init__(self) -> None:
        self._events: List[MACEvent] = []

    def log(self, event: MACEvent) -> None:
        self._events.append(event)

    @property
    def total(self) -> int:
        return len(self._events)

    @property
    def events(self) -> List[MACEvent]:
        return list(self._events)

    def count_by_type(self, event_type: MACEventType) -> int:
        return sum(1 for e in self._events if e.event_type == event_type)

    def high_priority_events(self) -> List[MACEvent]:
        return [e for e in self._events if e.severity in ("high", "critical")]
