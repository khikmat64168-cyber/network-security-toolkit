"""
DNS event types and logging for the spoofing detector.

Design mirrors the ARP detector's events.py:
  DNSEventType  — str-enum so values are usable as table labels directly.
  DNSEvent      — immutable record of one detected anomaly.
  EventLogger   — append-only list with convenience query methods.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional


class DNSEventType(str, Enum):
    IP_CHANGE   = "ip_change"
    UNSOLICITED = "unsolicited_response"
    ZERO_TTL    = "zero_ttl"
    MULTIPLE_IPS = "multiple_ips"


@dataclass
class DNSEvent:
    """Record of one DNS anomaly detected during a monitoring session."""

    event_type: DNSEventType
    domain: str
    new_ip: str
    src_ip: str        # DNS server that sent the suspicious response
    timestamp: datetime
    severity: str      # "low" | "medium" | "high" | "critical"
    description: str
    old_ip: Optional[str] = None
    ttl: Optional[int] = None

    def severity_level(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
            self.severity, 0
        )


class EventLogger:
    """Append-only log of DNSEvents for one dns-watch session."""

    def __init__(self) -> None:
        self._events: List[DNSEvent] = []

    def log(self, event: DNSEvent) -> None:
        self._events.append(event)

    @property
    def total(self) -> int:
        return len(self._events)

    @property
    def events(self) -> List[DNSEvent]:
        return list(self._events)

    def count_by_type(self, event_type: DNSEventType) -> int:
        return sum(1 for e in self._events if e.event_type == event_type)

    def count_by_severity(self, severity: str) -> int:
        return sum(1 for e in self._events if e.severity == severity)

    def high_priority_events(self) -> List[DNSEvent]:
        return [e for e in self._events if e.severity in ("high", "critical")]
