"""
ARP event types and structured event log.

ARPEventType covers the full spectrum from normal operation through
suspected MITM.  Severity levels map to Rich colour coding in the alert
manager:

    normal       → ignored (not stored)
    low          → dim / grey
    medium       → yellow  (gratuitous ARP, suspicious replay)
    high         → red     (MAC change for non-gateway IP)
    critical     → bold red (MAC change for gateway IP / MITM confirmed)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

from src.core.logger import get_logger

logger = get_logger(__name__)


class ARPEventType(str, Enum):
    MAC_CHANGE = "mac_change"
    GRATUITOUS_ARP = "gratuitous_arp"
    MITM_SUSPECTED = "mitm_suspected"
    GATEWAY_MAC_CHANGE = "gateway_mac_change"


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class ARPEvent:
    """Immutable record of a single ARP anomaly."""

    event_type: ARPEventType
    src_ip: str
    src_mac: str
    dst_ip: str
    timestamp: datetime
    severity: str
    description: str
    old_mac: Optional[str] = None

    def severity_level(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 0)


class EventLogger:
    """
    In-memory log of ARPEvent records.

    Emits to the module logger at the appropriate level so that
    persistent file logging picks them up automatically via setup_logging().
    """

    def __init__(self) -> None:
        self._events: List[ARPEvent] = []

    def log(self, event: ARPEvent) -> None:
        """Append *event* and forward it to the module logger."""
        self._events.append(event)
        msg = "ARP %s [%s]: %s"
        args = (event.event_type.value, event.severity, event.description)
        if event.severity in ("high", "critical"):
            logger.warning(msg, *args)
        else:
            logger.info(msg, *args)

    # ── Read ──────────────────────────────────────────────────────────────────

    @property
    def events(self) -> List[ARPEvent]:
        """Snapshot of all logged events (oldest first)."""
        return list(self._events)

    @property
    def total(self) -> int:
        return len(self._events)

    def count_by_type(self, event_type: ARPEventType) -> int:
        return sum(1 for e in self._events if e.event_type == event_type)

    def count_by_severity(self, severity: str) -> int:
        return sum(1 for e in self._events if e.severity == severity)

    def high_priority_events(self) -> List[ARPEvent]:
        """Return events with severity high or critical."""
        return [e for e in self._events if e.severity_level() >= 2]
