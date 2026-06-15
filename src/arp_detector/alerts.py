"""
Rich-formatted alert output for ARP anomalies.

ARPAlertManager prints to *stderr* (same as the Phase 3 AlertManager) so
that normal stdout output (piped to files, grep, etc.) is not polluted by
alert banners.

Severity → colour mapping
──────────────────────────
    low      → dim
    medium   → yellow
    high     → red
    critical → bold red (with extra border emphasis)
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.arp_detector.events import ARPEvent, ARPEventType

_stderr = Console(stderr=True, highlight=False)

_SEVERITY_COLOUR: dict[str, str] = {
    "low": "dim",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_EVENT_LABEL: dict[ARPEventType, str] = {
    ARPEventType.MAC_CHANGE: "MAC ADDRESS CHANGED",
    ARPEventType.GRATUITOUS_ARP: "GRATUITOUS ARP DETECTED",
    ARPEventType.MITM_SUSPECTED: "MITM ATTACK SUSPECTED",
    ARPEventType.GATEWAY_MAC_CHANGE: "GATEWAY MAC CHANGED",
}


class ARPAlertManager:
    """
    Displays Rich alert panels for ARP anomaly events and counts alerts
    so the CLI can include them in the session summary.
    """

    def __init__(self) -> None:
        self._total = 0
        self._critical = 0

    def show_alert(self, event: ARPEvent) -> None:
        """Print a Rich panel for *event* and increment internal counters."""
        colour = _SEVERITY_COLOUR.get(event.severity, "white")
        label = _EVENT_LABEL.get(event.event_type, event.event_type.value.upper())
        title = f"[{colour}] ARP ALERT — {label} [/{colour}]"

        body = Text()
        body.append("Source IP:  ", style="bold")
        body.append(f"{event.src_ip}\n")
        body.append("Source MAC: ", style="bold")
        body.append(f"{event.src_mac}\n")

        if event.old_mac:
            body.append("Old MAC:    ", style="bold")
            body.append(f"{event.old_mac}\n")

        body.append("Target IP:  ", style="bold")
        body.append(f"{event.dst_ip}\n")
        body.append("Severity:   ", style="bold")
        body.append(event.severity.upper(), style=colour)
        body.append(f"\n\n{event.description}")

        _stderr.print(Panel(body, title=title, border_style=colour, expand=False))

        self._total += 1
        if event.severity == "critical":
            self._critical += 1

    @property
    def total_alerts(self) -> int:
        return self._total

    @property
    def critical_alerts(self) -> int:
        return self._critical
