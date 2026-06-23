"""
Rich-formatted DNS spoofing alert output.

All alerts are printed to stderr so they remain visible alongside the
normal packet stream and can be redirected independently.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.dns_detector.events import DNSEvent, DNSEventType

_stderr = Console(stderr=True)

_SEVERITY_STYLES = {
    "low":      "yellow",
    "medium":   "orange3",
    "high":     "bold red",
    "critical": "bold white on red",
}

_EVENT_LABELS = {
    DNSEventType.IP_CHANGE:    "IP CHANGE",
    DNSEventType.UNSOLICITED:  "UNSOLICITED RESPONSE",
    DNSEventType.ZERO_TTL:     "ZERO TTL",
    DNSEventType.MULTIPLE_IPS: "MULTIPLE IPS",
}


class DNSAlertManager:
    """
    Renders DNS spoofing alerts as Rich panels to stderr.

    One instance per dns-watch session.
    """

    def __init__(self) -> None:
        self.total_alerts: int = 0
        self.high_alerts: int = 0

    def show_alert(self, event: DNSEvent) -> None:
        self.total_alerts += 1
        if event.severity in ("high", "critical"):
            self.high_alerts += 1

        style = _SEVERITY_STYLES.get(event.severity, "yellow")
        label = _EVENT_LABELS.get(event.event_type, event.event_type.value.upper())

        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="white")

        table.add_row("Domain   :", f"[bold cyan]{event.domain}[/bold cyan]")
        table.add_row("New IP   :", f"[bold yellow]{event.new_ip}[/bold yellow]")
        if event.old_ip:
            table.add_row("Old IP   :", f"[dim]{event.old_ip}[/dim]")
        if event.ttl is not None:
            table.add_row("TTL      :", str(event.ttl))
        table.add_row("Server   :", event.src_ip)
        table.add_row("Severity :", f"[{style}]{event.severity.upper()}[/{style}]")
        table.add_row("Detail   :", event.description)

        _stderr.print(
            Panel(
                table,
                title=f"[{style}] ⚠  DNS ALERT — {label} [/{style}]",
                border_style=style.split()[-1],
                expand=False,
            )
        )
