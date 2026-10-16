"""Rich-formatted MAC flooding alert output (printed to stderr)."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nst.mac_detector.events import MACEvent, MACEventType

_stderr = Console(stderr=True)

_SEVERITY_STYLES = {
    "high":     "bold red",
    "critical": "bold white on red",
}
_EVENT_LABELS = {
    MACEventType.FLOOD_DETECTED: "MAC FLOOD DETECTED",
    MACEventType.TABLE_OVERFLOW: "MAC TABLE OVERFLOW",
}


class MACAlertManager:
    """Renders MAC flood alerts as Rich panels to stderr."""

    def __init__(self) -> None:
        self.total_alerts: int = 0
        self.critical_alerts: int = 0

    def show_alert(self, event: MACEvent) -> None:
        self.total_alerts += 1
        if event.severity == "critical":
            self.critical_alerts += 1

        style = _SEVERITY_STYLES.get(event.severity, "bold red")
        label = _EVENT_LABELS.get(event.event_type, event.event_type.value.upper())

        grid = Table.grid(padding=(0, 1))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column(style="white")

        grid.add_row("Trigger MAC :", f"[bold cyan]{event.mac}[/bold cyan]")
        grid.add_row("New / window:", f"[bold yellow]{event.new_macs_in_window}[/bold yellow]")
        grid.add_row("Total seen  :", str(event.total_macs))
        grid.add_row("Severity    :", f"[{style}]{event.severity.upper()}[/{style}]")
        grid.add_row("Detail      :", event.description)

        _stderr.print(
            Panel(
                grid,
                title=f"[{style}] 🚨  {label} [/{style}]",
                border_style=style.split()[-1],
                expand=False,
            )
        )
