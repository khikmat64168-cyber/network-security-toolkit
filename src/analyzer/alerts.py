"""
Rich-formatted security alert output.

All alerts are printed to stderr so they stand out from the normal
packet stream on stdout and can be redirected independently.

Severity colour map:
    low      → yellow
    medium   → orange3
    high     → red
    critical → bold red on white
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.analyzer.credentials import CredentialFinding
from src.analyzer.threats import ThreatEvent

_console = Console(stderr=True)

_SEVERITY_STYLES = {
    "low":      "yellow",
    "medium":   "orange3",
    "high":     "bold red",
    "critical": "bold white on red",
}

_SEVERITY_ICONS = {
    "low":      "⚠",
    "medium":   "⚠",
    "high":     "🚨",
    "critical": "🚨",
}


class AlertManager:
    """
    Renders security alerts as Rich panels to stderr.

    One instance per capture session — keeps a running tally of alerts
    shown so the final summary can reference the count.
    """

    def __init__(self) -> None:
        self.credential_count: int = 0
        self.threat_count: int = 0

    def credential_alert(self, finding: CredentialFinding) -> None:
        """Print a bright alert panel for a detected plaintext credential."""
        self.credential_count += 1

        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="bold white")

        table.add_row("Protocol :", finding.protocol)
        table.add_row("Type     :", finding.kind)
        table.add_row("Source   :", finding.src_ip)
        table.add_row("Target   :", finding.dst_ip)
        table.add_row("Username :", f"[bold cyan]{finding.username}[/bold cyan]")
        table.add_row("Password :", f"[bold red]{finding.password}[/bold red]")
        table.add_row("Context  :", f"[dim]{finding.context}[/dim]")

        _console.print(
            Panel(
                table,
                title="[bold white on red] CREDENTIAL DETECTED [/bold white on red]",
                border_style="red",
                expand=False,
            )
        )

    def threat_alert(self, event: ThreatEvent) -> None:
        """Print a coloured alert panel for a detected network threat."""
        self.threat_count += 1

        style = _SEVERITY_STYLES.get(event.severity, "yellow")
        icon = _SEVERITY_ICONS.get(event.severity, "⚠")

        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="white")

        table.add_row("Type     :", event.threat_type.replace("_", " ").title())
        table.add_row("Severity :", f"[{style}]{event.severity.upper()}[/{style}]")
        table.add_row("Source   :", event.src_ip)
        table.add_row("Target   :", event.dst_ip)
        table.add_row("Detail   :", event.description)

        for key, value in event.details.items():
            label = key.replace("_", " ").title()
            table.add_row(f"{label:<9}:", str(value))

        _console.print(
            Panel(
                table,
                title=f"[{style}] {icon}  SECURITY ALERT — {event.threat_type.upper()} [/{style}]",
                border_style=style.split()[-1],  # use last word as colour
                expand=False,
            )
        )
