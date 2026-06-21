"""
Pure Rich layout renderer for the live dashboard.

render() is a side-effect-free function: it accepts a DashboardSnapshot
and returns a Rich Layout suitable for Rich Live.update().  No I/O,
no threading — easy to unit-test.
"""
from __future__ import annotations

import datetime
from typing import Dict

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.dashboard.stats import DashboardSnapshot

_PROTO_COLOURS: Dict[str, str] = {
    "HTTP":  "bold green",
    "DNS":   "bold yellow",
    "TCP":   "bold cyan",
    "UDP":   "bold blue",
    "ARP":   "bold magenta",
    "ICMP":  "bold bright_magenta",
    "OTHER": "dim white",
}


def render(snapshot: DashboardSnapshot) -> Layout:
    """Build the full-screen Rich Layout from *snapshot*."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="protocols", ratio=1),
        Layout(name="top_sources", ratio=1),
    )

    layout["header"].update(_render_header(snapshot))
    layout["protocols"].update(_render_protocols(snapshot))
    layout["top_sources"].update(_render_top_sources(snapshot))
    layout["right"].update(_render_recent(snapshot))
    layout["footer"].update(_render_footer(snapshot))

    return layout


# ── Section renderers ────────────────────────────────────────────────────────

def _render_header(snap: DashboardSnapshot) -> Panel:
    elapsed = datetime.timedelta(seconds=int(snap.elapsed))
    text = Text()
    text.append("Network Security Toolkit", style="bold cyan")
    text.append("  —  Live Traffic Dashboard", style="dim white")
    text.append(f"     Session: {elapsed}", style="bold green")
    return Panel(text, border_style="cyan")


def _render_protocols(snap: DashboardSnapshot) -> Panel:
    table = Table(
        show_header=True, header_style="bold", box=None, expand=True, padding=(0, 1)
    )
    table.add_column("Proto", style="bold", width=6)
    table.add_column("Pkts", justify="right", width=7)
    table.add_column("Share", justify="left")

    total = snap.total_packets or 1
    for proto, count in snap.protocol_counts.items():
        colour = _PROTO_COLOURS.get(proto, "white")
        pct = count / total * 100
        bars = int(pct / 5)  # 1 block ≈ 5 %
        table.add_row(
            f"[{colour}]{proto}[/{colour}]",
            str(count),
            f"{pct:4.1f}% {'█' * bars}",
        )

    return Panel(table, title="[bold]Protocols[/bold]", border_style="blue")


def _render_top_sources(snap: DashboardSnapshot) -> Panel:
    table = Table(
        show_header=True, header_style="bold", box=None, expand=True, padding=(0, 1)
    )
    table.add_column("Source IP", style="cyan")
    table.add_column("Pkts", justify="right", width=6)

    for ip, cnt in snap.top_sources[:8]:
        table.add_row(ip, str(cnt))

    return Panel(table, title="[bold]Top Sources[/bold]", border_style="magenta")


def _render_recent(snap: DashboardSnapshot) -> Panel:
    table = Table(
        show_header=True, header_style="bold", box=None, expand=True, padding=(0, 1)
    )
    table.add_column("Time", style="dim", width=7, no_wrap=True)
    table.add_column("Source", width=22, no_wrap=True)
    table.add_column("Destination", width=22, no_wrap=True)
    table.add_column("Proto", width=6, no_wrap=True)
    table.add_column("Len", justify="right", width=6)
    table.add_column("Info", no_wrap=True)

    for row in reversed(snap.recent):
        colour = _PROTO_COLOURS.get(row.protocol, "white")
        table.add_row(
            f"{row.elapsed:6.1f}s",
            row.src,
            row.dst,
            f"[{colour}]{row.protocol}[/{colour}]",
            str(row.length),
            row.info[:60] if row.info else "",
        )

    return Panel(table, title="[bold]Recent Packets[/bold]", border_style="green")


def _render_footer(snap: DashboardSnapshot) -> Panel:
    text = Text()
    text.append("  Packets: ", style="dim")
    text.append(f"{snap.total_packets:,}", style="bold white")
    text.append("    Rate: ", style="dim")
    text.append(f"{snap.pps:.1f} pkt/s", style="bold cyan")
    text.append("    Bytes: ", style="dim")
    text.append(_fmt_bytes(snap.total_bytes), style="bold green")
    text.append("    Alerts: ", style="dim")
    alert_style = "bold red" if snap.alert_count > 0 else "bold white"
    text.append(str(snap.alert_count), style=alert_style)
    text.append("    Press Ctrl+C to stop", style="dim italic")
    return Panel(text, border_style="dim")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"
