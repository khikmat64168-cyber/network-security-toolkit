"""Rich display helpers for geolocation results."""
from __future__ import annotations

from typing import List

from rich.console import Console
from rich.table import Table

from nst.geoip.models import GeoResult

console = Console()


def format_location(result: GeoResult) -> str:
    """Return a short Rich-markup location string for inline use."""
    if result.is_private:
        return "[dim]Private Range[/dim]"
    if not result.success:
        return "[dim]Unknown[/dim]"
    return f"{result.flag}  {result.country}"


def format_city(result: GeoResult) -> str:
    if result.is_private or not result.success:
        return "[dim]—[/dim]"
    return result.city or "[dim]—[/dim]"


def print_geo_table(results: List[GeoResult]) -> None:
    """Render a Rich table of geolocation results to stdout."""
    table = Table(
        title="IP Geolocation Results",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    table.add_column("IP / Host", style="bold cyan", no_wrap=True)
    table.add_column(" ", no_wrap=True)          # flag column
    table.add_column("Country", style="white")
    table.add_column("City / Region", style="dim")
    table.add_column("ISP", style="dim")
    table.add_column("Coordinates", style="dim", no_wrap=True)

    for r in results:
        if r.is_private:
            table.add_row(
                r.ip, "🏠", "[dim]Private Range[/dim]", "—", "—", "—"
            )
        elif not r.success:
            table.add_row(
                r.ip, "❓",
                f"[red]Error:[/red] {r.error}", "—", "—", "—"
            )
        else:
            city_region = ", ".join(p for p in (r.city, r.region) if p) or "—"
            coords = (
                f"{r.latitude:.2f}, {r.longitude:.2f}"
                if r.latitude or r.longitude
                else "—"
            )
            table.add_row(
                r.ip,
                r.flag,
                r.country or "—",
                city_region,
                r.isp or "—",
                coords,
            )

    console.print(table)
