"""
ASCII banner and startup display for the Network Security Toolkit.
"""
from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from nst import __version__

_BANNER_ART = """\
 ███╗   ██╗███████╗████████╗
 ████╗  ██║██╔════╝╚══██╔══╝
 ██╔██╗ ██║███████╗   ██║
 ██║╚██╗██║╚════██║   ██║
 ██║ ╚████║███████║   ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝
  Network Security Toolkit  v{version}""".format(version=__version__)

_SUBTITLE = (
    "  [dim]Packet Sniffer[/dim]  [bright_blue]•[/bright_blue]  "
    "[dim]ARP Spoofing Detector[/dim]"
)

_CONSOLE = Console()


def print_banner() -> None:
    """Print the startup banner to stdout."""
    banner_text = Text(_BANNER_ART, style="bold cyan", justify="center")
    subtitle = Text.from_markup(_SUBTITLE, justify="center")

    combined = Text()
    combined.append_text(banner_text)
    combined.append("\n")
    combined.append_text(subtitle)

    _CONSOLE.print(
        Panel(
            Align.center(combined),
            border_style="bright_blue",
            padding=(0, 4),
        )
    )
    _CONSOLE.print()


def print_section(title: str) -> None:
    """Print a section divider with *title*."""
    _CONSOLE.rule(f"[bold cyan]{title}[/bold cyan]")
