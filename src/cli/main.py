"""
Main CLI for the Network Security Toolkit.

Entry point: `nst` (installed via pyproject.toml) or `python main.py`.

Subcommands
───────────
  sniff       — Capture and analyse network packets in real time.
  arp-watch   — Monitor ARP traffic for spoofing / MITM attacks.
  interfaces  — List available network interfaces.
  status      — Display current configuration and toolkit status.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import print_banner
from src.core.config import AppConfig
from src.core.exceptions import InsufficientPermissionsError
from src.core.logger import get_logger, setup_logging

console = Console()
err_console = Console(stderr=True)


# ──────────────────────────────────────────────────────────────────────────────
# Root command group
# ──────────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="1.0.0", prog_name="nst")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    metavar="FILE",
    help="Path to a YAML configuration file (default: config/default.yaml).",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Force DEBUG log level for this run.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[Path], debug: bool) -> None:
    """
    \b
    Network Security Toolkit — packet analysis & ARP spoofing detection.

    \b
    Subcommands:
      sniff       Capture and analyse packets in real time
      arp-watch   Detect ARP spoofing and MITM attacks
      interfaces  List available network interfaces
      status      Show current configuration

    Most operations require root / sudo privileges.
    """
    ctx.ensure_object(dict)

    app_config = AppConfig.load(config_path=config_path)
    if debug:
        app_config.logging.level = "DEBUG"

    setup_logging(app_config.logging)
    ctx.obj["config"] = app_config

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


# ──────────────────────────────────────────────────────────────────────────────
# `nst sniff`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("sniff")
@click.option(
    "-i", "--interface",
    default=None,
    metavar="IFACE",
    help="Network interface to capture on (default: auto-detect).",
)
@click.option(
    "-c", "--count",
    default=0,
    type=click.IntRange(min=0),
    show_default=True,
    help="Packets to capture before stopping (0 = unlimited).",
)
@click.option(
    "-f", "--filter",
    "bpf_filter",
    default="",
    metavar="EXPR",
    help='BPF filter expression (e.g. "tcp port 80", "arp").',
)
@click.option(
    "-o", "--output",
    default=None,
    metavar="FILE",
    help="Write captured packets to a .pcap file.",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Print every packet's summary to the console.",
)
@click.pass_context
def sniff(
    ctx: click.Context,
    interface: Optional[str],
    count: int,
    bpf_filter: str,
    output: Optional[str],
    verbose: bool,
) -> None:
    """Capture and analyse network packets in real time."""
    _require_root()
    cfg: AppConfig = ctx.obj["config"]

    # CLI flags override config-file values
    if interface:
        cfg.network.interface = interface
    if count:
        cfg.sniffer.packet_count = count
    if bpf_filter:
        cfg.sniffer.filter = bpf_filter
    if output:
        cfg.sniffer.output_file = output

    console.print(
        Panel(
            Text(
                "Packet Sniffer will be fully implemented in Phase 2.\n"
                f"Interface : {cfg.network.interface or 'auto-detect'}\n"
                f"Count     : {cfg.sniffer.packet_count or 'unlimited'}\n"
                f"Filter    : {cfg.sniffer.filter or '(none)'}\n"
                f"Output    : {cfg.sniffer.output_file or '(none)'}",
                style="yellow",
            ),
            title="[bold cyan]nst sniff[/bold cyan]",
            border_style="cyan",
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# `nst arp-watch`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("arp-watch")
@click.option(
    "-i", "--interface",
    default=None,
    metavar="IFACE",
    help="Network interface to monitor (default: auto-detect).",
)
@click.option(
    "--interval",
    default=None,
    type=click.FloatRange(min=0.1),
    metavar="SECS",
    help="ARP table snapshot interval in seconds (default from config).",
)
@click.option(
    "--trusted-ip",
    "trusted_ips",
    multiple=True,
    metavar="IP",
    help="IP address to treat as trusted; may be repeated.",
)
@click.pass_context
def arp_watch(
    ctx: click.Context,
    interface: Optional[str],
    interval: Optional[float],
    trusted_ips: tuple[str, ...],
) -> None:
    """Monitor ARP traffic and detect spoofing / MITM attacks."""
    _require_root()
    cfg: AppConfig = ctx.obj["config"]

    if interface:
        cfg.network.interface = interface
    if interval is not None:
        cfg.arp_detector.check_interval = interval
    if trusted_ips:
        cfg.arp_detector.trusted_ips = list(trusted_ips)

    console.print(
        Panel(
            Text(
                "ARP Spoofing Detector will be fully implemented in Phase 4.\n"
                f"Interface : {cfg.network.interface or 'auto-detect'}\n"
                f"Interval  : {cfg.arp_detector.check_interval}s\n"
                f"Trusted   : {cfg.arp_detector.trusted_ips or '(none)'}",
                style="yellow",
            ),
            title="[bold cyan]nst arp-watch[/bold cyan]",
            border_style="cyan",
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# `nst interfaces`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("interfaces")
@click.pass_context
def interfaces(ctx: click.Context) -> None:
    """List available network interfaces."""
    _require_root()
    console.print(
        Panel(
            "[yellow]Interface listing will be fully implemented in Phase 2.[/yellow]",
            title="[bold cyan]nst interfaces[/bold cyan]",
            border_style="cyan",
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# `nst status`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Display current configuration and toolkit status."""
    cfg: AppConfig = ctx.obj["config"]

    table = Table(
        title="Network Security Toolkit — Configuration",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("Section", style="cyan", no_wrap=True, min_width=14)
    table.add_column("Setting", style="white", no_wrap=True, min_width=28)
    table.add_column("Value", style="green")

    # Network
    table.add_row("network", "interface", cfg.network.interface or "[dim]auto-detect[/dim]")
    table.add_row("", "promiscuous", str(cfg.network.promiscuous))
    table.add_row("", "capture_timeout", f"{cfg.network.capture_timeout}s" if cfg.network.capture_timeout else "[dim]unlimited[/dim]")

    # Sniffer
    table.add_row("sniffer", "packet_count", str(cfg.sniffer.packet_count) if cfg.sniffer.packet_count else "[dim]unlimited[/dim]")
    table.add_row("", "filter", cfg.sniffer.filter or "[dim](none)[/dim]")
    table.add_row("", "output_file", cfg.sniffer.output_file or "[dim](none)[/dim]")

    # Analyzer
    table.add_row("analyzer", "detect_credentials", str(cfg.analyzer.detect_credentials))
    table.add_row("", "port_scan_threshold", str(cfg.analyzer.suspicious_port_scan_threshold))
    table.add_row("", "alert_on_suspicious", str(cfg.analyzer.alert_on_suspicious))

    # ARP detector
    table.add_row("arp_detector", "check_interval", f"{cfg.arp_detector.check_interval}s")
    table.add_row("", "alert_threshold", str(cfg.arp_detector.alert_threshold))
    table.add_row("", "trusted_ips", ", ".join(cfg.arp_detector.trusted_ips) or "[dim](none)[/dim]")

    # Logging
    table.add_row("logging", "level", cfg.logging.level)
    table.add_row("", "file", cfg.logging.file)
    table.add_row("", "max_bytes", f"{cfg.logging.max_bytes:,} bytes")
    table.add_row("", "backup_count", str(cfg.logging.backup_count))

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _require_root() -> None:
    """
    Abort with a helpful message if the process is not running as root.

    Scapy requires raw socket access which is restricted to uid 0 on
    Linux and macOS.  Raising InsufficientPermissionsError here gives
    callers a typed exception to catch in tests.
    """
    import os
    if os.geteuid() != 0:
        err_console.print(
            Panel(
                "[bold red]Root privileges required.[/bold red]\n\n"
                "Packet capture and ARP monitoring use raw sockets, which\n"
                "require administrator access.\n\n"
                "Re-run with:  [bold]sudo nst[/bold] [dim]<command>[/dim]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
