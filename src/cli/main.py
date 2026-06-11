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

import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import print_banner
from src.core.config import AppConfig
from src.core.exceptions import (
    CaptureError,
    InsufficientPermissionsError,
    InterfaceError,
)
from src.core.logger import get_logger, setup_logging

console = Console()
err_console = Console(stderr=True)
logger = get_logger(__name__)

# Protocol → Rich colour mapping (used in sniff output)
_PROTO_COLOURS = {
    "HTTP":  "bold green",
    "DNS":   "bold yellow",
    "TCP":   "bold cyan",
    "UDP":   "bold blue",
    "ARP":   "bold magenta",
    "ICMP":  "bold bright_magenta",
    "OTHER": "dim white",
}


# ──────────────────────────────────────────────────────────────────────────────
# Root command group
# ──────────────────────────────────────────────────────────────────────────────

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(version="1.0.0", prog_name="nst")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    metavar="FILE",
    help="Path to a YAML config file (default: config/default.yaml).",
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
@click.option("-i", "--interface", default=None, metavar="IFACE",
              help="Network interface to capture on (default: auto-detect).")
@click.option("-c", "--count", default=0, type=click.IntRange(min=0),
              show_default=True,
              help="Packets to capture before stopping (0 = unlimited).")
@click.option("-f", "--filter", "bpf_filter", default="", metavar="EXPR",
              help='BPF filter expression (e.g. "tcp port 80", "arp").')
@click.option("-o", "--output", default=None, metavar="FILE",
              help="Write captured packets to a .pcap file.")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Show full packet summary (default: concise one-liner).")
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

    # Apply CLI flags over config-file values
    if interface:
        cfg.network.interface = interface
    if count:
        cfg.sniffer.packet_count = count
    if bpf_filter:
        cfg.sniffer.filter = bpf_filter
    if output:
        cfg.sniffer.output_file = output

    # Late imports so startup is fast when --help is used
    from src.analyzer.engine import AnalysisEngine
    from src.sniffer.capture import PacketCapture
    from src.sniffer.interface import InterfaceManager
    from src.sniffer.parsers import ParserDispatcher

    # Resolve and validate the interface
    try:
        resolved = InterfaceManager.resolve(cfg.network.interface)
        cfg.network.interface = resolved
    except InterfaceError as exc:
        err_console.print(f"[red]Interface error:[/red] {exc}")
        raise SystemExit(1)

    iface_label = cfg.network.interface or "auto-detect"

    console.print(
        Panel(
            f"Interface         : [cyan]{iface_label}[/cyan]\n"
            f"Filter            : [cyan]{cfg.sniffer.filter or '(none)'}[/cyan]\n"
            f"Count             : [cyan]{cfg.sniffer.packet_count or 'unlimited'}[/cyan]\n"
            f"Output            : [cyan]{cfg.sniffer.output_file or '(none)'}[/cyan]\n"
            f"Credential scan   : [cyan]{cfg.analyzer.detect_credentials}[/cyan]\n"
            f"Threat detection  : [cyan]{cfg.analyzer.alert_on_suspicious}[/cyan]\n\n"
            "Press [bold]Ctrl+C[/bold] to stop.",
            title="[bold cyan]Packet Capture — Started[/bold cyan]",
            border_style="cyan",
        )
    )

    capture = PacketCapture(cfg.sniffer, cfg.network)
    engine = AnalysisEngine(cfg.analyzer)

    def on_packet(pkt: object) -> None:  # type: ignore[type-arg]
        from scapy.packet import Packet as ScapyPacket

        if not isinstance(pkt, ScapyPacket):
            return

        parsed = ParserDispatcher.dispatch(pkt)

        proto = parsed.protocol.value
        colour = _PROTO_COLOURS.get(proto, "white")
        ts = parsed.timestamp.strftime("%H:%M:%S")

        src = parsed.src_ip
        dst = parsed.dst_ip
        if parsed.src_port is not None and parsed.dst_port is not None:
            src = f"{src}:{parsed.src_port}"
            dst = f"{dst}:{parsed.dst_port}"

        flags_str = f" [{parsed.flags}]" if parsed.flags else ""
        summary = parsed.summary[:70] if not verbose else parsed.summary

        console.print(
            f"[dim]{ts}[/dim]  "
            f"[{colour}]{proto:<5}[/{colour}]  "
            f"[white]{src}[/white] → [white]{dst}[/white]"
            f"[dim]{flags_str}[/dim]  "
            f"[italic dim]{summary}[/italic dim]  "
            f"[dim]{parsed.length}B[/dim]"
        )

        # Run analysis (credential detection + threat detection)
        engine.process(parsed)

    try:
        capture.start(on_packet)
    except KeyboardInterrupt:
        pass
    except InsufficientPermissionsError as exc:
        err_console.print(
            Panel(
                f"[bold red]{exc}[/bold red]\n\nRe-run with: [bold]sudo nst sniff[/bold]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
    except CaptureError as exc:
        err_console.print(f"[red]Capture failed:[/red] {exc}")
        raise SystemExit(1)
    finally:
        _print_session_summary(capture.packet_count, engine)


# ──────────────────────────────────────────────────────────────────────────────
# `nst arp-watch`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("arp-watch")
@click.option("-i", "--interface", default=None, metavar="IFACE",
              help="Network interface to monitor (default: auto-detect).")
@click.option("--interval", default=None, type=click.FloatRange(min=0.1),
              metavar="SECS",
              help="ARP table snapshot interval in seconds (default from config).")
@click.option("--trusted-ip", "trusted_ips", multiple=True, metavar="IP",
              help="IP address to treat as trusted; may be repeated.")
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
    from src.sniffer.interface import InterfaceManager

    try:
        iface_list = InterfaceManager.list_interfaces()
        default_name = ""
        try:
            default_name = InterfaceManager.get_default()
        except InterfaceError:
            pass
    except InterfaceError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1)

    if not iface_list:
        console.print("[yellow]No network interfaces found.[/yellow]")
        return

    table = Table(
        title="Available Network Interfaces",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("Interface", style="bold cyan", no_wrap=True)
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="dim")
    table.add_column("Description", style="dim")
    table.add_column("Default", justify="center")

    for iface in iface_list:
        is_default = "[bold yellow]★[/bold yellow]" if iface.name == default_name else ""
        desc = iface.description if iface.description != iface.name else ""
        table.add_row(
            iface.name,
            iface.ip or "[dim](none)[/dim]",
            iface.mac or "[dim](none)[/dim]",
            desc,
            is_default,
        )

    console.print(table)
    if default_name:
        console.print(
            f"\n[dim]★ Default capture interface:[/dim] [cyan]{default_name}[/cyan]"
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
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("Section", style="cyan", no_wrap=True, min_width=14)
    table.add_column("Setting", style="white", no_wrap=True, min_width=28)
    table.add_column("Value", style="green")

    table.add_row("network", "interface",
                  cfg.network.interface or "[dim]auto-detect[/dim]")
    table.add_row("", "promiscuous", str(cfg.network.promiscuous))
    table.add_row("", "capture_timeout",
                  f"{cfg.network.capture_timeout}s"
                  if cfg.network.capture_timeout else "[dim]unlimited[/dim]")

    table.add_row("sniffer", "packet_count",
                  str(cfg.sniffer.packet_count)
                  if cfg.sniffer.packet_count else "[dim]unlimited[/dim]")
    table.add_row("", "filter", cfg.sniffer.filter or "[dim](none)[/dim]")
    table.add_row("", "output_file",
                  cfg.sniffer.output_file or "[dim](none)[/dim]")

    table.add_row("analyzer", "detect_credentials",
                  str(cfg.analyzer.detect_credentials))
    table.add_row("", "port_scan_threshold",
                  str(cfg.analyzer.suspicious_port_scan_threshold))
    table.add_row("", "alert_on_suspicious",
                  str(cfg.analyzer.alert_on_suspicious))

    table.add_row("arp_detector", "check_interval",
                  f"{cfg.arp_detector.check_interval}s")
    table.add_row("", "alert_threshold",
                  str(cfg.arp_detector.alert_threshold))
    table.add_row("", "trusted_ips",
                  ", ".join(cfg.arp_detector.trusted_ips)
                  or "[dim](none)[/dim]")

    table.add_row("logging", "level", cfg.logging.level)
    table.add_row("", "file", cfg.logging.file)
    table.add_row("", "max_bytes", f"{cfg.logging.max_bytes:,} bytes")
    table.add_row("", "backup_count", str(cfg.logging.backup_count))

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _print_session_summary(packet_count: int, engine: "AnalysisEngine") -> None:  # type: ignore[name-defined]
    """Print a Rich statistics table after the capture session ends."""
    from src.analyzer.engine import AnalysisEngine as _AE  # local import avoids circular

    stats = engine.stats
    alerts = engine.alerts

    console.print()
    console.rule("[bold cyan]Session Summary[/bold cyan]")

    # ── Overview ───────────────────────────────────────────────────────────────
    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="dim", no_wrap=True)
    overview.add_column(style="bold white")
    overview.add_row("Total packets :", str(packet_count))
    overview.add_row("Total bytes   :", f"{stats.total_bytes:,}")
    overview.add_row("Credentials   :", f"[bold red]{alerts.credential_count}[/bold red]")
    overview.add_row("Threats       :", f"[bold red]{alerts.threat_count}[/bold red]")
    console.print(overview)
    console.print()

    if stats.is_empty():
        console.print("[dim]No packets analysed.[/dim]")
        return

    # ── Protocol breakdown ─────────────────────────────────────────────────────
    proto_table = Table(
        title="Protocol Breakdown",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Packets", justify="right")
    proto_table.add_column("Bytes", justify="right")
    proto_table.add_column("Share", justify="right")

    for proto, pkt_count, byte_count, pct in stats.protocol_breakdown():
        proto_table.add_row(
            proto.value,
            str(pkt_count),
            f"{byte_count:,}",
            f"{pct:.1f}%",
        )
    console.print(proto_table)

    # ── Top talkers ────────────────────────────────────────────────────────────
    talkers = stats.top_talkers(5)
    ports = stats.top_ports(5)

    if talkers:
        console.print()
        talker_table = Table(
            title="Top Source IPs",
            header_style="bold magenta",
            border_style="bright_blue",
            show_lines=False,
        )
        talker_table.add_column("IP Address", style="cyan")
        talker_table.add_column("Packets", justify="right")
        for ip, cnt in talkers:
            talker_table.add_row(ip, str(cnt))
        console.print(talker_table)

    if ports:
        console.print()
        port_table = Table(
            title="Top Destination Ports",
            header_style="bold magenta",
            border_style="bright_blue",
            show_lines=False,
        )
        port_table.add_column("Port", style="cyan")
        port_table.add_column("Hits", justify="right")
        for port, cnt in ports:
            port_table.add_row(str(port), str(cnt))
        console.print(port_table)


def _require_root() -> None:
    """
    Abort with a clear message if the process is not running as root.

    Scapy requires raw socket access which the OS restricts to uid 0
    on Linux and macOS.
    """
    if os.geteuid() != 0:
        err_console.print(
            Panel(
                "[bold red]Root privileges required.[/bold red]\n\n"
                "Packet capture and ARP monitoring use raw sockets,\n"
                "which require administrator access.\n\n"
                "Re-run with:  [bold]sudo nst[/bold] [dim]<command>[/dim]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
