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
from typing import TYPE_CHECKING, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.cli.banner import print_banner
from src.core.config import AppConfig
from src.core.exceptions import (
    CaptureError,
    ConfigurationError,
    InsufficientPermissionsError,
    InterfaceError,
    NetworkToolkitError,
)
from src.core.logger import get_logger, setup_logging

if TYPE_CHECKING:
    from src.analyzer.engine import AnalysisEngine
    from src.arp_detector.monitor import ARPMonitor
    from src.dns_detector.monitor import DNSMonitor

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
      dns-watch   Detect DNS spoofing and cache poisoning
      dashboard   Live traffic dashboard with real-time statistics
      interfaces  List available network interfaces
      status      Show current configuration

    Most operations require root / sudo privileges.
    """
    ctx.ensure_object(dict)

    try:
        app_config = AppConfig.load(config_path=config_path)
    except ConfigurationError as exc:
        err_console.print(
            Panel(
                f"[bold red]{exc}[/bold red]",
                title="[red]Configuration Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)

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

    def on_packet(pkt: object) -> None:
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
@click.option("--gateway", default=None, metavar="IP",
              help="Gateway IP to monitor for MAC changes (critical severity).")
@click.pass_context
def arp_watch(
    ctx: click.Context,
    interface: Optional[str],
    interval: Optional[float],
    trusted_ips: tuple[str, ...],
    gateway: Optional[str],
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
    if gateway:
        cfg.arp_detector.gateway_ip = gateway

    from src.arp_detector.monitor import ARPMonitor

    monitor = ARPMonitor(cfg.arp_detector, cfg.network)

    iface_label = cfg.network.interface or "auto-detect"
    gateway_label = cfg.arp_detector.gateway_ip or "(not set)"
    trusted_label = ", ".join(cfg.arp_detector.trusted_ips) or "(none)"

    console.print(
        Panel(
            f"Interface  : [cyan]{iface_label}[/cyan]\n"
            f"Gateway IP : [cyan]{gateway_label}[/cyan]\n"
            f"Trusted IPs: [cyan]{trusted_label}[/cyan]\n\n"
            "Monitoring ARP traffic — press [bold]Ctrl+C[/bold] to stop.",
            title="[bold cyan]ARP Spoofing Monitor — Started[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        monitor.start()
    except KeyboardInterrupt:
        pass
    except InsufficientPermissionsError as exc:
        err_console.print(
            Panel(
                f"[bold red]{exc}[/bold red]\n\nRe-run with: [bold]sudo nst arp-watch[/bold]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
    except CaptureError as exc:
        err_console.print(f"[red]ARP capture failed:[/red] {exc}")
        raise SystemExit(1)
    finally:
        _print_arp_summary(monitor)


# ──────────────────────────────────────────────────────────────────────────────
# `nst dns-watch`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("dns-watch")
@click.option("-i", "--interface", default=None, metavar="IFACE",
              help="Network interface to monitor (default: auto-detect).")
@click.option("--trusted-domain", "trusted_domains", multiple=True, metavar="DOMAIN",
              help="Domain to treat as trusted; may be repeated.")
@click.option("--no-query-tracking", is_flag=True, default=False,
              help="Disable unsolicited-response detection.")
@click.pass_context
def dns_watch(
    ctx: click.Context,
    interface: Optional[str],
    trusted_domains: tuple,
    no_query_tracking: bool,
) -> None:
    """Monitor DNS traffic and detect spoofing / cache-poisoning attacks."""
    _require_root()
    cfg: AppConfig = ctx.obj["config"]

    if interface:
        cfg.network.interface = interface
    if trusted_domains:
        cfg.dns_detector.trusted_domains = list(trusted_domains)
    if no_query_tracking:
        cfg.dns_detector.track_queries = False

    from src.dns_detector.monitor import DNSMonitor

    monitor = DNSMonitor(cfg.dns_detector, cfg.network)

    iface_label = cfg.network.interface or "auto-detect"
    trusted_label = ", ".join(cfg.dns_detector.trusted_domains) or "(none)"

    console.print(
        Panel(
            f"Interface       : [cyan]{iface_label}[/cyan]\n"
            f"Trusted domains : [cyan]{trusted_label}[/cyan]\n"
            f"Query tracking  : [cyan]{cfg.dns_detector.track_queries}[/cyan]\n\n"
            "Monitoring DNS traffic — press [bold]Ctrl+C[/bold] to stop.",
            title="[bold cyan]DNS Spoofing Monitor — Started[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        monitor.start()
    except KeyboardInterrupt:
        pass
    except InsufficientPermissionsError as exc:
        err_console.print(
            Panel(
                f"[bold red]{exc}[/bold red]\n\nRe-run with: [bold]sudo nst dns-watch[/bold]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
    except CaptureError as exc:
        err_console.print(f"[red]DNS capture failed:[/red] {exc}")
        raise SystemExit(1)
    finally:
        _print_dns_summary(monitor)


# ──────────────────────────────────────────────────────────────────────────────
# `nst dashboard`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("dashboard")
@click.option("-i", "--interface", default=None, metavar="IFACE",
              help="Network interface to capture on (default: auto-detect).")
@click.option("-c", "--count", default=0, type=click.IntRange(min=0),
              show_default=True,
              help="Packets to capture before stopping (0 = unlimited).")
@click.option("-f", "--filter", "bpf_filter", default="", metavar="EXPR",
              help='BPF filter expression (e.g. "tcp port 80").')
@click.option("--refresh-rate", default=4, type=click.IntRange(min=1, max=60),
              show_default=True,
              help="Dashboard refresh rate in renders/second.")
@click.pass_context
def dashboard(
    ctx: click.Context,
    interface: Optional[str],
    count: int,
    bpf_filter: str,
    refresh_rate: int,
) -> None:
    """Live traffic dashboard — real-time protocol and IP statistics."""
    _require_root()
    cfg: AppConfig = ctx.obj["config"]

    if interface:
        cfg.network.interface = interface
    if count:
        cfg.sniffer.packet_count = count
    if bpf_filter:
        cfg.sniffer.filter = bpf_filter

    from src.analyzer.engine import AnalysisEngine
    from src.dashboard.display import DashboardDisplay
    from src.sniffer.capture import PacketCapture
    from src.sniffer.interface import InterfaceManager
    from src.sniffer.parsers import ParserDispatcher

    try:
        resolved = InterfaceManager.resolve(cfg.network.interface)
        cfg.network.interface = resolved
    except InterfaceError as exc:
        err_console.print(f"[red]Interface error:[/red] {exc}")
        raise SystemExit(1)

    capture = PacketCapture(cfg.sniffer, cfg.network)
    engine = AnalysisEngine(cfg.analyzer)
    display = DashboardDisplay(refresh_rate=refresh_rate)

    try:
        with display:
            def on_packet(pkt: object) -> None:
                from scapy.packet import Packet as ScapyPacket

                if not isinstance(pkt, ScapyPacket):
                    return
                parsed = ParserDispatcher.dispatch(pkt)
                prev_alerts = (
                    engine.alerts.credential_count + engine.alerts.threat_count
                )
                engine.process(parsed)
                display.record(parsed)
                if (
                    engine.alerts.credential_count + engine.alerts.threat_count
                    > prev_alerts
                ):
                    display.record_alert()

            capture.start(on_packet)
    except KeyboardInterrupt:
        pass
    except InsufficientPermissionsError as exc:
        err_console.print(
            Panel(
                f"[bold red]{exc}[/bold red]\n\nRe-run with: [bold]sudo nst dashboard[/bold]",
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
    table.add_row("", "gateway_ip",
                  cfg.arp_detector.gateway_ip or "[dim](none)[/dim]")

    table.add_row("logging", "level", cfg.logging.level)
    table.add_row("", "file", cfg.logging.file)
    table.add_row("", "max_bytes", f"{cfg.logging.max_bytes:,} bytes")
    table.add_row("", "backup_count", str(cfg.logging.backup_count))

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _print_session_summary(packet_count: int, engine: "AnalysisEngine") -> None:
    """Print a Rich statistics table after the capture session ends."""
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


def _print_arp_summary(monitor: "ARPMonitor") -> None:
    """Print ARP session statistics after arp-watch exits."""
    event_log = monitor.event_logger
    alerts = monitor.alert_manager

    console.print()
    console.rule("[bold cyan]ARP Session Summary[/bold cyan]")

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="dim", no_wrap=True)
    overview.add_column(style="bold white")
    overview.add_row("ARP packets seen  :", str(monitor.packet_count))
    overview.add_row("Total events      :", str(event_log.total))
    high_priority_count = len(event_log.high_priority_events())
    overview.add_row("High-priority     :", f"[bold red]{high_priority_count}[/bold red]")
    overview.add_row("Alerts shown      :", f"[bold red]{alerts.total_alerts}[/bold red]")
    overview.add_row("Critical alerts   :", f"[bold red]{alerts.critical_alerts}[/bold red]")
    console.print(overview)
    console.print()

    entries = monitor.table.all_entries()
    if not entries:
        console.print("[dim]No ARP bindings observed.[/dim]")
        return

    arp_table = Table(
        title="Observed ARP Bindings",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    arp_table.add_column("IP Address", style="cyan", no_wrap=True)
    arp_table.add_column("MAC Address", style="green")
    arp_table.add_column("Packets", justify="right")
    arp_table.add_column("Trusted", justify="center")

    for entry in entries:
        trusted_label = "[bold yellow]YES[/bold yellow]" if entry.is_trusted else ""
        arp_table.add_row(
            entry.ip,
            entry.mac,
            str(entry.packet_count),
            trusted_label,
        )
    console.print(arp_table)


def _print_dns_summary(monitor: "DNSMonitor") -> None:
    """Print DNS session statistics after dns-watch exits."""
    event_log = monitor.event_logger
    alerts = monitor.alert_manager

    console.print()
    console.rule("[bold cyan]DNS Session Summary[/bold cyan]")

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="dim", no_wrap=True)
    overview.add_column(style="bold white")
    overview.add_row("DNS packets seen :", str(monitor.packet_count))
    overview.add_row("Total events     :", str(event_log.total))
    overview.add_row(
        "High-priority    :",
        f"[bold red]{len(event_log.high_priority_events())}[/bold red]",
    )
    overview.add_row(
        "Alerts shown     :",
        f"[bold red]{alerts.total_alerts}[/bold red]",
    )
    console.print(overview)
    console.print()

    entries = monitor.table.all_entries()
    if not entries:
        console.print("[dim]No DNS resolutions observed.[/dim]")
        return

    dns_table = Table(
        title="Observed DNS Resolutions",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    dns_table.add_column("Domain", style="cyan")
    dns_table.add_column("Current IP", style="green")
    dns_table.add_column("Unique IPs", justify="right")
    dns_table.add_column("Queries", justify="right")

    for entry in entries:
        ip_count = len(entry.ips_seen)
        ip_style = "bold red" if ip_count > 1 else "green"
        dns_table.add_row(
            entry.domain,
            entry.current_ip,
            f"[{ip_style}]{ip_count}[/{ip_style}]",
            str(entry.packet_count),
        )
    console.print(dns_table)


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


def main() -> None:
    """
    Top-level entry point used by both `python main.py` and the
    installed `nst` console script (see pyproject.toml).

    Every command already handles its own expected failure modes
    (permission errors, capture errors, config errors) with friendly
    Rich panels. This wrapper is the last line of defense: it catches
    any NetworkToolkitError or unexpected exception that escapes a
    command so the user never sees a raw Python traceback, while still
    logging the full exception for post-mortem debugging.
    """
    try:
        cli()
    except NetworkToolkitError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        logger.exception("Unhandled exception")
        err_console.print(
            "[bold red]An unexpected error occurred.[/bold red] "
            "See the log file for details."
        )
        raise SystemExit(1)
