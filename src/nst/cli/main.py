"""
Main CLI for the Network Security Toolkit.

Entry point: `nst` (installed via pyproject.toml) or `python main.py`.

Subcommands
───────────
  sniff       — Capture and analyse network packets in real time.
  arp-watch   — Monitor ARP traffic for spoofing / MITM attacks.
  dns-watch   — Monitor DNS traffic for spoofing / cache poisoning.
  mac-watch   — Detect MAC flooding / CAM table overflow.
  tls-scan    — Inspect TLS certificates for security issues.
  report      — Generate a self-contained HTML security report.
  geoip       — Look up IP / hostname geolocation.
  dashboard   — Live traffic dashboard.
  web         — Local browser dashboard (FastAPI, loopback only).
  interfaces  — List available network interfaces.
  status      — Display current configuration and toolkit status.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nst import __version__
from nst.cli.banner import print_banner
from nst.core.config import AppConfig
from nst.core.exceptions import (
    CaptureError,
    ConfigurationError,
    InsufficientPermissionsError,
    InterfaceError,
    NetworkToolkitError,
)
from nst.core.logger import get_logger, setup_logging
from nst.core.paths import resolve_state_path

if TYPE_CHECKING:
    from nst.analyzer.engine import AnalysisEngine
    from nst.arp_detector.monitor import ARPMonitor
    from nst.dns_detector.monitor import DNSMonitor
    from nst.mac_detector.monitor import MACMonitor
    from nst.tls_inspector.result import TLSScanResult

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
@click.version_option(version=__version__, prog_name="nst")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    metavar="FILE",
    help="Path to a YAML config file "
         "(default: $NST_CONFIG, ~/.config/nst/config.yaml, then bundled defaults).",
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
    Network Security Toolkit — packet analysis & LAN attack detection.

    \b
    Subcommands:
      sniff       Capture and analyse packets in real time
      arp-watch   Detect ARP spoofing and MITM attacks
      dns-watch   Detect DNS spoofing and cache poisoning
      mac-watch   Detect MAC flooding / CAM table overflow attacks
      tls-scan    Inspect TLS certificates for security issues
      report      Generate an HTML security report
      geoip       Look up geolocation for IP addresses or hostnames
      dashboard   Live traffic dashboard with real-time statistics
      web         Local browser dashboard (http://127.0.0.1 only)
      interfaces  List available network interfaces
      status      Show current configuration

    \b
    Capture subcommands (sniff, arp-watch, dns-watch, mac-watch, dashboard)
    require root / sudo.  tls-scan, report, geoip and status do not.
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
    from nst.analyzer.engine import AnalysisEngine
    from nst.sniffer.capture import PacketCapture
    from nst.sniffer.interface import InterfaceManager
    from nst.sniffer.parsers import ParserDispatcher

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

    from nst.arp_detector.monitor import ARPMonitor

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
    trusted_domains: tuple[str, ...],
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

    from nst.dns_detector.monitor import DNSMonitor

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
# `nst tls-scan`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("tls-scan")
@click.argument("hosts", nargs=-1, metavar="HOST[:PORT]")
@click.option("--port", default=443, show_default=True, type=int,
              help="Default port when not included in the HOST argument.")
@click.option("--timeout", default=10, show_default=True, type=int,
              help="Connection timeout in seconds per host.")
@click.option("--save-report", "report_path", default=None,
              type=click.Path(path_type=Path),
              metavar="FILE",
              help="Save an HTML security report to FILE after scanning.")
@click.option("--open", "open_browser", is_flag=True, default=False,
              help="Open the report in the default browser (requires --save-report).")
@click.pass_context
def tls_scan(
    ctx: click.Context,
    hosts: tuple[str, ...],
    port: int,
    timeout: int,
    report_path: Optional[Path],
    open_browser: bool,
) -> None:
    """Inspect TLS certificates — expiry, cipher, and version checks.

    \b
    Examples:
      nst tls-scan github.com
      nst tls-scan github.com:443 example.com:8443
      nst tls-scan --timeout 5 github.com google.com
      nst tls-scan --save-report report.html --open github.com
    """
    if not hosts:
        err_console.print("[yellow]No hosts specified.  Pass at least one HOST[:PORT].[/yellow]")
        raise SystemExit(1)

    from nst.tls_inspector import scanner
    from nst.tls_inspector.display import print_result, print_summary

    results = []
    for host_str in hosts:
        host, scan_port = scanner.parse_host_port(host_str, default_port=port)
        console.rule(f"[dim]{host}:{scan_port}[/dim]")
        result = scanner.scan(host, port=scan_port, timeout=timeout)
        print_result(result)
        results.append(result)

    print_summary(results)

    if report_path:
        _write_report(results=results, output_path=report_path,
                      open_browser=open_browser)

    has_critical = any(r.critical_count > 0 for r in results)
    has_error    = any(r.error is not None for r in results)
    if has_critical or has_error:
        raise SystemExit(1)


# ──────────────────────────────────────────────────────────────────────────────
# `nst report`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("report")
@click.option("--tls", "tls_hosts", multiple=True, metavar="HOST[:PORT]",
              help="TLS host to scan; may be repeated.")
@click.option("--port", default=443, show_default=True, type=int,
              help="Default TLS port when not included in HOST.")
@click.option("--timeout", default=10, show_default=True, type=int,
              help="TLS connection timeout per host in seconds.")
@click.option("--no-interfaces", is_flag=True, default=False,
              help="Skip network interface discovery.")
@click.option("--geo", "enable_geo", is_flag=True, default=False,
              help="Add geolocation data to TLS findings (requires internet).")
@click.option("--output", "-o", "output_path", default=None,
              type=click.Path(path_type=Path),
              metavar="FILE",
              help="Output HTML file (default: nst_report_<timestamp>.html).")
@click.option("--open", "open_browser", is_flag=True, default=False,
              help="Open the report in the default browser after writing.")
@click.pass_context
def report(
    ctx: click.Context,
    tls_hosts: tuple[str, ...],
    port: int,
    timeout: int,
    no_interfaces: bool,
    enable_geo: bool,
    output_path: Optional[Path],
    open_browser: bool,
) -> None:
    """Generate a self-contained HTML security report.

    \b
    Examples:
      nst report --tls github.com --tls google.com --output report.html --open
      nst report --tls github.com:443 --geo -o scan.html
      nst report --no-interfaces -o interfaces-only.html
    """
    from nst.reporter.builder import ReportBuilder
    from nst.reporter.writer import default_output_path, write

    builder = ReportBuilder()

    if tls_hosts:
        from nst.tls_inspector import scanner
        from nst.tls_inspector.display import print_result

        console.print(
            Panel(
                f"Scanning {len(tls_hosts)} host(s) — timeout {timeout}s per host.\n\n"
                "Press [bold]Ctrl+C[/bold] to abort.",
                title="[bold cyan]TLS Scan[/bold cyan]",
                border_style="cyan",
            )
        )
        results = []
        for host_str in tls_hosts:
            host, scan_port = scanner.parse_host_port(host_str, default_port=port)
            console.rule(f"[dim]{host}:{scan_port}[/dim]")
            result = scanner.scan(host, port=scan_port, timeout=timeout)
            print_result(result)
            results.append(result)
        builder.add_tls_results(results)

        if enable_geo and results:
            from nst.geoip.client import GeoIPClient
            console.print("[dim]Looking up geolocation data…[/dim]")
            builder.add_geo(GeoIPClient())

    if not no_interfaces:
        builder.add_interfaces()

    data = builder.build()

    if output_path is None:
        output_path = default_output_path(data)

    out = write(data, output_path, open_browser=open_browser)

    console.print()
    console.print(
        Panel(
            f"[bold green]Report saved:[/bold green] [cyan]{out}[/cyan]\n\n"
            f"TLS hosts scanned : [bold]{len(data.tls_findings)}[/bold]\n"
            f"Interfaces listed : [bold]{len(data.interfaces)}[/bold]\n"
            f"Critical issues   : [bold red]{data.critical_tls_count}[/bold red]\n"
            + (
                "\n[dim]Opening in browser…[/dim]" if open_browser else
                f"\n[dim]Open with:[/dim] open {out}"
            ),
            title="[bold green]Report Generated[/bold green]",
            border_style="green",
        )
    )

    if data.critical_tls_count > 0:
        raise SystemExit(1)


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

    from nst.analyzer.engine import AnalysisEngine
    from nst.dashboard.display import DashboardDisplay
    from nst.sniffer.capture import PacketCapture
    from nst.sniffer.interface import InterfaceManager
    from nst.sniffer.parsers import ParserDispatcher

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
# `nst mac-watch`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("mac-watch")
@click.option("-i", "--interface", default=None, metavar="IFACE",
              help="Network interface to monitor (default: auto-detect).")
@click.option("--threshold", default=None, type=click.IntRange(min=1),
              metavar="N",
              help="New MACs per window that trigger an alert (default from config).")
@click.option("--window", default=None, type=click.FloatRange(min=0.5),
              metavar="SECS",
              help="Sliding window width in seconds (default from config).")
@click.pass_context
def mac_watch(
    ctx: click.Context,
    interface: Optional[str],
    threshold: Optional[int],
    window: Optional[float],
) -> None:
    """Monitor Ethernet frames and detect MAC flooding / CAM table overflow."""
    _require_root()
    cfg: AppConfig = ctx.obj["config"]

    if interface:
        cfg.network.interface = interface
    if threshold is not None:
        cfg.mac_detector.flood_threshold = threshold
    if window is not None:
        cfg.mac_detector.window_secs = window

    from nst.mac_detector.monitor import MACMonitor

    monitor = MACMonitor(cfg.mac_detector, cfg.network)

    iface_label = cfg.network.interface or "auto-detect"

    console.print(
        Panel(
            f"Interface  : [cyan]{iface_label}[/cyan]\n"
            f"Threshold  : [cyan]{cfg.mac_detector.flood_threshold} new MACs "
            f"/ {cfg.mac_detector.window_secs:.1f}s window[/cyan]\n"
            f"Table limit: [cyan]{cfg.mac_detector.table_limit}[/cyan]\n\n"
            "Monitoring Ethernet frames — press [bold]Ctrl+C[/bold] to stop.",
            title="[bold cyan]MAC Flooding Monitor — Started[/bold cyan]",
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
                f"[bold red]{exc}[/bold red]\n\nRe-run with: [bold]sudo nst mac-watch[/bold]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)
    except CaptureError as exc:
        err_console.print(f"[red]MAC capture failed:[/red] {exc}")
        raise SystemExit(1)
    finally:
        _print_mac_summary(monitor)


# ──────────────────────────────────────────────────────────────────────────────
# `nst geoip`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("geoip")
@click.argument("targets", nargs=-1, metavar="IP_OR_HOST")
@click.pass_context
def geoip(ctx: click.Context, targets: tuple[str, ...]) -> None:
    """Look up geolocation for one or more IP addresses or hostnames.

    \b
    Examples:
      nst geoip 8.8.8.8
      nst geoip 8.8.8.8 1.1.1.1 github.com
    """
    if not targets:
        err_console.print(
            "[yellow]No targets specified.  Pass at least one IP address or hostname.[/yellow]"
        )
        raise SystemExit(1)

    from nst.geoip.client import GeoIPClient
    from nst.geoip.display import print_geo_table

    client = GeoIPClient()
    results = [client.lookup(t) for t in targets]
    print_geo_table(results)


# ──────────────────────────────────────────────────────────────────────────────
# `nst web`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("web")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Loopback address to listen on (127.0.0.1, ::1 or localhost).")
@click.option("--port", default=8765, show_default=True, type=click.IntRange(1, 65535),
              envvar="NST_WEB_PORT", help="TCP port to listen on.")
@click.option("--no-browser", is_flag=True, default=False,
              help="Do not open the dashboard in a browser.")
@click.option("--dev-origin", "dev_origins", multiple=True, hidden=True,
              help="Extra allowed browser origin (frontend dev server).")
@click.option("--mode", type=click.Choice(["local", "console", "public"]), default="local",
              show_default=True, envvar="NST_WEB_MODE",
              help="local: this machine; console / public: behind the VPS reverse proxy.")
@click.option("--allowed-host", "allowed_hosts", multiple=True, envvar="NST_ALLOWED_HOSTS",
              metavar="HOST",
              help="Host name served by the reverse proxy (console / public modes); repeatable. "
                   "NST_ALLOWED_HOSTS takes a space-separated list.")
@click.pass_context
def web(
    ctx: click.Context,
    host: str,
    port: int,
    no_browser: bool,
    dev_origins: tuple[str, ...],
    mode: str,
    allowed_hosts: tuple[str, ...],
) -> None:
    """Serve the browser dashboard on loopback.

    \b
    Packet capture needs the same privileges as the CLI capture commands,
    so start it with sudo to use the live sensors:
      sudo nst web
    TLS scans, GeoIP and reports work without root.

    \b
    On the VPS the same command runs behind Caddy:
      nst web --mode public  --allowed-host example.com
      nst web --mode console --allowed-host console.example.com
    Console mode reads its access token from NST_WEB_TOKEN.
    """
    try:
        from nst.web.server import serve
    except ImportError as exc:
        err_console.print(
            Panel(
                f"[bold red]Web dependencies are not installed[/bold red] ({exc.name}).\n\n"
                "Install them with:  [bold]pip install 'network-security-toolkit[web]'[/bold]\n"
                "or from a checkout: [bold]pip install -e '.[web]'[/bold]",
                title="[red]Missing Dependency[/red]",
                border_style="red",
            )
        )
        raise SystemExit(1)

    cfg: AppConfig = ctx.obj["config"]

    def announce(url: str) -> None:
        if mode != "local":
            console.print(
                f"[bold cyan]NST Web ({mode} mode)[/bold cyan] listening on "
                f"{host}:{port} behind the reverse proxy for: {url}",
                soft_wrap=True, highlight=False,
            )
            return
        console.print(
            Panel(
                "Listening on loopback only.  The link below contains a one-time\n"
                "access token for this session — don't share it.\n\n"
                "Press [bold]Ctrl+C[/bold] to stop.",
                title="[bold cyan]NST Web — Started[/bold cyan]",
                border_style="cyan",
            )
        )
        # Printed outside the panel and unwrapped so it stays clickable / copyable.
        console.print(url, style="bold cyan", soft_wrap=True, highlight=False)

    try:
        serve(cfg, host=host, port=port, open_browser=not no_browser,
              dev_origins=list(dev_origins), announce=announce, mode=mode,
              allowed_hosts=list(allowed_hosts),
              console_token=os.environ.get("NST_WEB_TOKEN"))
    except ConfigurationError as exc:
        err_console.print(f"[red]Cannot start web dashboard:[/red] {exc}")
        raise SystemExit(1)


# ──────────────────────────────────────────────────────────────────────────────
# `nst interfaces`
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("interfaces")
@click.pass_context
def interfaces(ctx: click.Context) -> None:
    """List available network interfaces."""
    from nst.sniffer.interface import InterfaceManager

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
    table.add_column("Value", style="green", overflow="fold")

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

    table.add_row("dns_detector", "trusted_domains",
                  ", ".join(cfg.dns_detector.trusted_domains)
                  or "[dim](none)[/dim]")
    table.add_row("", "track_queries", str(cfg.dns_detector.track_queries))

    table.add_row("mac_detector", "flood_threshold",
                  str(cfg.mac_detector.flood_threshold))
    table.add_row("", "window_secs", f"{cfg.mac_detector.window_secs}s")
    table.add_row("", "table_limit", str(cfg.mac_detector.table_limit))

    table.add_row("logging", "level", cfg.logging.level)
    table.add_row("", "file", str(resolve_state_path(cfg.logging.file)))
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


def _write_report(
    results: List["TLSScanResult"],
    output_path: Path,
    open_browser: bool = False,
) -> None:
    """Build and write an HTML report from TLS scan results."""
    from nst.reporter.builder import ReportBuilder
    from nst.reporter.writer import write

    data = ReportBuilder().add_tls_results(results).add_interfaces().build()
    out = write(data, output_path, open_browser=open_browser)
    console.print(
        f"\n[bold green]Report saved:[/bold green] [cyan]{out}[/cyan]"
    )


def _print_mac_summary(monitor: "MACMonitor") -> None:
    """Print MAC flooding session statistics after mac-watch exits."""
    event_log = monitor.event_logger
    alerts = monitor.alert_manager

    console.print()
    console.rule("[bold cyan]MAC Session Summary[/bold cyan]")

    from nst.mac_detector.events import MACEventType

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="dim", no_wrap=True)
    overview.add_column(style="bold white")
    overview.add_row("Packets seen     :", str(monitor.packet_count))
    overview.add_row("Unique MACs seen :", str(monitor.table.total()))
    overview.add_row("Flood events     :",
                     str(event_log.count_by_type(MACEventType.FLOOD_DETECTED)))
    overview.add_row("Overflow events  :",
                     str(event_log.count_by_type(MACEventType.TABLE_OVERFLOW)))
    overview.add_row(
        "Alerts shown     :",
        f"[bold red]{alerts.total_alerts}[/bold red]",
    )
    overview.add_row(
        "Critical alerts  :",
        f"[bold red]{alerts.critical_alerts}[/bold red]",
    )
    console.print(overview)
    console.print()

    entries = monitor.table.all_entries()
    if not entries:
        console.print("[dim]No MAC addresses observed.[/dim]")
        return

    top = sorted(entries, key=lambda e: e.packet_count, reverse=True)[:10]
    mac_table = Table(
        title="Top Source MAC Addresses",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    mac_table.add_column("MAC Address", style="cyan", no_wrap=True)
    mac_table.add_column("Packets", justify="right")

    for entry in top:
        mac_table.add_row(entry.mac, str(entry.packet_count))
    console.print(mac_table)


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
                "Packet capture and the *-watch monitors use raw sockets,\n"
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
    except Exception as exc:
        # Full traceback goes to the log file (DEBUG); the console only
        # shows it when --debug is active.
        logger.error("Unhandled exception: %s", exc)
        logger.debug("Unhandled exception details", exc_info=True)
        err_console.print(
            "[bold red]An unexpected error occurred.[/bold red] "
            "See the log file for details."
        )
        raise SystemExit(1)
