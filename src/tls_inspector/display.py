"""
Rich-formatted output for TLS scan results.

print_result()  — full certificate detail panel for one host.
print_summary() — compact one-row-per-host table for multi-host scans.
"""
from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.tls_inspector.result import TLSScanResult

_console = Console()

_SEVERITY_STYLES = {
    "medium":   "yellow",
    "high":     "bold red",
    "critical": "bold white on red",
}
_SEVERITY_ICONS = {
    "medium":   "⚠",
    "high":     "🔴",
    "critical": "🚨",
}

_WEAK_CIPHER_TOKENS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "RC2"}
_WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


def print_result(result: TLSScanResult) -> None:
    """Print a full Rich certificate report for one scan result."""
    if result.error:
        _console.print(Panel(
            f"[bold red]{result.error}[/bold red]",
            title=f"[red]✗  {result.host}:{result.port} — Connection Failed[/red]",
            border_style="red",
        ))
        return

    days = result.days_until_expiry
    if result.critical_count > 0:
        border, status = "red", "[bold red]✗  CRITICAL ISSUES FOUND[/bold red]"
    elif result.high_count > 0:
        border, status = "orange3", "[bold orange3]⚠  ISSUES FOUND[/bold orange3]"
    elif result.issues:
        border, status = "yellow", "[yellow]⚠  WARNINGS[/yellow]"
    else:
        border, status = "green", "[bold green]✓  SECURE[/bold green]"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(style="white")

    grid.add_row("Host      :", f"[bold cyan]{result.host}:{result.port}[/bold cyan]")
    grid.add_row("TLS       :", _version_label(result.tls_version))
    grid.add_row("Cipher    :", _cipher_label(result.cipher_suite, result.key_bits))
    grid.add_row("Subject   :", result.subject or "[dim](none)[/dim]")
    grid.add_row("Issuer    :", result.issuer or "[dim](none)[/dim]")
    grid.add_row("Valid from:", str(result.not_before.date()))

    if days <= 0:
        expiry_style = "bold red"
    elif days <= 30:
        expiry_style = "yellow"
    else:
        expiry_style = "green"
    grid.add_row(
        "Expires   :",
        f"[{expiry_style}]{result.not_after.date()} ({days} days)[/{expiry_style}]",
    )
    if result.san:
        preview = result.san[:6]
        suffix = "…" if len(result.san) > 6 else ""
        grid.add_row("SANs      :", ", ".join(preview) + suffix)

    _console.print(Panel(
        grid,
        title=f"{status}  [dim]{result.host}:{result.port}[/dim]",
        border_style=border,
    ))

    if result.issues:
        issue_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        issue_table.add_column("Severity", width=12)
        issue_table.add_column("Issue", width=22)
        issue_table.add_column("Detail")

        for issue in sorted(result.issues, key=lambda i: -i.severity_level()):
            style = _SEVERITY_STYLES.get(issue.severity, "white")
            icon  = _SEVERITY_ICONS.get(issue.severity, "")
            label = issue.issue_type.value.replace("_", " ").title()
            issue_table.add_row(
                f"[{style}]{icon} {issue.severity.upper()}[/{style}]",
                f"[{style}]{label}[/{style}]",
                issue.detail,
            )
        _console.print(issue_table)

    _console.print()


def print_summary(results: List[TLSScanResult]) -> None:
    """Print a compact summary table.  Only shown when scanning 2+ hosts."""
    if len(results) <= 1:
        return

    table = Table(
        title="Scan Summary",
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=False,
    )
    table.add_column("Host", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("TLS", style="dim")
    table.add_column("Expires", justify="right")
    table.add_column("Issues", justify="right")
    table.add_column("Status", justify="center")

    for r in results:
        if r.error:
            table.add_row(r.host, str(r.port), "—", "—", "—", "[red]ERROR[/red]")
            continue
        days = r.days_until_expiry
        days_label = f"[red]{days}d[/red]" if days <= 30 else f"{days}d"
        if r.critical_count:
            status = f"[bold red]✗ CRITICAL ({r.critical_count})[/bold red]"
        elif r.high_count:
            status = f"[orange3]⚠ HIGH ({r.high_count})[/orange3]"
        elif r.issues:
            status = f"[yellow]⚠ WARN ({len(r.issues)})[/yellow]"
        else:
            status = "[green]✓ OK[/green]"
        table.add_row(
            r.host, str(r.port), r.tls_version, days_label,
            str(len(r.issues)), status,
        )
    _console.print(table)


def _version_label(version: str) -> str:
    if version in _WEAK_TLS:
        return f"[bold red]{version}  ← WEAK[/bold red]"
    if version == "TLSv1.2":
        return f"[yellow]{version}[/yellow]"
    return f"[green]{version}[/green]"


def _cipher_label(cipher: str, key_bits: int) -> str:
    is_weak = any(t in cipher.upper() for t in _WEAK_CIPHER_TOKENS)
    bits = f" ({key_bits} bits)" if key_bits else ""
    if is_weak:
        return f"[bold red]{cipher}{bits}  ← WEAK[/bold red]"
    return f"[dim]{cipher}[/dim]{bits}"
