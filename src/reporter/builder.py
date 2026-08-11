"""
Build ReportData from live toolkit objects.

ReportBuilder uses a fluent interface — each add_*() method returns
self so callers can chain:

    data = (
        ReportBuilder()
        .add_tls_results(results)
        .add_interfaces()
        .build()
    )
"""
from __future__ import annotations

import socket
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from src.reporter.models import InterfaceInfo, ReportData, TLSFinding

if TYPE_CHECKING:
    from src.geoip.client import GeoIPClient
    from src.tls_inspector.result import TLSScanResult


def _resolve_host(host: str) -> Optional[str]:
    """Resolve *host* to an IP string; return None on failure."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _tls_severity(result: "TLSScanResult") -> str:
    if result.error:
        return "error"
    if result.critical_count > 0:
        return "critical"
    if result.high_count > 0:
        return "high"
    if result.issues:
        return "warning"
    return "ok"


class ReportBuilder:
    """
    Accumulates data from multiple toolkit sources and produces ReportData.

    All add_*() methods are optional — call only the ones relevant to
    the current session.
    """

    def __init__(self) -> None:
        self._data = ReportData(generated_at=datetime.now())

    # ── TLS ────────────────────────────────────────────────────────────────────

    def add_tls_results(self, results: List["TLSScanResult"]) -> "ReportBuilder":
        """Convert a list of TLSScanResult objects into TLSFinding records."""
        for r in results:
            days: int | None = None
            if not r.error:
                try:
                    days = r.days_until_expiry
                except Exception:
                    pass

            finding = TLSFinding(
                host=r.host,
                port=r.port,
                tls_version=r.tls_version or "(unknown)",
                cipher_suite=r.cipher_suite or "(unknown)",
                subject=r.subject or "(unknown)",
                issuer=r.issuer or "(unknown)",
                days_until_expiry=days,
                issues=[f"{i.issue_type.value}: {i.detail}" for i in r.issues],
                severity=_tls_severity(r),
            )
            self._data.tls_findings.append(finding)
        return self

    # ── Network interfaces ──────────────────────────────────────────────────────

    def add_interfaces(self) -> "ReportBuilder":
        """Query Scapy for available interfaces and record them."""
        try:
            from src.sniffer.interface import InterfaceManager

            ifaces = InterfaceManager.list_interfaces()
            try:
                default_name = InterfaceManager.get_default()
            except Exception:
                default_name = ""

            for iface in ifaces:
                self._data.interfaces.append(
                    InterfaceInfo(
                        name=iface.name,
                        ip=iface.ip or None,
                        mac=iface.mac or None,
                        is_default=(iface.name == default_name),
                    )
                )
        except Exception:
            pass
        return self

    # ── Geolocation ────────────────────────────────────────────────────────────

    def add_geo(self, client: "GeoIPClient") -> "ReportBuilder":
        """
        Enrich existing TLS findings with geolocation data.

        For each finding, the hostname is resolved to an IP and looked up
        via *client*.  Failures are silently ignored — the finding's geo
        field stays None.

        Call AFTER add_tls_results() so there are findings to enrich.
        """
        for finding in self._data.tls_findings:
            try:
                ip = _resolve_host(finding.host) or finding.host
                finding.geo = client.lookup(ip)
            except Exception:
                pass
        return self

    # ── Finalise ───────────────────────────────────────────────────────────────

    def build(self) -> ReportData:
        return self._data
