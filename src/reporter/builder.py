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

from datetime import datetime
from typing import TYPE_CHECKING, List

from src.reporter.models import InterfaceInfo, ReportData, TLSFinding

if TYPE_CHECKING:
    from src.tls_inspector.result import TLSScanResult


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

    # ── Finalise ───────────────────────────────────────────────────────────────

    def build(self) -> ReportData:
        return self._data
