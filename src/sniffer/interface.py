"""
Network interface discovery and validation.

Design decisions
────────────────
* Uses Scapy's IFACES dict as the single source of truth — works on
  both Linux and macOS without extra dependencies.
* All attribute access is guarded with getattr + _safe_str so that
  unusual interface objects (tunnels, VPNs, loopback) never cause a crash.
* resolve() is the main entry point for other modules: given an optional
  interface name it returns a validated name, the system default, or None
  (letting Scapy auto-select at capture time).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from src.core.exceptions import InterfaceError
from src.core.logger import get_logger

logger = get_logger(__name__)


def _safe_str(value: Any, default: str = "") -> str:
    """Convert *value* to str, returning *default* for None / 'None' / empty."""
    if value is None:
        return default
    try:
        result = str(value)
        return result if result and result.lower() != "none" else default
    except Exception:
        return default


@dataclass(frozen=True)
class NetworkInterface:
    """Immutable snapshot of one network interface on the host."""

    name: str
    ip: str
    mac: str
    description: str

    def __str__(self) -> str:
        parts = [self.name]
        if self.ip:
            parts.append(f"({self.ip})")
        return " ".join(parts)


class InterfaceManager:
    """
    Discovers and validates network interfaces via Scapy.

    All public methods are static — callers never need an instance.
    """

    @staticmethod
    def list_interfaces() -> List[NetworkInterface]:
        """Return all interfaces visible to Scapy, sorted by name."""
        try:
            from scapy.interfaces import IFACES
        except ImportError as exc:
            raise InterfaceError(
                "Scapy cannot be imported — is it installed?"
            ) from exc

        result: List[NetworkInterface] = []

        try:
            iface_iter = IFACES.values()
        except Exception as exc:
            raise InterfaceError(f"Cannot enumerate interfaces: {exc}") from exc

        for iface_data in iface_iter:
            try:
                name = _safe_str(getattr(iface_data, "name", None))
                if not name:
                    continue
                ip = _safe_str(getattr(iface_data, "ip", None))
                mac = _safe_str(getattr(iface_data, "mac", None))
                description = _safe_str(
                    getattr(iface_data, "description", None), default=name
                )
                result.append(
                    NetworkInterface(name=name, ip=ip, mac=mac, description=description)
                )
            except Exception as exc:
                logger.debug("Skipping interface — %s", exc)

        return sorted(result, key=lambda i: i.name)

    @staticmethod
    def get_default() -> str:
        """
        Return the name of the system default capture interface.

        Raises InterfaceError if Scapy cannot determine one.
        """
        try:
            from scapy.config import conf

            iface = conf.iface
            if hasattr(iface, "name"):
                return _safe_str(iface.name)
            return _safe_str(iface)
        except Exception as exc:
            raise InterfaceError(
                f"Cannot determine default interface: {exc}"
            ) from exc

    @staticmethod
    def validate(name: str) -> bool:
        """Return True if *name* identifies an existing interface."""
        try:
            from scapy.interfaces import IFACES

            known = {
                _safe_str(getattr(i, "name", None)) for i in IFACES.values()
            }
            return name in known
        except Exception:
            return False

    @staticmethod
    def resolve(name: Optional[str]) -> Optional[str]:
        """
        Validate and return *name*, or fall back to the system default.

        Returns None only when no interface can be determined — Scapy will
        then auto-select one at capture time.

        Raises InterfaceError if *name* is provided but does not exist.
        """
        if name is None:
            try:
                return InterfaceManager.get_default() or None
            except InterfaceError:
                logger.debug(
                    "Cannot determine default interface — Scapy will auto-select."
                )
                return None

        if not InterfaceManager.validate(name):
            raise InterfaceError(
                f"Interface '{name}' not found. "
                "Run `nst interfaces` to list available interfaces."
            )
        return name
