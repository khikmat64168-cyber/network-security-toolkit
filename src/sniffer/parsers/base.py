"""
Shared types for the protocol parser layer.

Design decisions
────────────────
* Protocol is a str-enum so values can be used directly as Rich markup
  labels and JSON keys without an extra .value call.
* ParsedPacket is a plain dataclass (not frozen) so Phase 3 analyzers
  can enrich it (e.g. add a "credential_detected" flag) without copying.
* BaseParser uses @staticmethod + @abstractmethod — parsers hold no
  state, so there is no reason to instantiate them.  The ParserDispatcher
  stores class references, not instances.
* payload is stored as bytes, not str, to avoid encoding assumptions and
  to allow binary inspection in Phase 3.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class Protocol(str, Enum):
    """Network / application layer protocols recognised by this toolkit."""

    TCP = "TCP"
    UDP = "UDP"
    HTTP = "HTTP"
    DNS = "DNS"
    ARP = "ARP"
    ICMP = "ICMP"
    OTHER = "OTHER"


@dataclass
class ParsedPacket:
    """
    Normalised, protocol-agnostic representation of a captured packet.

    Fields
    ──────
    timestamp   : when the packet was observed (local time)
    protocol    : highest recognised protocol layer
    src_ip      : source IP address (empty string if not an IP packet)
    dst_ip      : destination IP address
    src_port    : source transport port, or None
    dst_port    : destination transport port, or None
    length      : total on-wire packet size in bytes
    summary     : one-line human description produced by the parser
    payload     : raw application-layer payload bytes (may be empty)
    flags       : TCP flag string (e.g. "S", "PA") or empty
    extra       : protocol-specific key/value metadata
    """

    timestamp: datetime
    protocol: Protocol
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    summary: str
    payload: bytes = field(default_factory=bytes)
    flags: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def one_line(self) -> str:
        """Return a compact single-line description suitable for console output."""
        if self.src_port is not None and self.dst_port is not None:
            src = f"{self.src_ip}:{self.src_port}"
            dst = f"{self.dst_ip}:{self.dst_port}"
        else:
            src = self.src_ip
            dst = self.dst_ip
        flags = f" [{self.flags}]" if self.flags else ""
        return f"[{self.protocol.value}] {src} → {dst}{flags}  {self.summary}  ({self.length}B)"


class BaseParser(ABC):
    """
    Abstract base class for all protocol parsers.

    Subclasses implement two static methods:
        can_parse(packet) → bool   decides whether this parser handles packet
        parse(packet)     → ParsedPacket   extracts fields into a ParsedPacket
    """

    @staticmethod
    @abstractmethod
    def can_parse(packet: Any) -> bool:
        """Return True if this parser can handle *packet*."""
        ...

    @staticmethod
    @abstractmethod
    def parse(packet: Any) -> ParsedPacket:
        """Parse *packet* and return a populated ParsedPacket."""
        ...
