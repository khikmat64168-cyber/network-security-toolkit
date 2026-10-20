"""
Input validation for the web API.

Every value that reaches a capture socket, a TLS connection or an
outbound HTTP request is checked here first.  Validators raise
ValidationError with a message that is safe to show to the user.

Design decisions
────────────────
* Interfaces are accepted only if they appear in the live interface
  list — never passed through as arbitrary strings.
* BPF filters are length-limited and compiled with libpcap (in-process,
  no shell) so syntax errors are reported before a capture starts.
* Hosts must be a valid IP address or RFC 1123 hostname; ports are
  range-checked.  Batch sizes are capped so one request cannot turn the
  dashboard into a scanner.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple

MAX_BPF_LENGTH = 256
MAX_TLS_HOSTS = 10
MAX_GEO_TARGETS = 20
MAX_TLS_TIMEOUT = 15

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class ValidationError(ValueError):
    """Raised when user input is rejected.  The message is user-facing."""


def interface(name: Optional[str], available: List[str]) -> Optional[str]:
    """Return *name* if it is a known interface, None for auto-detect."""
    if name is None or name == "":
        return None
    if name not in available:
        raise ValidationError(f"Unknown network interface: {name!r}")
    return name


def bpf_filter(expression: Optional[str]) -> str:
    """Return a compiled-and-verified BPF expression ("" means no filter)."""
    expr = (expression or "").strip()
    if not expr:
        return ""
    if len(expr) > MAX_BPF_LENGTH:
        raise ValidationError(f"BPF filter is longer than {MAX_BPF_LENGTH} characters")
    if any(ord(ch) < 32 for ch in expr):
        raise ValidationError("BPF filter contains control characters")

    from scapy.arch.common import compile_filter
    from scapy.data import DLT_EN10MB

    try:
        compile_filter(expr, linktype=DLT_EN10MB)
    except Exception as exc:
        raise ValidationError(f"Invalid BPF filter: {expr}") from exc
    return expr


def host(value: str) -> str:
    """Return a normalized hostname or IP address."""
    candidate = value.strip()
    if not candidate:
        raise ValidationError("Host must not be empty")
    try:
        return str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(candidate):
        raise ValidationError(f"Not a valid hostname or IP address: {candidate!r}")
    return candidate.rstrip(".").lower()


def port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise ValidationError(f"Port out of range: {value}")
    return value


def tls_targets(values: List[str], default_port: int) -> List[Tuple[str, int]]:
    """Parse and validate "host[:port]" strings for a TLS scan."""
    from nst.tls_inspector.scanner import parse_host_port

    cleaned = [v.strip() for v in values if v and v.strip()]
    if not cleaned:
        raise ValidationError("Provide at least one host")
    if len(cleaned) > MAX_TLS_HOSTS:
        raise ValidationError(f"At most {MAX_TLS_HOSTS} hosts per scan")
    port(default_port)

    targets = []
    for raw in cleaned:
        name, scan_port = parse_host_port(raw, default_port=default_port)
        targets.append((host(name), port(scan_port)))
    return targets


def tls_timeout(value: int) -> int:
    if not 1 <= value <= MAX_TLS_TIMEOUT:
        raise ValidationError(f"Timeout must be between 1 and {MAX_TLS_TIMEOUT} seconds")
    return value


def geo_targets(values: List[str]) -> List[str]:
    cleaned = [v.strip() for v in values if v and v.strip()]
    if not cleaned:
        raise ValidationError("Provide at least one IP address or hostname")
    if len(cleaned) > MAX_GEO_TARGETS:
        raise ValidationError(f"At most {MAX_GEO_TARGETS} targets per lookup")
    return [host(v) for v in cleaned]
