"""
Outbound-connection guard for the public demo.

In public mode anyone on the internet can ask the server to open a TLS
connection.  Without a guard that turns the server into a proxy for
probing its own network: 127.0.0.1 services, the VPS provider's private
range, or the cloud metadata endpoint (169.254.169.254).

Design decisions
────────────────
* A host is resolved once here and every returned address must be a
  public (globally routable, non-multicast) address — one private answer
  rejects the whole host.
* The caller connects to the address returned from this check instead of
  resolving the name again, so a DNS answer that changes between check
  and connect (DNS rebinding) cannot slip a private address through.
* Only ports where TLS is spoken from the first byte are allowed, so the
  demo cannot be used as a general port scanner.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import FrozenSet, List

from nst.web.validation import ValidationError

PUBLIC_TLS_PORTS: FrozenSet[int] = frozenset({443, 465, 636, 853, 993, 995, 5061, 8443, 9443})


def is_public_address(address: str) -> bool:
    """True for a globally routable unicast address (IPv4-mapped IPv6 unwrapped)."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str) -> str:
    """
    Resolve *host* and return one address to connect to.

    Raises ValidationError if the name does not resolve or if any of its
    addresses is not public.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValidationError(f"Cannot resolve {host!r}") from exc

    addresses: List[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValidationError(f"Cannot resolve {host!r}")

    for address in addresses:
        if not is_public_address(address):
            raise ValidationError(
                f"{host!r} resolves to a non-public address; the public demo only "
                "scans hosts on the public internet"
            )
    # Prefer IPv4: many VPS images have IPv6 addresses but no working route.
    return next((a for a in addresses if ":" not in a), addresses[0])


def check_public_port(port: int) -> int:
    if port not in PUBLIC_TLS_PORTS:
        allowed = ", ".join(str(p) for p in sorted(PUBLIC_TLS_PORTS))
        raise ValidationError(f"Port {port} is not allowed in the public demo (allowed: {allowed})")
    return port
