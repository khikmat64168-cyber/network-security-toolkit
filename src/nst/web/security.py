"""
Access control for the local web dashboard.

Threat model
────────────
The service only listens on loopback, but "only reachable from this
machine" still includes every web page open in the user's browser:

* Cross-site requests  — any site could POST to http://127.0.0.1:<port>.
  Mitigation: every API call needs a per-launch bearer token that a
  foreign page cannot read.
* DNS rebinding        — evil.example re-resolving to 127.0.0.1 makes
  requests same-origin.  Mitigation: the Host header must be a loopback
  name; rebinding keeps the attacker's hostname, so it is rejected.
* WebSocket hijacking  — browsers do not apply CORS to WebSockets.
  Mitigation: Origin must be one of our own origins *and* the token
  must be presented (as a subprotocol, so it never lands in URLs/logs).

Behind the VPS reverse proxy (public / console modes) the service still
listens on loopback only.  The proxy forwards the public host name, so
those names are added to the Host allowlist explicitly; nothing else is.

The token is generated with `secrets` at startup, printed to the
terminal and handed to the browser in the URL fragment, which is never
sent to the server or written to access logs.
"""
from __future__ import annotations

import hmac
import ipaddress
import secrets
from typing import Iterable, List, Optional, Set

from starlette.types import ASGIApp, Receive, Scope, Send

WS_SUBPROTOCOL = "nst.v1"
WS_TOKEN_PREFIX = "auth."

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_match(expected: str, presented: Optional[str]) -> bool:
    return presented is not None and hmac.compare_digest(expected, presented)


def is_loopback_host(host: str) -> bool:
    """True for localhost / 127.0.0.0/8 / ::1 (with or without brackets)."""
    name = host.strip().strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def split_host_header(value: str) -> str:
    """Return the hostname part of a Host header ("[::1]:8765" → "::1")."""
    value = value.strip()
    if value.startswith("["):
        return value[1:value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def allowed_origins(port: int, extra: Iterable[str] = ()) -> Set[str]:
    origins = {f"http://{h}:{port}" for h in ("127.0.0.1", "localhost", "[::1]")}
    origins.update(o.rstrip("/") for o in extra)
    return origins


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


def ws_token(subprotocols: List[str]) -> Optional[str]:
    for proto in subprotocols:
        if proto.startswith(WS_TOKEN_PREFIX):
            return proto[len(WS_TOKEN_PREFIX):]
    return None


def normalize_host(host: str) -> str:
    return split_host_header(host).strip().strip("[]").rstrip(".").lower()


class HostAllowlistMiddleware:
    """
    Reject HTTP and WebSocket requests whose Host is neither a loopback
    name nor one of *allowed_hosts* (the names the reverse proxy serves).
    """

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str] = ()) -> None:
        self.app = app
        self.allowed = {normalize_host(h) for h in allowed_hosts if h.strip()}

    def host_allowed(self, host: str) -> bool:
        return is_loopback_host(split_host_header(host)) or normalize_host(host) in self.allowed

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            host = ""
            for key, value in scope.get("headers", []):
                if key == b"host":
                    host = value.decode("latin-1")
                    break
            if not self.host_allowed(host):
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                    return
                await send({
                    "type": "http.response.start",
                    "status": 421,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                })
                await send({"type": "http.response.body",
                            "body": b"Misdirected request: unexpected Host header"})
                return
        await self.app(scope, receive, send)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def app_csp(port: int) -> str:
    """Content-Security-Policy for the dashboard shell served on *port*."""
    # CSP host-sources cannot express IPv6 literals; 'self' covers ws://[::1]
    # same-origin connections in CSP Level 3 browsers.
    sockets = " ".join(f"ws://{h}:{port}" for h in ("127.0.0.1", "localhost"))
    return (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; font-src 'self'; connect-src 'self' {sockets}; "
        "frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )


# Generated reports are static HTML with inline CSS.  They are rendered
# in a sandboxed iframe and get no script, network or form capability.
REPORT_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"
