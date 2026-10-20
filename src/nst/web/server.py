"""
Run the NST web dashboard with uvicorn.

local and console modes listen on loopback only: they can start packet
captures, so they must never be reachable from the network directly, and
there is deliberately no flag to override that.  The public demo (no
capture, no stored data, no token) may also listen on a container address
so a reverse proxy on a Docker network — Coolify's Traefik — can reach it.
The proxy's public host names are passed in as allowed hosts and its
network as trusted proxies.
"""
from __future__ import annotations

import socket
import threading
import webbrowser
from typing import Callable, List, Optional, Tuple

from nst.core.config import AppConfig
from nst.core.exceptions import ConfigurationError
from nst.web.security import is_loopback_host, new_token

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MIN_CONSOLE_TOKEN_LENGTH = 32


def dashboard_url(host: str, port: int, token: str) -> str:
    shown = f"[{host}]" if ":" in host else host
    return f"http://{shown}:{port}/#token={token}"


def check_bind(host: str, port: int, mode: str = "local") -> None:
    """
    Raise ConfigurationError if *host* is not allowed for *mode* or *port*
    is taken.

    Only the public demo may listen beyond loopback: it captures nothing,
    stores nothing and needs no token, and in a container (Coolify) the
    reverse proxy reaches it over the Docker network.  local and console
    control packet capture and stay on loopback, always.
    """
    if not is_loopback_host(host) and mode != "public":
        raise ConfigurationError(
            f"Refusing to bind to {host!r}: the dashboard controls packet capture "
            "and only listens on loopback (127.0.0.1, ::1 or localhost). Only "
            "--mode public may listen on other addresses."
        )
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        # Same option uvicorn sets: a port whose old connections linger in
        # TIME_WAIT after a restart is free; one with a live listener is not.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise ConfigurationError(f"Cannot listen on {host}:{port}: {exc.strerror}") from exc


def resolve_settings(
    mode: str,
    allowed_hosts: List[str],
    console_token: Optional[str],
) -> Tuple[Optional[str], List[str]]:
    """
    Validate the mode-specific settings and return (token, extra origins).

    local    → a fresh random token, no extra hosts needed
    console  → the operator-provided token (≥ 32 chars) and at least one
               proxied host; the browser origins are https://<host>
    public   → no token, at least one proxied host
    """
    hosts = [h.strip().lower() for h in allowed_hosts if h.strip()]
    if mode == "local":
        return new_token(), []
    if mode not in ("console", "public"):
        raise ConfigurationError(f"Unknown mode {mode!r}")
    if not hosts:
        raise ConfigurationError(
            f"--mode {mode} runs behind the reverse proxy and needs the host name(s) it "
            "serves: pass --allowed-host or set NST_ALLOWED_HOSTS"
        )
    if mode == "public":
        return None, []
    if not console_token or len(console_token) < MIN_CONSOLE_TOKEN_LENGTH:
        raise ConfigurationError(
            f"--mode console needs NST_WEB_TOKEN with at least {MIN_CONSOLE_TOKEN_LENGTH} "
            "characters (generate one with: openssl rand -base64 48)"
        )
    return console_token, [f"https://{h}" for h in hosts]


def serve(
    config: AppConfig,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
    dev_origins: Optional[List[str]] = None,
    announce: Optional[Callable[[str], None]] = None,
    mode: str = "local",
    allowed_hosts: Optional[List[str]] = None,
    console_token: Optional[str] = None,
    trusted_proxies: Optional[List[str]] = None,
) -> None:
    """Start the dashboard and block until interrupted."""
    import uvicorn

    from nst.web.app import create_app

    from nst.web.app import LOOPBACK_NETWORKS, parse_networks

    check_bind(host, port, mode)
    token, proxy_origins = resolve_settings(mode, allowed_hosts or [], console_token)
    proxies = list(trusted_proxies or LOOPBACK_NETWORKS)
    try:
        parse_networks(proxies)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid NST_TRUSTED_PROXIES entry: {exc}") from exc
    app = create_app(
        config, token=token, port=port,
        extra_origins=[*(dev_origins or []), *proxy_origins],
        mode=mode, allowed_hosts=allowed_hosts or [], trusted_proxies=proxies,
    )
    if mode == "local":
        assert token is not None
        url = dashboard_url(host, port, token)
    else:
        # Behind the proxy: never print the console token.
        url = ", ".join(f"https://{h}" for h in (allowed_hosts or []))
        open_browser = False
    if announce is not None:
        announce(url)

    server = uvicorn.Server(uvicorn.Config(
        app, host=host, port=port, log_level="warning", access_log=False,
        ws="auto", lifespan="on",
    ))

    if open_browser:
        def _open_when_ready() -> None:
            for _ in range(100):
                if server.started:
                    webbrowser.open(url)
                    return
                threading.Event().wait(0.1)

        threading.Thread(target=_open_when_ready, daemon=True).start()

    server.run()
