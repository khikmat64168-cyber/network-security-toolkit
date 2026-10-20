"""
Run the NST web dashboard with uvicorn.

The bind address is restricted to loopback in every mode: the dashboard
can start packet captures, so it must never be reachable from the network
directly.  There is deliberately no flag to override this.  On the VPS a
reverse proxy (Caddy) on the same host terminates HTTPS and forwards to
the loopback port; the proxy's public host names are passed in as
allowed hosts.
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


def check_bind(host: str, port: int) -> None:
    """Raise ConfigurationError if *host* is not loopback or *port* is taken."""
    if not is_loopback_host(host):
        raise ConfigurationError(
            f"Refusing to bind to {host!r}: the dashboard controls packet capture "
            "and only listens on loopback (127.0.0.1, ::1 or localhost)."
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
) -> None:
    """Start the dashboard and block until interrupted."""
    import uvicorn

    from nst.web.app import create_app

    check_bind(host, port)
    token, proxy_origins = resolve_settings(mode, allowed_hosts or [], console_token)
    app = create_app(
        config, token=token, port=port,
        extra_origins=[*(dev_origins or []), *proxy_origins],
        mode=mode, allowed_hosts=allowed_hosts or [],
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
