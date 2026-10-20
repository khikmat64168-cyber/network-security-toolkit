"""
FastAPI application for the local NST web dashboard.

create_app() wires the existing toolkit modules behind a small JSON API
and one WebSocket stream:

    REST  /api/*          state, actions, history (bearer token required)
    WS    /api/stream     live events, sensor state, traffic snapshots
    GET   /api/mode       which mode this server runs in (no token needed)
    GET   /               the built single-page frontend (no data inside)

Modes
─────
    local    `nst web` on the operator's machine: everything, random
             per-launch token, loopback Host names only.
    console  The private console on the VPS behind the reverse proxy:
             everything, a fixed token from the environment, the proxy's
             host names allowed.
    public   The public demo behind the reverse proxy: no token, no
             capture, no stored data — only TLS inspection and GeoIP,
             rate-limited per client, with outbound TLS restricted to
             public addresses and TLS ports (see netguard).

Design decisions
────────────────
* Blocking toolkit calls (TLS handshakes, GeoIP HTTP, report rendering,
  capture probes) are plain `def` endpoints, so FastAPI runs them in its
  threadpool and the event loop stays responsive.
* Sniffer threads never touch asyncio directly: they hand messages to
  the loop with call_soon_threadsafe, and each WebSocket client drains
  its own bounded queue.  A client that falls behind is disconnected
  (code 1013) and resynchronises over REST when it reconnects.
* Errors carry a stable machine-readable `code` next to the message, so
  the UI can tell "permission denied" from "bad input" from "offline".
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import platform
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Set, Union

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from nst import __version__
from nst.core.config import AppConfig
from nst.core.logger import get_logger
from nst.core.paths import resolve_state_path
from nst.web import validation
from nst.web import netguard
from nst.web.events import EventStore, SecurityEvent
from nst.web.limits import SlidingWindowLimiter
from nst.web.reports import ReportStore
from nst.web.security import (
    REPORT_CSP,
    SECURITY_HEADERS,
    WS_SUBPROTOCOL,
    HostAllowlistMiddleware,
    allowed_origins,
    app_csp,
    bearer_token,
    tokens_match,
    ws_token,
)
from nst.web.sensors import SENSOR_KINDS, Sensor, SensorManager, probe_capture

logger = get_logger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
_CLIENT_QUEUE_SIZE = 1000
_TICK_SECONDS = 1.0
_RECENT_IN_TICK = 25
_TIMELINE_IN_TICK = 120

MODES = ("local", "console", "public")

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Public demo limits.  ip-api.com allows 45 requests/minute per server
# IP, so the global GeoIP budget stays below that.
PUBLIC_MAX_TLS_HOSTS = 3
PUBLIC_MAX_TLS_TIMEOUT = 8
PUBLIC_TLS_PER_MINUTE = 6          # hosts per client IP
PUBLIC_GEO_PER_MINUTE = 20         # targets per client IP
PUBLIC_GEO_GLOBAL_PER_MINUTE = 40  # targets across all clients
PUBLIC_UNAVAILABLE = (
    "Not available in the public demo. Live capture, detector tables and reports "
    "run in a local install (pip install 'network-security-toolkit[web]', then nst web)."
)


# ──────────────────────────────────────────────────────────────────────────────
# Request models
# ──────────────────────────────────────────────────────────────────────────────

class SensorStartRequest(BaseModel):
    interface: Optional[str] = Field(default=None, max_length=64)
    bpf_filter: Optional[str] = Field(default=None, max_length=validation.MAX_BPF_LENGTH)


class TLSScanRequest(BaseModel):
    hosts: List[str] = Field(min_length=1, max_length=validation.MAX_TLS_HOSTS)
    port: int = 443
    timeout: int = 10


class GeoRequest(BaseModel):
    targets: List[str] = Field(min_length=1, max_length=validation.MAX_GEO_TARGETS)


class ReportRequest(BaseModel):
    tls_hosts: List[str] = Field(default_factory=list, max_length=validation.MAX_TLS_HOSTS)
    port: int = 443
    timeout: int = 10
    include_interfaces: bool = True
    geo: bool = False


class APIError(Exception):
    def __init__(
        self, status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None
    ) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = headers


# ──────────────────────────────────────────────────────────────────────────────
# Live stream hub
# ──────────────────────────────────────────────────────────────────────────────

class StreamHub:
    """Fan-out of JSON messages from any thread to every WebSocket client."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._clients: Set["asyncio.Queue[Optional[Dict[str, Any]]]"] = set()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def register(self) -> "asyncio.Queue[Optional[Dict[str, Any]]]":
        queue: "asyncio.Queue[Optional[Dict[str, Any]]]" = asyncio.Queue(_CLIENT_QUEUE_SIZE)
        self._clients.add(queue)
        return queue

    def unregister(self, queue: "asyncio.Queue[Optional[Dict[str, Any]]]") -> None:
        self._clients.discard(queue)

    def publish(self, message: Dict[str, Any]) -> None:
        """Thread-safe: schedule *message* for delivery to all clients."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._deliver, message)
        except RuntimeError:   # loop shutting down
            pass

    def _deliver(self, message: Dict[str, Any]) -> None:
        for queue in list(self._clients):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Too slow: tell the consumer to drop the connection.
                self._clients.discard(queue)
                try:
                    while True:
                        queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                queue.put_nowait(None)


# ──────────────────────────────────────────────────────────────────────────────
# Serialisers
# ──────────────────────────────────────────────────────────────────────────────

def _tls_dict(result: Any) -> Dict[str, Any]:
    ok = result.error is None
    return {
        "host": result.host,
        "port": result.port,
        "error": result.error,
        "tls_version": result.tls_version or None,
        "cipher_suite": result.cipher_suite or None,
        "cipher_bits": result.key_bits or None,
        "public_key_type": result.public_key_type or None,
        "public_key_bits": result.public_key_bits or None,
        "subject": result.subject or None,
        "issuer": result.issuer or None,
        "not_before": result.not_before.isoformat() if ok else None,
        "not_after": result.not_after.isoformat() if ok else None,
        "days_until_expiry": result.days_until_expiry if ok else None,
        "san": list(result.san),
        "issues": [
            {"type": i.issue_type.value, "severity": i.severity, "detail": i.detail}
            for i in result.issues
        ],
    }


def _geo_dict(result: Any) -> Dict[str, Any]:
    return {
        "target": result.ip,
        "success": result.success,
        "is_private": result.is_private,
        "error": result.error or None,
        "country": result.country or None,
        "country_code": result.country_code or None,
        "region": result.region or None,
        "city": result.city or None,
        "isp": result.isp or None,
        "latitude": result.latitude if result.success and not result.is_private else None,
        "longitude": result.longitude if result.success and not result.is_private else None,
        "location": result.location,
    }


def _traffic_tick(details: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a traffic snapshot to what a 1-second WebSocket push needs."""
    if not details:
        return {}
    tick = dict(details)
    tick["recent"] = details["recent"][-_RECENT_IN_TICK:]
    tick["timeline"] = details["timeline"][-_TIMELINE_IN_TICK:]
    return tick


# ──────────────────────────────────────────────────────────────────────────────
# Application factory
# ──────────────────────────────────────────────────────────────────────────────

LOOPBACK_NETWORKS = ("127.0.0.0/8", "::1/128")


def parse_networks(values: Iterable[str]) -> List[IPNetwork]:
    """Parse CIDRs (and bare addresses); raises ValueError on a bad entry."""
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip()]


def _in_networks(address: str, networks: List[IPNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(address.strip().strip("[]"))
    except ValueError:
        return False
    return any(ip in net for net in networks)


def client_ip(request: Request, trusted: Optional[List[IPNetwork]] = None) -> str:
    """
    The requesting client's address.

    When the peer is a trusted reverse proxy (loopback for Caddy, the
    Docker network for Coolify's Traefik), the client is taken from
    X-Forwarded-For: the right-most entry that is not itself a trusted
    proxy.  Proxies append the address they saw, so entries further left
    may be forged by the client and are ignored.
    """
    networks = trusted if trusted is not None else parse_networks(LOOPBACK_NETWORKS)
    peer = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _in_networks(peer, networks):
        for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
            if not _in_networks(hop, networks):
                return hop
    return peer or "unknown"


def create_app(
    config: AppConfig,
    token: Optional[str],
    port: int,
    extra_origins: Optional[List[str]] = None,
    report_store: Optional[ReportStore] = None,
    static_dir: Path = STATIC_DIR,
    mode: str = "local",
    allowed_hosts: Iterable[str] = (),
    trusted_proxies: Iterable[str] = LOOPBACK_NETWORKS,
) -> FastAPI:
    if mode not in MODES:
        raise ValueError(f"Unknown mode {mode!r}")
    if mode == "public":
        token = None
    elif not token:
        raise ValueError(f"Mode {mode!r} requires an access token")
    public = mode == "public"
    trusted = parse_networks(trusted_proxies)

    # Event sequence numbers restart with the server; clients compare this
    # id to know when their cached history belongs to a previous run.
    instance_id = uuid.uuid4().hex
    store = EventStore()
    sensors = SensorManager(config, store)
    reports = report_store or ReportStore()
    hub = StreamHub()
    origins = allowed_origins(port, extra_origins or [])
    pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="nst-tls")
    tls_limiter = SlidingWindowLimiter(PUBLIC_TLS_PER_MINUTE, 60.0)
    geo_limiter = SlidingWindowLimiter(PUBLIC_GEO_PER_MINUTE, 60.0)
    geo_global = SlidingWindowLimiter(PUBLIC_GEO_GLOBAL_PER_MINUTE, 60.0)

    from nst.geoip.client import GeoIPClient

    geo_client = GeoIPClient()

    store.subscribe(lambda event: hub.publish({"type": "event", "data": event.to_dict()}))

    def on_sensor_change(sensor: Sensor) -> None:
        hub.publish({"type": "sensor", "data": sensor.status()})

    for sensor in sensors.sensors.values():
        sensor.on_change = on_sensor_change

    async def ticker() -> None:
        """Push sensor counters and traffic snapshots while anything is running."""
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            if hub.client_count == 0:
                continue
            active = [s for s in sensors.sensors.values() if s.active]
            if not active:
                continue
            hub.publish({"type": "sensors", "data": sensors.statuses()})
            traffic = sensors.get("traffic")
            if traffic.active:
                hub.publish({"type": "traffic", "data": _traffic_tick(traffic.details())})

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        hub.bind(asyncio.get_running_loop())
        task = asyncio.create_task(ticker())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.get_running_loop().run_in_executor(None, sensors.stop_all)
            pool.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="NST Web",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.sensors = sensors
    app.state.store = store
    app.state.hub = hub

    # ── Middleware & error handling ─────────────────────────────────────────

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        response.headers.setdefault("Content-Security-Policy", app_csp(port))
        return response

    app.add_middleware(HostAllowlistMiddleware, allowed_hosts=list(allowed_hosts))

    @app.exception_handler(APIError)
    async def api_error(_request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, exc.status,
                            headers=exc.headers)

    @app.exception_handler(validation.ValidationError)
    async def invalid_input(_request: Request, exc: validation.ValidationError) -> JSONResponse:
        return JSONResponse({"error": {"code": "invalid_input", "message": str(exc)}}, 422)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {401: "unauthorized", 404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error")
        return JSONResponse({"error": {"code": code, "message": str(exc.detail)}},
                            exc.status_code)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def bad_request(_request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", []) if p != "body")
        message = f"{where}: {first.get('msg', 'invalid request')}" if where else "Invalid request"
        return JSONResponse({"error": {"code": "invalid_input", "message": message}}, 422)

    def require_token(request: Request) -> None:
        if public:
            return
        assert token is not None
        if not tokens_match(token, bearer_token(request.headers.get("authorization"))):
            raise HTTPException(401, "Missing or invalid access token")

    def require_full(request: Request) -> None:
        """Endpoints that capture, store or reveal host data: never in the public demo."""
        if public:
            raise APIError(403, "public_demo", PUBLIC_UNAVAILABLE)
        require_token(request)

    def rate_limit(limiter: SlidingWindowLimiter, key: str, cost: int, what: str) -> None:
        retry = limiter.hit(key, cost)
        if retry is not None:
            seconds = max(1, int(retry + 0.999))
            raise APIError(429, "rate_limited",
                           f"Too many {what} from this address. Try again in {seconds}s.",
                           headers={"Retry-After": str(seconds)})

    auth = [Depends(require_token)]
    full = [Depends(require_full)]

    # ── System ──────────────────────────────────────────────────────────────

    @app.get("/api/mode")
    def get_mode() -> Dict[str, Any]:
        body: Dict[str, Any] = {"mode": mode, "version": __version__,
                                "auth": "none" if public else "token"}
        if public:
            body["limits"] = {
                "tls_hosts_per_request": PUBLIC_MAX_TLS_HOSTS,
                "tls_hosts_per_minute": PUBLIC_TLS_PER_MINUTE,
                "tls_timeout_max": PUBLIC_MAX_TLS_TIMEOUT,
                "tls_ports": sorted(netguard.PUBLIC_TLS_PORTS),
                "geoip_targets_per_minute": PUBLIC_GEO_PER_MINUTE,
            }
        return body

    @app.get("/api/health", dependencies=auth)
    def health() -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "status": "ok",
            "version": __version__,
            "mode": mode,
            "instance_id": instance_id,
            "last_event_seq": store.last_seq,
        }
        if not public:   # host details are for the operator only
            body.update({
                "python": sys.version.split()[0],
                "platform": platform.system(),
                "running_as_root": hasattr(os, "geteuid") and os.geteuid() == 0,
            })
        return body

    @app.get("/api/capabilities", dependencies=auth)
    def capabilities(interface: Optional[str] = None) -> Dict[str, Any]:
        if public:
            return _public_capabilities(sensors)
        iface = validation.interface(interface, _interface_names())
        probe = probe_capture(iface)
        capture_status = "operational" if probe.allowed else "blocked"
        capture_reason = None if probe.allowed else probe.message
        features = [
            {"id": kind, "label": sensors.get(kind).status()["label"],
             "status": capture_status, "reason": capture_reason, "requires": "capture"}
            for kind in SENSOR_KINDS
        ]
        features += [
            {"id": "tls_scan", "label": "TLS certificate inspection", "status": "operational",
             "reason": None, "requires": "network"},
            {"id": "geoip", "label": "IP geolocation", "status": "operational",
             "reason": "Sends public IPs to ip-api.com over plain HTTP; requires internet.",
             "requires": "internet"},
            {"id": "reports", "label": "HTML security reports", "status": "operational",
             "reason": None, "requires": None},
            {"id": "pcap_export", "label": "PCAP export", "status": "unavailable",
             "reason": "Not exposed in the dashboard. Use nst sniff -o FILE from the CLI.",
             "requires": None},
        ]
        return {
            "capture": {"allowed": probe.allowed, "code": probe.code,
                        "message": probe.message, "interface": iface},
            "features": features,
        }

    @app.get("/api/interfaces", dependencies=full)
    def interfaces() -> Dict[str, Any]:
        from nst.core.exceptions import InterfaceError
        from nst.sniffer.interface import InterfaceManager

        try:
            items = InterfaceManager.list_interfaces()
        except InterfaceError as exc:
            raise APIError(503, "interfaces_unavailable", str(exc))
        try:
            default = InterfaceManager.get_default()
        except InterfaceError:
            default = None
        return {
            "default": default,
            "interfaces": [
                {"name": i.name, "ip": i.ip or None, "mac": i.mac or None,
                 "description": i.description if i.description != i.name else None,
                 "is_default": i.name == default}
                for i in items
            ],
        }

    @app.get("/api/config", dependencies=full)
    def get_config() -> Dict[str, Any]:
        return {
            "network": {"interface": config.network.interface,
                        "promiscuous": config.network.promiscuous},
            "analyzer": {
                "detect_credentials": config.analyzer.detect_credentials,
                "port_scan_threshold": config.analyzer.suspicious_port_scan_threshold,
                "alert_on_suspicious": config.analyzer.alert_on_suspicious,
            },
            "arp_detector": {"trusted_ips": config.arp_detector.trusted_ips,
                             "gateway_ip": config.arp_detector.gateway_ip},
            "dns_detector": {"trusted_domains": config.dns_detector.trusted_domains,
                             "track_queries": config.dns_detector.track_queries},
            "mac_detector": {"flood_threshold": config.mac_detector.flood_threshold,
                             "window_secs": config.mac_detector.window_secs,
                             "table_limit": config.mac_detector.table_limit},
            "logging": {"level": config.logging.level,
                        "file": str(resolve_state_path(config.logging.file))},
            "reports_dir": str(reports.directory),
        }

    # ── Sensors ─────────────────────────────────────────────────────────────

    def _sensor(kind: str) -> Sensor:
        try:
            return sensors.get(kind)
        except KeyError:
            raise APIError(404, "unknown_sensor", f"Unknown sensor: {kind}")

    @app.get("/api/sensors", dependencies=full)
    def list_sensors() -> Dict[str, Any]:
        return {"sensors": sensors.statuses()}

    @app.get("/api/sensors/{kind}", dependencies=full)
    def sensor_detail(kind: str) -> Dict[str, Any]:
        sensor = _sensor(kind)
        return {"status": sensor.status(), "details": sensor.details()}

    @app.post("/api/sensors/{kind}/start", dependencies=full)
    def start_sensor(kind: str, body: SensorStartRequest) -> Dict[str, Any]:
        sensor = _sensor(kind)
        iface = validation.interface(body.interface, _interface_names())
        bpf = validation.bpf_filter(body.bpf_filter) if kind == "traffic" else ""
        if sensor.active:
            raise APIError(409, "already_running", f"{sensor.status()['label']} is already running")
        probe = probe_capture(iface)
        if not probe.allowed:
            status = 403 if probe.code == "permission_denied" else 503
            raise APIError(status, probe.code, probe.message)
        try:
            sensor.start(config, iface, bpf)
        except RuntimeError as exc:
            raise APIError(409, "already_running", str(exc))
        return {"status": sensor.status()}

    @app.post("/api/sensors/{kind}/stop", dependencies=full)
    def stop_sensor(kind: str) -> Dict[str, Any]:
        sensor = _sensor(kind)
        sensor.stop()
        sensor.join(timeout=5.0)
        return {"status": sensor.status()}

    # ── Events ──────────────────────────────────────────────────────────────

    @app.get("/api/events", dependencies=full)
    def list_events(after: int = 0, limit: int = 200, severity: Optional[str] = None,
                    sensor: Optional[str] = None) -> Dict[str, Any]:
        limit = max(1, min(limit, 1000))
        events = store.list(after=after, limit=limit, severity=severity, sensor=sensor)
        return {"events": [e.to_dict() for e in events], "counts": store.counts(),
                "last_seq": store.last_seq, "instance_id": instance_id}

    @app.get("/api/events/{event_id}", dependencies=full)
    def get_event(event_id: str) -> Dict[str, Any]:
        event: Optional[SecurityEvent] = store.get(event_id)
        if event is None:
            raise APIError(404, "not_found", "Event not found (it may have aged out)")
        return {"event": event.to_dict()}

    # ── TLS / GeoIP ─────────────────────────────────────────────────────────

    def _scan_all(hosts: List[str], default_port: int, timeout: int) -> List[Any]:
        from nst.tls_inspector import scanner

        targets = validation.tls_targets(hosts, default_port)
        timeout = validation.tls_timeout(timeout)
        futures = [pool.submit(scanner.scan, h, port=p, timeout=timeout) for h, p in targets]
        return [f.result() for f in futures]

    def _scan_public(request: Request, body: TLSScanRequest) -> List[Any]:
        from nst.tls_inspector import scanner

        if len(body.hosts) > PUBLIC_MAX_TLS_HOSTS:
            raise validation.ValidationError(
                f"At most {PUBLIC_MAX_TLS_HOSTS} hosts per scan in the public demo")
        # Shorter waits are harmless, so the demo caps the timeout instead
        # of rejecting the console's default.
        timeout = min(validation.tls_timeout(body.timeout), PUBLIC_MAX_TLS_TIMEOUT)
        targets = validation.tls_targets(body.hosts, body.port)
        for _host, scan_port in targets:
            netguard.check_public_port(scan_port)
        rate_limit(tls_limiter, client_ip(request, trusted), len(targets), "TLS scans")
        # Resolve and vet every host before connecting to any of them.
        pinned = [(h, p, netguard.resolve_public(h)) for h, p in targets]
        futures = [pool.submit(scanner.scan, h, port=p, timeout=timeout, connect_ip=ip)
                   for h, p, ip in pinned]
        return [f.result() for f in futures]

    @app.post("/api/tls/scan", dependencies=auth)
    def tls_scan(request: Request, body: TLSScanRequest) -> Dict[str, Any]:
        if public:
            results = _scan_public(request, body)
        else:
            results = _scan_all(body.hosts, body.port, body.timeout)
        return {"results": [_tls_dict(r) for r in results]}

    @app.post("/api/geoip", dependencies=auth)
    def geoip(request: Request, body: GeoRequest) -> Dict[str, Any]:
        targets = validation.geo_targets(body.targets)
        if public:
            rate_limit(geo_limiter, client_ip(request, trusted), len(targets), "GeoIP lookups")
            rate_limit(geo_global, "global", len(targets), "GeoIP lookups (server-wide)")
        return {"results": [_geo_dict(geo_client.lookup(t)) for t in targets]}

    # ── Reports ─────────────────────────────────────────────────────────────

    @app.get("/api/reports", dependencies=full)
    def list_reports() -> Dict[str, Any]:
        return {"reports": reports.list(), "directory": str(reports.directory)}

    @app.post("/api/reports", dependencies=full)
    def create_report(body: ReportRequest) -> Dict[str, Any]:
        from nst.reporter.builder import ReportBuilder
        from nst.reporter.writer import write

        if not body.tls_hosts and not body.include_interfaces:
            raise validation.ValidationError("Select TLS hosts or include interfaces")
        builder = ReportBuilder()
        if body.tls_hosts:
            builder.add_tls_results(_scan_all(body.tls_hosts, body.port, body.timeout))
            if body.geo:
                builder.add_geo(geo_client)
        if body.include_interfaces:
            builder.add_interfaces()
        data = builder.build()
        path = write(data, reports.new_path(data.generated_at))
        return {
            "report": next((r for r in reports.list() if r["name"] == path.name),
                           {"name": path.name}),
            "summary": {"tls_hosts": len(data.tls_findings),
                        "interfaces": len(data.interfaces),
                        "critical": data.critical_tls_count},
        }

    @app.get("/api/reports/{name}", dependencies=full)
    def get_report(name: str) -> Response:
        path = reports.resolve(name)
        if path is None:
            raise APIError(404, "not_found", "Report not found")
        return FileResponse(path, media_type="text/html; charset=utf-8",
                            headers={"Content-Security-Policy": REPORT_CSP})

    # ── Live stream ─────────────────────────────────────────────────────────

    @app.websocket("/api/stream")
    async def stream(ws: WebSocket) -> None:
        if public:
            await ws.close(code=1008)
            return
        assert token is not None
        origin = ws.headers.get("origin")
        if origin is None or origin.rstrip("/") not in origins:
            await ws.close(code=1008)
            return
        if not tokens_match(token, ws_token(list(ws.scope.get("subprotocols", [])))):
            await ws.close(code=1008)
            return
        await ws.accept(subprotocol=WS_SUBPROTOCOL)
        queue = hub.register()
        receiver: "asyncio.Future[Any]" = asyncio.ensure_future(ws.receive())
        try:
            await ws.send_json({"type": "hello", "data": {
                "version": __version__, "instance_id": instance_id, "last_seq": store.last_seq,
                "sensors": sensors.statuses()}})
            while True:
                getter = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait({receiver, getter},
                                             return_when=asyncio.FIRST_COMPLETED)
                if receiver in done:
                    getter.cancel()
                    if receiver.result().get("type") == "websocket.disconnect":
                        return
                    receiver = asyncio.ensure_future(ws.receive())   # ignore client data
                    continue
                message = getter.result()
                if message is None:
                    await ws.close(code=1013)
                    return
                await ws.send_json(message)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            receiver.cancel()
            hub.unregister(queue)

    # ── Frontend ────────────────────────────────────────────────────────────

    index = static_dir / "index.html"
    if (static_dir / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def root() -> Response:
        if index.is_file():
            return FileResponse(index, media_type="text/html; charset=utf-8")
        return HTMLResponse(_NOT_BUILT, status_code=503)

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon() -> Response:
        icon = static_dir / "favicon.svg"
        if icon.is_file():
            return FileResponse(icon, media_type="image/svg+xml")
        raise APIError(404, "not_found", "No favicon")

    return app


def _public_capabilities(sensors: SensorManager) -> Dict[str, Any]:
    features = [
        {"id": kind, "label": sensors.get(kind).status()["label"], "status": "unavailable",
         "reason": PUBLIC_UNAVAILABLE, "requires": "capture"}
        for kind in SENSOR_KINDS
    ]
    features += [
        {"id": "tls_scan", "label": "TLS certificate inspection", "status": "operational",
         "reason": (f"Public demo: up to {PUBLIC_MAX_TLS_HOSTS} public hosts per scan and "
                    f"{PUBLIC_TLS_PER_MINUTE} per minute; TLS ports only."),
         "requires": "network"},
        {"id": "geoip", "label": "IP geolocation", "status": "operational",
         "reason": (f"Public demo: up to {PUBLIC_GEO_PER_MINUTE} lookups per minute. Sends public "
                    "IPs to ip-api.com over plain HTTP."),
         "requires": "internet"},
        {"id": "reports", "label": "HTML security reports", "status": "unavailable",
         "reason": PUBLIC_UNAVAILABLE, "requires": None},
        {"id": "pcap_export", "label": "PCAP export", "status": "unavailable",
         "reason": "Not exposed in the dashboard. Use nst sniff -o FILE from the CLI.",
         "requires": None},
    ]
    return {
        "capture": {"allowed": False, "code": "public_demo",
                    "message": PUBLIC_UNAVAILABLE, "interface": None},
        "features": features,
    }


def _interface_names() -> List[str]:
    from nst.core.exceptions import InterfaceError
    from nst.sniffer.interface import InterfaceManager

    try:
        return [i.name for i in InterfaceManager.list_interfaces()]
    except InterfaceError:
        return []


_NOT_BUILT = """<!doctype html><meta charset="utf-8"><title>NST Web</title>
<body style="font:15px system-ui;background:#0b0f14;color:#d6dde6;padding:40px">
<h1 style="font-size:20px">NST Web frontend is not built</h1>
<p>The API is running, but no frontend bundle was found in
<code>src/nst/web/static/</code>.</p>
<p>Install it with <code>./scripts/fetch_frontend.sh --release</code> (or
<code>--from ../Networkscan-front</code>) and restart <code>nst web</code>.</p></body>"""
