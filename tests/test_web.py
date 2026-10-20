"""
Tests for the local web dashboard backend (nst/web/).

The FastAPI app is driven through Starlette's TestClient.  Capture is
exercised end-to-end through the real sensor → pipeline → EventStore →
API path, with only SniffLoop.run replaced by a replay of real Scapy
packets, so no root privileges or network access are needed.

Tests cover:
  - Security: bearer token, loopback Host check, WebSocket Origin/token,
    security headers, loopback-only bind
  - Validation of interfaces, BPF filters, hosts, batch sizes
  - Event normalisation and credential redaction
  - Sensor lifecycle (start / duplicate / stop / permission errors)
  - TLS scan, GeoIP and report endpoints, including path traversal
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterator, List
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from nst.analyzer.credentials import CredentialFinding
from nst.analyzer.threats import ThreatEvent
from nst.core.config import AppConfig
from nst.core.exceptions import ConfigurationError
from nst.sniffer.interface import NetworkInterface
from nst.web import security, validation
from nst.web.app import create_app
from nst.web.events import REDACTED, EventStore, normalize
from nst.web.reports import ReportStore
from nst.web.sensors import CaptureProbe, TrafficTimeline
from nst.web.server import check_bind, dashboard_url

TOKEN = "test-token-123"
PORT = 8780
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = BASE
WS_URL = f"ws://127.0.0.1:{PORT}/api/stream"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

_IFACES = [
    NetworkInterface(name="en0", ip="10.0.0.2", mac="aa:aa:aa:aa:aa:aa", description="Wi-Fi"),
    NetworkInterface(name="lo0", ip="127.0.0.1", mac="", description="lo0"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

def _basic_auth_packet() -> Any:
    payload = (b"GET / HTTP/1.1\r\nHost: x\r\n"
               b"Authorization: Basic YWRtaW46czNjcjN0\r\n\r\n")
    return (Ether() / IP(src="10.0.0.5", dst="10.0.0.9")
            / TCP(sport=40000, dport=80, flags="PA") / Raw(load=payload))


REPLAY: List[Any] = []


def _fake_run(self: Any, **kwargs: Any) -> None:
    """Replacement for SniffLoop.run: replay REPLAY, then idle until stopped."""
    for pkt in REPLAY:
        kwargs["prn"](pkt)
    self._stop_requested.wait(5)


@pytest.fixture()
def client(tmp_path: Path) -> Iterator[TestClient]:
    REPLAY[:] = []
    app = create_app(AppConfig(), token=TOKEN, port=PORT,
                     report_store=ReportStore(tmp_path / "reports"),
                     static_dir=tmp_path / "static")
    with patch("nst.sniffer.interface.InterfaceManager.list_interfaces", return_value=_IFACES), \
         patch("nst.sniffer.interface.InterfaceManager.get_default", return_value="en0"), \
         patch("nst.web.app.probe_capture",
               return_value=CaptureProbe(True, "ok", "Capture socket opened successfully")), \
         patch("nst.sniffer.loop.SniffLoop.run", _fake_run), \
         patch("nst.arp_detector.table.get_system_arp_cache", return_value={}):
        with TestClient(app, base_url=BASE) as test_client:
            yield test_client


def _wait_state(client: TestClient, kind: str, states: tuple[str, ...]) -> dict:
    for _ in range(100):
        status = client.get(f"/api/sensors/{kind}", headers=AUTH).json()["status"]
        if status["state"] in states:
            return status
        time.sleep(0.02)
    raise AssertionError(f"{kind} never reached {states}")


# ──────────────────────────────────────────────────────────────────────────────
# Security
# ──────────────────────────────────────────────────────────────────────────────

class TestAccessControl:
    def test_api_requires_token(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"

    def test_wrong_token_rejected(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401

    def test_valid_token_accepted(self, client: TestClient) -> None:
        body = client.get("/api/health", headers=AUTH).json()
        assert body["status"] == "ok"
        assert "running_as_root" in body

    def test_foreign_host_header_rejected(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={**AUTH, "Host": "evil.example:8780"})
        assert response.status_code == 421

    def test_security_headers_present(self, client: TestClient) -> None:
        headers = client.get("/api/health", headers=AUTH).headers
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert f"ws://127.0.0.1:{PORT}" in headers["content-security-policy"]
        assert "frame-ancestors 'none'" in headers["content-security-policy"]

    def test_websocket_rejects_foreign_origin(self, client: TestClient) -> None:
        from starlette.websockets import WebSocketDisconnect

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                WS_URL, headers={"origin": "http://evil.example"},
                subprotocols=[security.WS_SUBPROTOCOL, security.WS_TOKEN_PREFIX + TOKEN],
            ) as ws:
                ws.receive_json()

    def test_websocket_rejects_missing_token(self, client: TestClient) -> None:
        from starlette.websockets import WebSocketDisconnect

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(WS_URL, headers={"origin": ORIGIN},
                                          subprotocols=[security.WS_SUBPROTOCOL]) as ws:
                ws.receive_json()

    def test_websocket_rejects_foreign_host(self, client: TestClient) -> None:
        from starlette.websockets import WebSocketDisconnect

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "ws://evil.example:8780/api/stream", headers={"origin": ORIGIN},
                subprotocols=[security.WS_SUBPROTOCOL, security.WS_TOKEN_PREFIX + TOKEN],
            ) as ws:
                ws.receive_json()

    def test_websocket_hello_with_valid_credentials(self, client: TestClient) -> None:
        with client.websocket_connect(
            WS_URL, headers={"origin": ORIGIN},
            subprotocols=[security.WS_SUBPROTOCOL, security.WS_TOKEN_PREFIX + TOKEN],
        ) as ws:
            hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert len(hello["data"]["instance_id"]) == 32
        events = client.get("/api/events", headers=AUTH).json()
        assert events["instance_id"] == hello["data"]["instance_id"]
        assert {s["kind"] for s in hello["data"]["sensors"]} == {"traffic", "arp", "dns", "mac"}


class TestSecurityHelpers:
    @pytest.mark.parametrize("host, ok", [
        ("127.0.0.1", True), ("127.8.8.8", True), ("localhost", True), ("::1", True),
        ("[::1]", True), ("0.0.0.0", False), ("192.168.1.10", False), ("evil.example", False),
    ])
    def test_is_loopback_host(self, host: str, ok: bool) -> None:
        assert security.is_loopback_host(host) is ok

    @pytest.mark.parametrize("header, host", [
        ("127.0.0.1:8780", "127.0.0.1"), ("[::1]:8780", "::1"), ("localhost", "localhost"),
    ])
    def test_split_host_header(self, header: str, host: str) -> None:
        assert security.split_host_header(header) == host

    def test_new_tokens_are_unique_and_long(self) -> None:
        tokens = {security.new_token() for _ in range(20)}
        assert len(tokens) == 20
        assert all(len(t) >= 40 for t in tokens)

    def test_refuses_non_loopback_bind(self) -> None:
        with pytest.raises(ConfigurationError, match="loopback"):
            check_bind("0.0.0.0", 8780)

    def test_reports_port_in_use(self) -> None:
        import socket

        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen()
            with pytest.raises(ConfigurationError, match="Cannot listen"):
                check_bind("127.0.0.1", busy.getsockname()[1])

    def test_dashboard_url_puts_token_in_fragment(self) -> None:
        assert dashboard_url("127.0.0.1", 8780, "abc") == "http://127.0.0.1:8780/#token=abc"
        assert dashboard_url("::1", 8780, "abc") == "http://[::1]:8780/#token=abc"


# ──────────────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────────────

class TestValidation:
    def test_unknown_interface(self) -> None:
        with pytest.raises(validation.ValidationError):
            validation.interface("evil;rm", ["en0"])

    def test_blank_interface_means_auto(self) -> None:
        assert validation.interface("", ["en0"]) is None

    @pytest.mark.parametrize("expr", ["tcp port 80", "arp", "host 10.0.0.1 and not port 22"])
    def test_valid_bpf(self, expr: str) -> None:
        assert validation.bpf_filter(expr) == expr

    @pytest.mark.parametrize("expr", ["tcp portt 80", "udp; rm -rf /", "x" * 300, "tcp\x00"])
    def test_invalid_bpf(self, expr: str) -> None:
        with pytest.raises(validation.ValidationError):
            validation.bpf_filter(expr)

    def test_hosts(self) -> None:
        assert validation.host("GitHub.com.") == "github.com"
        assert validation.host("[::1]") == "::1"
        with pytest.raises(validation.ValidationError):
            validation.host("bad host")

    def test_tls_targets_parse_ports_and_cap_batch(self) -> None:
        assert validation.tls_targets(["a.com:8443", "b.com"], 443) == [("a.com", 8443),
                                                                          ("b.com", 443)]
        with pytest.raises(validation.ValidationError):
            validation.tls_targets([f"h{i}.com" for i in range(11)], 443)
        with pytest.raises(validation.ValidationError):
            validation.tls_targets(["a.com:70000"], 443)


# ──────────────────────────────────────────────────────────────────────────────
# Events
# ──────────────────────────────────────────────────────────────────────────────

class TestEvents:
    def test_credentials_are_redacted(self) -> None:
        finding = CredentialFinding(
            src_ip="10.0.0.5", dst_ip="10.0.0.9", protocol="HTTP", kind="HTTP Basic Auth",
            username="admin", password="s3cr3t", context="Authorization: Basic YWRtaW46czNjcjN0",
        )
        event = normalize(finding, "traffic", 1)
        flat = str(event.to_dict())
        assert "s3cr3t" not in flat
        assert "YWRtaW46czNjcjN0" not in flat
        assert event.evidence["password"] == REDACTED
        assert event.category == "credential.plaintext"
        assert event.severity == "high"

    def test_threat_details_become_json(self) -> None:
        threat = ThreatEvent(threat_type="port_scan", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                             severity="medium", description="scan",
                             details={"ports": {22, 80, 443}})
        event = normalize(threat, "traffic", 7)
        assert event.evidence["ports"] == [22, 443, 80] or event.evidence["ports"] == [22, 80, 443]
        assert event.category == "threat.port_scan"
        assert event.seq == 7

    def test_unknown_type_rejected(self) -> None:
        with pytest.raises(TypeError):
            normalize(object(), "traffic", 1)

    def test_store_sequence_filter_and_counts(self) -> None:
        store = EventStore(capacity=3)
        threat = ThreatEvent("suspicious_port", "1.1.1.1", "2.2.2.2", "high", "x")
        for _ in range(5):
            store.add(threat, "traffic")
        assert [e.seq for e in store.list()] == [3, 4, 5]
        assert [e.seq for e in store.list(after=4)] == [5]
        assert store.counts()["high"] == 5          # not capped by capacity
        assert store.list(severity="low") == []
        first = store.list()[0]
        assert store.get(first.id) == first

    def test_broken_subscriber_does_not_stop_store(self) -> None:
        store = EventStore()
        store.subscribe(lambda _e: (_ for _ in ()).throw(RuntimeError("boom")))
        store.add(ThreatEvent("suspicious_port", "1.1.1.1", "2.2.2.2", "high", "x"), "traffic")
        assert store.last_seq == 1

    def test_timeline_buckets_per_second(self) -> None:
        timeline = TrafficTimeline()
        timeline.add(100, now=10.2)
        timeline.add(50, now=10.9)
        timeline.add(10, now=11.0)
        assert timeline.series() == [{"t": 10, "packets": 2, "bytes": 150},
                                     {"t": 11, "packets": 1, "bytes": 10}]


# ──────────────────────────────────────────────────────────────────────────────
# System endpoints
# ──────────────────────────────────────────────────────────────────────────────

class TestSystemEndpoints:
    def test_interfaces(self, client: TestClient) -> None:
        body = client.get("/api/interfaces", headers=AUTH).json()
        assert body["default"] == "en0"
        assert [i["name"] for i in body["interfaces"]] == ["en0", "lo0"]
        assert body["interfaces"][0]["is_default"] is True

    def test_capabilities_distinguish_unavailable(self, client: TestClient) -> None:
        body = client.get("/api/capabilities", headers=AUTH).json()
        status = {f["id"]: f["status"] for f in body["features"]}
        assert status["traffic"] == "operational"
        assert status["pcap_export"] == "unavailable"
        assert body["capture"]["allowed"] is True

    def test_capabilities_report_blocked_capture(self, client: TestClient) -> None:
        denied = CaptureProbe(False, "permission_denied", "denied")
        with patch("nst.web.app.probe_capture", return_value=denied):
            body = client.get("/api/capabilities", headers=AUTH).json()
        status = {f["id"]: f["status"] for f in body["features"]}
        assert status["arp"] == "blocked"
        assert status["tls_scan"] == "operational"

    def test_config_has_no_secrets_and_resolved_paths(self, client: TestClient) -> None:
        body = client.get("/api/config", headers=AUTH).json()
        assert set(body) >= {"network", "analyzer", "arp_detector", "logging", "reports_dir"}
        assert TOKEN not in str(body)

    def test_frontend_missing_returns_503(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 503
        assert "not built" in response.text


# ──────────────────────────────────────────────────────────────────────────────
# Sensors
# ──────────────────────────────────────────────────────────────────────────────

class TestSensors:
    def test_traffic_pipeline_end_to_end(self, client: TestClient) -> None:
        REPLAY[:] = [_basic_auth_packet(),
                     Ether() / IP(src="10.0.0.7", dst="10.0.0.9") / TCP(dport=443, flags="S")]
        started = client.post("/api/sensors/traffic/start", headers=AUTH,
                              json={"interface": "en0", "bpf_filter": "tcp"})
        assert started.status_code == 200, started.text
        assert started.json()["status"]["bpf_filter"] == "tcp"

        for _ in range(100):
            detail = client.get("/api/sensors/traffic", headers=AUTH).json()
            if detail["details"].get("total_packets") == 2:
                break
            time.sleep(0.02)
        details = detail["details"]
        assert details["total_packets"] == 2
        assert details["protocols"]
        assert details["timeline"] and details["timeline"][-1]["packets"] >= 1

        events = client.get("/api/events", headers=AUTH).json()
        credential = next(e for e in events["events"] if e["category"] == "credential.plaintext")
        assert credential["evidence"]["password"] == REDACTED
        assert "s3cr3t" not in str(events)
        assert client.get(f"/api/events/{credential['id']}", headers=AUTH).status_code == 200

        stopped = client.post("/api/sensors/traffic/stop", headers=AUTH).json()["status"]
        assert stopped["state"] == "stopped"
        assert stopped["packets"] == 2

    def test_arp_sensor_reports_bindings_and_events(self, client: TestClient) -> None:
        REPLAY[:] = [
            Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.0.0.2"),
            Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:99", pdst="10.0.0.2"),
        ]
        assert client.post("/api/sensors/arp/start", headers=AUTH, json={}).status_code == 200
        for _ in range(100):
            detail = client.get("/api/sensors/arp", headers=AUTH).json()
            if detail["status"]["events"]:
                break
            time.sleep(0.02)
        assert detail["details"]["bindings"][0]["mac"] == "aa:bb:cc:dd:ee:99"
        events = client.get("/api/events?sensor=arp", headers=AUTH).json()["events"]
        assert [e["category"] for e in events] == ["arp.mac_change"]
        client.post("/api/sensors/arp/stop", headers=AUTH)

    def test_duplicate_start_conflicts(self, client: TestClient) -> None:
        assert client.post("/api/sensors/mac/start", headers=AUTH, json={}).status_code == 200
        second = client.post("/api/sensors/mac/start", headers=AUTH, json={})
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "already_running"
        client.post("/api/sensors/mac/stop", headers=AUTH)

    def test_permission_denied_is_reported(self, client: TestClient) -> None:
        denied = CaptureProbe(False, "permission_denied", "Opening a capture socket was denied")
        with patch("nst.web.app.probe_capture", return_value=denied):
            response = client.post("/api/sensors/dns/start", headers=AUTH, json={})
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "permission_denied"
        assert client.get("/api/sensors/dns", headers=AUTH).json()["status"]["state"] == "idle"

    def test_runtime_permission_error_sets_error_state(self, client: TestClient) -> None:
        with patch("nst.sniffer.loop.SniffLoop.run", side_effect=PermissionError("denied")):
            client.post("/api/sensors/dns/start", headers=AUTH, json={})
            status = _wait_state(client, "dns", ("error",))
        assert status["error"]["code"] == "permission_denied"

    def test_invalid_inputs(self, client: TestClient) -> None:
        bad_iface = client.post("/api/sensors/traffic/start", headers=AUTH,
                                json={"interface": "eth9"})
        bad_bpf = client.post("/api/sensors/traffic/start", headers=AUTH,
                              json={"bpf_filter": "tcp portt 80"})
        unknown = client.post("/api/sensors/wifi/start", headers=AUTH, json={})
        assert bad_iface.status_code == bad_bpf.status_code == 422
        assert bad_bpf.json()["error"]["code"] == "invalid_input"
        assert unknown.status_code == 404

    def test_never_started_sensor_reports_no_metrics(self, client: TestClient) -> None:
        detail = client.get("/api/sensors/dns", headers=AUTH).json()
        assert detail["status"]["packets"] is None
        assert detail["details"] == {}


# ──────────────────────────────────────────────────────────────────────────────
# TLS / GeoIP / reports
# ──────────────────────────────────────────────────────────────────────────────

class TestTools:
    def test_tls_scan_serialises_results(self, client: TestClient) -> None:
        from tests.test_tls_inspector import _result

        with patch("nst.tls_inspector.scanner.scan",
                   return_value=_result(public_key_type="EC", public_key_bits=256)):
            body = client.post("/api/tls/scan", headers=AUTH,
                               json={"hosts": ["example.com"]}).json()
        result = body["results"][0]
        assert result["host"] == "example.com"
        assert result["public_key_type"] == "EC"
        assert result["days_until_expiry"] is not None

    def test_tls_scan_rejects_bad_host_and_timeout(self, client: TestClient) -> None:
        bad = client.post("/api/tls/scan", headers=AUTH, json={"hosts": ["not a host"]})
        slow = client.post("/api/tls/scan", headers=AUTH,
                           json={"hosts": ["a.com"], "timeout": 99})
        assert bad.status_code == slow.status_code == 422

    def test_geoip_private_address_needs_no_network(self, client: TestClient) -> None:
        body = client.post("/api/geoip", headers=AUTH, json={"targets": ["192.168.1.1"]}).json()
        assert body["results"][0]["is_private"] is True
        assert body["results"][0]["latitude"] is None

    def test_report_create_list_fetch(self, client: TestClient) -> None:
        created = client.post("/api/reports", headers=AUTH,
                              json={"include_interfaces": True}).json()
        name = created["report"]["name"]
        listing = client.get("/api/reports", headers=AUTH).json()
        assert name in [r["name"] for r in listing["reports"]]

        fetched = client.get(f"/api/reports/{name}", headers=AUTH)
        assert fetched.status_code == 200
        assert fetched.headers["content-security-policy"].startswith("sandbox")
        assert "<html" in fetched.text.lower()

    def test_report_requires_content(self, client: TestClient) -> None:
        response = client.post("/api/reports", headers=AUTH, json={"include_interfaces": False})
        assert response.status_code == 422

    @pytest.mark.parametrize("name", ["..%2F..%2Fsecret.html", "nst_report_x.html",
                                      "nst_report_20260101_000000.html"])
    def test_report_fetch_rejects_unknown_names(self, client: TestClient, name: str) -> None:
        assert client.get(f"/api/reports/{name}", headers=AUTH).status_code == 404

    def test_report_store_names_do_not_collide(self, tmp_path: Path) -> None:
        from datetime import datetime

        store = ReportStore(tmp_path)
        when = datetime(2026, 1, 1, 12, 0, 0)
        first = store.new_path(when)
        first.write_text("x")
        second = store.new_path(when)
        assert first != second
        assert store.resolve(second.name) is None      # not written yet
        assert store.resolve(first.name) == first.resolve()
