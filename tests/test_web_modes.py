"""
Tests for the VPS deployment modes of the web backend.

Tests cover:
  - netguard: public-address checks, resolution pinning, TLS port allowlist
  - SlidingWindowLimiter
  - public mode: no token, capture / storage endpoints refused, WebSocket
    refused, TLS scans restricted and rate-limited per client, GeoIP limits
  - console mode: fixed token, proxied host and https origin accepted
  - server.resolve_settings and the `nst web --mode` CLI validation
"""
from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Iterator, List
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from nst.core.config import AppConfig
from nst.core.exceptions import ConfigurationError
from nst.web import netguard, security
from nst.web.app import PUBLIC_TLS_PER_MINUTE, create_app
from nst.web.limits import SlidingWindowLimiter
from nst.web.reports import ReportStore
from nst.web.server import resolve_settings
from nst.web.validation import ValidationError

PUBLIC_HOST = "demo.example.com"
CONSOLE_HOST = "console.example.com"
CONSOLE_TOKEN = "c" * 48


def _addrinfo(*addresses: str) -> List[Any]:
    return [
        (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
        for a in addresses
    ]


# ──────────────────────────────────────────────────────────────────────────────
# netguard
# ──────────────────────────────────────────────────────────────────────────────

class TestNetguard:
    @pytest.mark.parametrize("address, public", [
        ("140.82.121.4", True), ("2606:4700::6810:84e5", True),
        ("127.0.0.1", False), ("10.0.0.5", False), ("172.16.3.4", False),
        ("192.168.1.1", False), ("169.254.169.254", False), ("100.64.0.1", False),
        ("0.0.0.0", False), ("224.0.0.1", False), ("::1", False), ("fe80::1", False),
        ("::ffff:10.0.0.1", False), ("::ffff:140.82.121.4", True),
    ])
    def test_is_public_address(self, address: str, public: bool) -> None:
        assert netguard.is_public_address(address) is public

    def test_resolve_returns_first_public_address(self) -> None:
        with patch("socket.getaddrinfo", return_value=_addrinfo("140.82.121.4", "140.82.121.3")):
            assert netguard.resolve_public("github.com") == "140.82.121.4"

    def test_prefers_ipv4_when_both_families_resolve(self) -> None:
        answer = _addrinfo("2606:4700::6810:84e5", "140.82.121.4")
        with patch("socket.getaddrinfo", return_value=answer):
            assert netguard.resolve_public("dual.example") == "140.82.121.4"

    def test_any_private_answer_rejects_the_host(self) -> None:
        with patch("socket.getaddrinfo", return_value=_addrinfo("140.82.121.4", "10.0.0.7")):
            with pytest.raises(ValidationError, match="non-public"):
                netguard.resolve_public("sneaky.example")

    def test_metadata_endpoint_rejected(self) -> None:
        with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254")):
            with pytest.raises(ValidationError):
                netguard.resolve_public("metadata.example")

    def test_unresolvable_host(self) -> None:
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with pytest.raises(ValidationError, match="Cannot resolve"):
                netguard.resolve_public("nonexistent.invalid")

    def test_port_allowlist(self) -> None:
        assert netguard.check_public_port(443) == 443
        with pytest.raises(ValidationError, match="not allowed"):
            netguard.check_public_port(22)


# ──────────────────────────────────────────────────────────────────────────────
# Rate limiter
# ──────────────────────────────────────────────────────────────────────────────

class TestLimiter:
    def test_window_and_retry_after(self) -> None:
        now = [100.0]
        limiter = SlidingWindowLimiter(3, 60.0, clock=lambda: now[0])
        assert limiter.hit("a", 2) is None
        assert limiter.hit("a") is None
        retry = limiter.hit("a")
        assert retry == pytest.approx(60.0)
        assert limiter.hit("b") is None          # other keys are independent
        now[0] += 60.0
        assert limiter.hit("a") is None          # window has passed

    def test_cost_above_limit_is_refused(self) -> None:
        limiter = SlidingWindowLimiter(3, 60.0)
        assert limiter.hit("a", 4) == 60.0
        assert limiter.hit("a", 3) is None

    def test_key_eviction_is_bounded(self) -> None:
        now = [0.0]
        limiter = SlidingWindowLimiter(1, 10.0, clock=lambda: now[0], max_keys=2)
        limiter.hit("a")
        limiter.hit("b")
        now[0] = 20.0
        limiter.hit("c")
        assert set(limiter._hits) == {"c"}


# ──────────────────────────────────────────────────────────────────────────────
# Public mode
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def public_client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(AppConfig(), token=None, port=8766, mode="public",
                     allowed_hosts=[PUBLIC_HOST], report_store=ReportStore(tmp_path),
                     static_dir=tmp_path / "static")
    # The reverse proxy connects from loopback and reports the client in XFF.
    with TestClient(app, base_url=f"https://{PUBLIC_HOST}", client=("127.0.0.1", 50000)) as client:
        yield client


def _xff(ip: str) -> dict:
    return {"X-Forwarded-For": ip}


class TestPublicMode:
    def test_mode_endpoint_needs_no_token(self, public_client: TestClient) -> None:
        body = public_client.get("/api/mode").json()
        assert body["mode"] == "public"
        assert body["auth"] == "none"
        assert 443 in body["limits"]["tls_ports"]

    def test_health_hides_host_details(self, public_client: TestClient) -> None:
        body = public_client.get("/api/health").json()
        assert body["mode"] == "public"
        assert "running_as_root" not in body and "python" not in body

    def test_capabilities_mark_capture_unavailable(self, public_client: TestClient) -> None:
        body = public_client.get("/api/capabilities").json()
        status = {f["id"]: f["status"] for f in body["features"]}
        assert status["traffic"] == status["arp"] == status["reports"] == "unavailable"
        assert status["tls_scan"] == status["geoip"] == "operational"
        assert body["capture"]["allowed"] is False

    @pytest.mark.parametrize("method, path", [
        ("get", "/api/interfaces"), ("get", "/api/config"), ("get", "/api/sensors"),
        ("post", "/api/sensors/traffic/start"), ("post", "/api/sensors/arp/stop"),
        ("get", "/api/events"), ("get", "/api/reports"), ("post", "/api/reports"),
        ("get", "/api/reports/nst_report_20260101_000000.html"),
    ])
    def test_capture_and_storage_endpoints_refused(
        self, public_client: TestClient, method: str, path: str
    ) -> None:
        response = getattr(public_client, method)(path, **({"json": {}} if method == "post" else {}))
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "public_demo"

    def test_websocket_refused(self, public_client: TestClient) -> None:
        from starlette.websockets import WebSocketDisconnect

        with pytest.raises(WebSocketDisconnect):
            with public_client.websocket_connect(
                f"wss://{PUBLIC_HOST}/api/stream", headers={"origin": f"https://{PUBLIC_HOST}"},
                subprotocols=[security.WS_SUBPROTOCOL],
            ) as ws:
                ws.receive_json()

    def test_foreign_host_still_rejected(self, public_client: TestClient) -> None:
        assert public_client.get("/api/mode", headers={"Host": "evil.example"}).status_code == 421

    def test_scan_pins_the_vetted_address(self, public_client: TestClient) -> None:
        from tests.test_tls_inspector import _result

        calls: List[Any] = []

        def fake_scan(host: str, **kwargs: Any) -> Any:
            calls.append((host, kwargs))
            return _result(host=host)

        with patch("socket.getaddrinfo", return_value=_addrinfo("140.82.121.4")), \
             patch("nst.tls_inspector.scanner.scan", side_effect=fake_scan):
            response = public_client.post("/api/tls/scan", json={"hosts": ["github.com"]},
                                          headers=_xff("203.0.113.10"))
        assert response.status_code == 200, response.text
        assert [host for host, _ in calls] == ["github.com"]
        assert calls[0][1]["connect_ip"] == "140.82.121.4"
        assert calls[0][1]["port"] == 443
        assert calls[0][1]["timeout"] == 8   # the console default of 10 is capped

    def test_scan_of_private_host_refused(self, public_client: TestClient) -> None:
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.7")), \
             patch("nst.tls_inspector.scanner.scan") as scan:
            response = public_client.post("/api/tls/scan", json={"hosts": ["intranet.example"]},
                                          headers=_xff("203.0.113.11"))
        assert response.status_code == 422
        scan.assert_not_called()

    @pytest.mark.parametrize("body, message", [
        ({"hosts": ["a.com", "b.com", "c.com", "d.com"]}, "At most 3"),
        ({"hosts": ["a.com:22"]}, "not allowed"),
    ])
    def test_scan_limits(self, public_client: TestClient, body: dict, message: str) -> None:
        with patch("nst.tls_inspector.scanner.scan") as scan:
            response = public_client.post("/api/tls/scan", json=body, headers=_xff("203.0.113.12"))
        assert response.status_code == 422
        assert message in response.json()["error"]["message"]
        scan.assert_not_called()

    def test_scan_rate_limited_per_client(self, public_client: TestClient) -> None:
        from tests.test_tls_inspector import _result

        with patch("socket.getaddrinfo", return_value=_addrinfo("140.82.121.4")), \
             patch("nst.tls_inspector.scanner.scan", return_value=_result()):
            for _ in range(PUBLIC_TLS_PER_MINUTE):
                ok = public_client.post("/api/tls/scan", json={"hosts": ["github.com"]},
                                        headers=_xff("203.0.113.20"))
                assert ok.status_code == 200
            limited = public_client.post("/api/tls/scan", json={"hosts": ["github.com"]},
                                         headers=_xff("203.0.113.20"))
            other = public_client.post("/api/tls/scan", json={"hosts": ["github.com"]},
                                       headers=_xff("203.0.113.21"))
        assert limited.status_code == 429
        assert limited.json()["error"]["code"] == "rate_limited"
        assert int(limited.headers["retry-after"]) >= 1
        assert other.status_code == 200

    def test_geoip_rate_limited(self, public_client: TestClient) -> None:
        targets = ["10.0.0.1"] * 20   # private targets: answered locally, no network
        first = public_client.post("/api/geoip", json={"targets": targets},
                                   headers=_xff("203.0.113.30"))
        second = public_client.post("/api/geoip", json={"targets": ["10.0.0.2"]},
                                    headers=_xff("203.0.113.30"))
        assert first.status_code == 200
        assert second.status_code == 429


# ──────────────────────────────────────────────────────────────────────────────
# Console mode
# ──────────────────────────────────────────────────────────────────────────────

class TestConsoleMode:
    @pytest.fixture()
    def console_client(self, tmp_path: Path) -> Iterator[TestClient]:
        app = create_app(AppConfig(), token=CONSOLE_TOKEN, port=8765, mode="console",
                         allowed_hosts=[CONSOLE_HOST], extra_origins=[f"https://{CONSOLE_HOST}"],
                         report_store=ReportStore(tmp_path), static_dir=tmp_path / "static")
        with TestClient(app, base_url=f"https://{CONSOLE_HOST}") as client:
            yield client

    def test_requires_the_fixed_token(self, console_client: TestClient) -> None:
        assert console_client.get("/api/health").status_code == 401
        ok = console_client.get("/api/health", headers={"Authorization": f"Bearer {CONSOLE_TOKEN}"})
        assert ok.status_code == 200
        assert ok.json()["mode"] == "console"

    def test_mode_endpoint_reports_token_auth(self, console_client: TestClient) -> None:
        body = console_client.get("/api/mode").json()
        assert (body["mode"], body["auth"]) == ("console", "token")
        assert "limits" not in body

    def test_websocket_from_proxied_origin(self, console_client: TestClient) -> None:
        with console_client.websocket_connect(
            f"wss://{CONSOLE_HOST}/api/stream", headers={"origin": f"https://{CONSOLE_HOST}"},
            subprotocols=[security.WS_SUBPROTOCOL, security.WS_TOKEN_PREFIX + CONSOLE_TOKEN],
        ) as ws:
            assert ws.receive_json()["type"] == "hello"

    def test_create_app_refuses_console_without_token(self) -> None:
        with pytest.raises(ValueError):
            create_app(AppConfig(), token=None, port=8765, mode="console")


# ──────────────────────────────────────────────────────────────────────────────
# Server settings and CLI
# ──────────────────────────────────────────────────────────────────────────────

class TestSettings:
    def test_local_gets_a_fresh_token(self) -> None:
        token, origins = resolve_settings("local", [], None)
        assert token and len(token) >= 40
        assert origins == []

    def test_public_needs_hosts_but_no_token(self) -> None:
        with pytest.raises(ConfigurationError, match="allowed-host"):
            resolve_settings("public", [], None)
        assert resolve_settings("public", [PUBLIC_HOST], None) == (None, [])

    def test_console_needs_a_long_token(self) -> None:
        with pytest.raises(ConfigurationError, match="NST_WEB_TOKEN"):
            resolve_settings("console", [CONSOLE_HOST], "short")
        token, origins = resolve_settings("console", [CONSOLE_HOST.upper()], CONSOLE_TOKEN)
        assert token == CONSOLE_TOKEN
        assert origins == [f"https://{CONSOLE_HOST}"]

    def test_host_allowlist_normalisation(self) -> None:
        mw = security.HostAllowlistMiddleware(app=lambda *a: None, allowed_hosts=["Demo.Example.com."])
        assert mw.host_allowed("demo.example.com:443")
        assert mw.host_allowed("127.0.0.1:8766")
        assert not mw.host_allowed("evil.example")

    def test_cli_rejects_public_mode_without_hosts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from nst.cli.main import cli

        monkeypatch.delenv("NST_ALLOWED_HOSTS", raising=False)
        result = CliRunner().invoke(cli, ["web", "--mode", "public", "--port", "18766"])
        assert result.exit_code == 1
        assert "allowed-host" in result.output

    def test_cli_reads_mode_and_hosts_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from nst.cli.main import cli

        monkeypatch.setenv("NST_WEB_MODE", "console")
        monkeypatch.setenv("NST_ALLOWED_HOSTS", f"{CONSOLE_HOST} other.example.com")
        monkeypatch.setenv("NST_WEB_TOKEN", CONSOLE_TOKEN)
        with patch("nst.web.server.serve") as serve:
            result = CliRunner().invoke(cli, ["web"])
        assert result.exit_code == 0, result.output
        kwargs = serve.call_args.kwargs
        assert kwargs["mode"] == "console"
        assert kwargs["allowed_hosts"] == [CONSOLE_HOST, "other.example.com"]
        assert kwargs["console_token"] == CONSOLE_TOKEN


# ──────────────────────────────────────────────────────────────────────────────
# Reverse-proxy client address (Caddy on loopback, Traefik on a Docker network)
# ──────────────────────────────────────────────────────────────────────────────

class TestClientIp:
    @staticmethod
    def _request(peer: str, xff: str | None) -> Any:
        from starlette.requests import Request

        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return Request({"type": "http", "headers": headers, "client": (peer, 1234)})

    def test_loopback_proxy_is_trusted_by_default(self) -> None:
        from nst.web.app import client_ip

        assert client_ip(self._request("127.0.0.1", "203.0.113.9")) == "203.0.113.9"

    def test_forged_left_entries_are_ignored(self) -> None:
        from nst.web.app import client_ip, parse_networks

        trusted = parse_networks(["10.0.1.0/24"])
        request = self._request("10.0.1.13", "1.2.3.4, 203.0.113.9")   # client forged 1.2.3.4
        assert client_ip(request, trusted) == "203.0.113.9"

    def test_untrusted_peer_header_is_ignored(self) -> None:
        from nst.web.app import client_ip

        assert client_ip(self._request("198.51.100.5", "1.2.3.4")) == "198.51.100.5"

    def test_docker_network_proxy(self) -> None:
        from nst.web.app import client_ip, parse_networks

        trusted = parse_networks(["10.0.1.0/24"])
        assert client_ip(self._request("10.0.1.13", "198.51.100.77"), trusted) == "198.51.100.77"
        # Loopback is not trusted once a specific network is configured.
        assert client_ip(self._request("127.0.0.1", "198.51.100.77"), trusted) == "127.0.0.1"

    def test_bad_network_rejected(self) -> None:
        from nst.web.app import parse_networks

        with pytest.raises(ValueError):
            parse_networks(["not-a-cidr"])


class TestBindRules:
    def test_public_mode_may_listen_on_all_addresses(self) -> None:
        from nst.web.server import check_bind

        check_bind("0.0.0.0", 0, "public")   # port 0: any free port

    @pytest.mark.parametrize("mode", ["local", "console"])
    def test_capture_modes_stay_on_loopback(self, mode: str) -> None:
        from nst.web.server import check_bind

        with pytest.raises(ConfigurationError, match="loopback"):
            check_bind("0.0.0.0", 0, mode)
