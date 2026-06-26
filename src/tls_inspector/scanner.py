"""
TLS connection and certificate retrieval.

scan() is the single public entry point: it opens an SSL socket,
reads the peer certificate and cipher info, then runs CertChecker.

Design decisions
────────────────
* ctx.check_hostname = False and ctx.verify_mode = CERT_NONE are
  intentional — we want the raw cert data even when the cert is
  invalid, so we can report the problems ourselves rather than raising
  before we have any information to display.
* Never raises — all connection and parsing errors are captured in
  TLSScanResult.error so the CLI can render a clean failure panel.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Tuple

from src.core.logger import get_logger
from src.tls_inspector.checker import CertChecker
from src.tls_inspector.result import TLSScanResult

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 10
_checker = CertChecker()


def parse_host_port(host_str: str, default_port: int = 443) -> Tuple[str, int]:
    """
    Split "host:port" into (host, port).  Returns (host_str, default_port)
    when no port suffix is present or when the suffix is not an integer.
    """
    if ":" in host_str:
        head, _, tail = host_str.rpartition(":")
        try:
            return head, int(tail)
        except ValueError:
            pass
    return host_str, default_port


def scan(
    host: str,
    port: int = 443,
    timeout: int = _DEFAULT_TIMEOUT,
) -> TLSScanResult:
    """
    Connect to host:port via TLS, retrieve the peer certificate and
    negotiated cipher, run all checks, and return a TLSScanResult.

    Never raises — errors are stored in result.error.
    """
    logger.debug("TLS scan: %s:%d (timeout=%ds)", host, port, timeout)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher_name, tls_version, key_bits = tls.cipher()
    except (socket.timeout, TimeoutError):
        return _error_result(host, port, f"Connection timed out after {timeout}s")
    except ConnectionRefusedError:
        return _error_result(host, port, f"Connection refused on port {port}")
    except OSError as exc:
        return _error_result(host, port, str(exc))
    except Exception as exc:
        logger.debug("TLS scan error %s:%d — %s", host, port, exc)
        return _error_result(host, port, str(exc))

    try:
        subject  = _parse_name(cert.get("subject", ()))
        issuer   = _parse_name(cert.get("issuer", ()))
        not_before = _parse_dt(cert["notBefore"])
        not_after  = _parse_dt(cert["notAfter"])
        san = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    except Exception as exc:
        return _error_result(host, port, f"Failed to parse certificate: {exc}")

    result = TLSScanResult(
        host=host,
        port=port,
        tls_version=tls_version or "",
        cipher_suite=cipher_name or "",
        key_bits=key_bits or 0,
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        san=san,
    )
    _checker.check(result)
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_name(rdns: tuple) -> str:
    """Flatten an SSL cert RDN sequence into 'key=value, …' form."""
    parts = []
    for rdn in rdns:
        for attr, value in rdn:
            parts.append(f"{attr}={value}")
    return ", ".join(parts)


def _parse_dt(ssl_time: str) -> datetime:
    """Parse an SSL notBefore/notAfter string into a datetime."""
    # Normalise double spaces produced by single-digit days ("Jan  1 …")
    normalised = " ".join(ssl_time.split())
    return datetime.strptime(normalised, "%b %d %H:%M:%S %Y %Z")


def _error_result(host: str, port: int, error: str) -> TLSScanResult:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return TLSScanResult(
        host=host,
        port=port,
        tls_version="",
        cipher_suite="",
        key_bits=0,
        subject="",
        issuer="",
        not_before=now,
        not_after=now,
        san=[],
        error=error,
    )
