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
* With CERT_NONE, ssl.getpeercert() returns an empty dict, so the
  certificate is fetched in DER form and parsed with `cryptography`.
  That also exposes the public key type and size, which the stdlib
  ssl module does not report at all.
* Never raises — all connection and parsing errors are captured in
  TLSScanResult.error so the CLI can render a clean failure panel.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from nst.core.logger import get_logger
from nst.tls_inspector.checker import CertChecker
from nst.tls_inspector.result import TLSScanResult

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
    connect_ip: Optional[str] = None,
) -> TLSScanResult:
    """
    Connect to host:port via TLS, retrieve the peer certificate and
    negotiated cipher, run all checks, and return a TLSScanResult.

    *connect_ip* pins the TCP connection to an address the caller already
    resolved and vetted, while *host* is still sent as SNI and checked
    against the certificate.  Without it the host is resolved here.

    Never raises — errors are stored in result.error.
    """
    logger.debug("TLS scan: %s:%d (timeout=%ds)", host, port, timeout)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((connect_ip or host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher_info = tls.cipher()
    except (socket.timeout, TimeoutError):
        return _error_result(host, port, f"Connection timed out after {timeout}s")
    except ConnectionRefusedError:
        return _error_result(host, port, f"Connection refused on port {port}")
    except OSError as exc:
        return _error_result(host, port, str(exc))
    except Exception as exc:
        logger.debug("TLS scan error %s:%d — %s", host, port, exc)
        return _error_result(host, port, str(exc))

    if not der:
        return _error_result(host, port, "Server did not present a certificate")

    cipher_name, tls_version, key_bits = cipher_info or ("", "", 0)

    try:
        result = build_result(
            host=host,
            port=port,
            der=der,
            tls_version=tls_version or "",
            cipher_suite=cipher_name or "",
            key_bits=key_bits or 0,
        )
    except Exception as exc:
        return _error_result(host, port, f"Failed to parse certificate: {exc}")

    _checker.check(result)
    return result


def build_result(
    host: str,
    port: int,
    der: bytes,
    tls_version: str,
    cipher_suite: str,
    key_bits: int,
) -> TLSScanResult:
    """
    Build an (unchecked) TLSScanResult from a DER-encoded certificate
    and the negotiated session parameters.

    Raises ValueError if *der* is not a valid X.509 certificate.
    """
    cert = x509.load_der_x509_certificate(der)
    key_type, public_key_bits = _public_key_info(cert)
    return TLSScanResult(
        host=host,
        port=port,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        key_bits=key_bits,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=_naive_utc(cert.not_valid_before_utc),
        not_after=_naive_utc(cert.not_valid_after_utc),
        san=_dns_sans(cert),
        public_key_type=key_type,
        public_key_bits=public_key_bits,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _public_key_info(cert: x509.Certificate) -> Tuple[str, int]:
    """Return (algorithm, size in bits) for the certificate's public key."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, 0


def _dns_sans(cert: x509.Certificate) -> list[str]:
    """DNS names from the subjectAltName extension (empty if absent)."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def _naive_utc(dt: datetime) -> datetime:
    """Convert an aware datetime to naive UTC (the convention used by TLSScanResult)."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


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
