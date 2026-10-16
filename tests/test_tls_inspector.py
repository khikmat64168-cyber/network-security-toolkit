"""
Unit tests for the SSL/TLS Certificate Inspector (Phase 8).

All tests run without network access:
  - CertChecker tests use hand-crafted TLSScanResult objects.
  - scanner tests mock ssl / socket so no real connections are made;
    certificate parsing runs against certificates generated in-process.
  - CLI tests use Click's CliRunner with a monkeypatched scan().
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from nst.cli.main import cli
from nst.tls_inspector.checker import CertChecker
from nst.tls_inspector.result import CertIssue, IssueType, TLSScanResult
from nst.tls_inspector.scanner import build_result, parse_host_port


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _result(
    host: str = "example.com",
    port: int = 443,
    tls_version: str = "TLSv1.3",
    cipher_suite: str = "TLS_AES_256_GCM_SHA384",
    key_bits: int = 256,
    subject: str = "CN=example.com",
    issuer: str = "CN=DigiCert",
    days_valid: int = 365,
    days_until_expiry: int = 180,
    san: list | None = None,
    error: str | None = None,
    public_key_type: str = "",
    public_key_bits: int = 0,
) -> TLSScanResult:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return TLSScanResult(
        host=host,
        port=port,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        key_bits=key_bits,
        subject=subject,
        issuer=issuer,
        not_before=now - timedelta(days=days_valid - days_until_expiry),
        not_after=now + timedelta(days=days_until_expiry),
        san=san if san is not None else [host],
        error=error,
        public_key_type=public_key_type,
        public_key_bits=public_key_bits,
    )


def _der_cert(
    common_name: str = "example.com",
    issuer_cn: str | None = None,
    san: list[str] | None = None,
    key: object | None = None,
    days_valid: int = 90,
) -> bytes:
    """Generate a DER certificate in-process (self-signed key, any issuer name)."""
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)
        ]))
        .public_key(key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = builder.sign(key, algorithm)  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.DER)


# ──────────────────────────────────────────────────────────────────────────────
# CertIssue
# ──────────────────────────────────────────────────────────────────────────────

class TestCertIssue:
    def test_severity_level_maps_correctly(self) -> None:
        def _issue(s: str) -> CertIssue:
            return CertIssue(IssueType.EXPIRED, s, "detail")

        assert _issue("medium").severity_level() == 1
        assert _issue("high").severity_level() == 2
        assert _issue("critical").severity_level() == 3

    def test_unknown_severity_returns_zero(self) -> None:
        issue = CertIssue(IssueType.EXPIRED, "bogus", "detail")
        assert issue.severity_level() == 0


# ──────────────────────────────────────────────────────────────────────────────
# TLSScanResult
# ──────────────────────────────────────────────────────────────────────────────

class TestTLSScanResult:
    def test_is_ok_when_no_issues(self) -> None:
        assert _result().is_ok is True

    def test_is_ok_false_when_has_issues(self) -> None:
        r = _result()
        r.issues.append(CertIssue(IssueType.SELF_SIGNED, "high", "x"))
        assert r.is_ok is False

    def test_is_ok_false_when_error(self) -> None:
        assert _result(error="timeout").is_ok is False

    def test_days_until_expiry_approximate(self) -> None:
        r = _result(days_until_expiry=45)
        assert 43 <= r.days_until_expiry <= 46

    def test_critical_count(self) -> None:
        r = _result()
        r.issues.append(CertIssue(IssueType.EXPIRED, "critical", "x"))
        r.issues.append(CertIssue(IssueType.SELF_SIGNED, "high", "x"))
        assert r.critical_count == 1
        assert r.high_count == 1


# ──────────────────────────────────────────────────────────────────────────────
# CertChecker
# ──────────────────────────────────────────────────────────────────────────────

class TestCertChecker:
    checker = CertChecker()

    def test_expired_cert_raises_critical(self) -> None:
        r = _result(days_until_expiry=-10)
        self.checker._check_expiry(r)
        assert any(i.issue_type == IssueType.EXPIRED for i in r.issues)
        assert r.issues[0].severity == "critical"

    def test_valid_cert_no_expiry_issue(self) -> None:
        r = _result(days_until_expiry=200)
        self.checker._check_expiry(r)
        assert r.issues == []

    def test_expiring_soon_raises_high(self) -> None:
        r = _result(days_until_expiry=15)
        self.checker._check_expiry(r)
        assert any(i.issue_type == IssueType.EXPIRING_SOON for i in r.issues)
        assert r.issues[0].severity == "high"

    def test_self_signed_raises_high(self) -> None:
        r = _result(subject="CN=self", issuer="CN=self")
        self.checker._check_self_signed(r)
        assert any(i.issue_type == IssueType.SELF_SIGNED for i in r.issues)

    def test_different_issuer_no_self_signed(self) -> None:
        r = _result(subject="CN=example.com", issuer="CN=DigiCert")
        self.checker._check_self_signed(r)
        assert r.issues == []

    def test_weak_tls_raises_high(self) -> None:
        for version in ("TLSv1", "TLSv1.1", "SSLv3"):
            r = _result(tls_version=version)
            self.checker._check_tls_version(r)
            assert any(i.issue_type == IssueType.WEAK_TLS_VERSION for i in r.issues)

    def test_strong_tls_no_issue(self) -> None:
        for version in ("TLSv1.2", "TLSv1.3"):
            r = _result(tls_version=version)
            self.checker._check_tls_version(r)
            assert r.issues == []

    def test_weak_cipher_raises_high(self) -> None:
        r = _result(cipher_suite="RC4-SHA")
        self.checker._check_cipher(r)
        assert any(i.issue_type == IssueType.WEAK_CIPHER for i in r.issues)

    def test_strong_cipher_no_issue(self) -> None:
        r = _result(cipher_suite="TLS_AES_256_GCM_SHA384")
        self.checker._check_cipher(r)
        assert r.issues == []

    def test_128_bit_cipher_is_not_weak(self) -> None:
        r = _result(cipher_suite="TLS_AES_128_GCM_SHA256", key_bits=128)
        self.checker._check_cipher(r)
        assert r.issues == []

    def test_low_cipher_strength_raises_high(self) -> None:
        r = _result(cipher_suite="SOME-LEGACY-SUITE", key_bits=56)
        self.checker._check_cipher(r)
        assert [i.issue_type for i in r.issues] == [IssueType.WEAK_CIPHER]
        assert r.issues[0].severity == "high"

    def test_weak_token_and_low_bits_reported_once(self) -> None:
        r = _result(cipher_suite="DES-CBC-SHA", key_bits=56)
        self.checker._check_cipher(r)
        assert len(r.issues) == 1

    def test_small_rsa_key_raises_medium(self) -> None:
        r = _result(public_key_type="RSA", public_key_bits=1024)
        self.checker._check_key_size(r)
        assert any(i.issue_type == IssueType.WEAK_KEY_SIZE for i in r.issues)
        assert r.issues[0].severity == "medium"

    def test_sufficient_rsa_key_no_issue(self) -> None:
        r = _result(public_key_type="RSA", public_key_bits=2048)
        self.checker._check_key_size(r)
        assert r.issues == []

    def test_ec_p256_key_no_issue(self) -> None:
        r = _result(public_key_type="EC", public_key_bits=256)
        self.checker._check_key_size(r)
        assert r.issues == []

    def test_small_ec_key_raises_medium(self) -> None:
        r = _result(public_key_type="EC", public_key_bits=192)
        self.checker._check_key_size(r)
        assert any(i.issue_type == IssueType.WEAK_KEY_SIZE for i in r.issues)

    def test_unknown_key_type_skips_check(self) -> None:
        r = _result(public_key_type="", public_key_bits=0)
        self.checker._check_key_size(r)
        assert r.issues == []

    def test_hostname_mismatch_raises_critical(self) -> None:
        r = _result(host="evil.com", san=["example.com"])
        self.checker._check_hostname(r)
        assert any(i.issue_type == IssueType.HOSTNAME_MISMATCH for i in r.issues)
        assert r.issues[0].severity == "critical"

    def test_hostname_exact_match_no_issue(self) -> None:
        r = _result(host="example.com", san=["example.com"])
        self.checker._check_hostname(r)
        assert r.issues == []

    def test_wildcard_match_no_issue(self) -> None:
        r = _result(host="sub.example.com", san=["*.example.com"])
        self.checker._check_hostname(r)
        assert r.issues == []

    def test_wildcard_does_not_match_apex(self) -> None:
        r = _result(host="example.com", san=["*.example.com"])
        self.checker._check_hostname(r)
        assert any(i.issue_type == IssueType.HOSTNAME_MISMATCH for i in r.issues)

    def test_no_san_skips_hostname_check(self) -> None:
        r = _result(host="example.com", san=[])
        self.checker._check_hostname(r)
        assert r.issues == []


# ──────────────────────────────────────────────────────────────────────────────
# Scanner helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestScannerHelpers:
    def test_parse_host_port_with_port(self) -> None:
        assert parse_host_port("example.com:8443") == ("example.com", 8443)

    def test_parse_host_port_without_port(self) -> None:
        assert parse_host_port("example.com", default_port=443) == ("example.com", 443)

    def test_parse_host_port_invalid_port_uses_default(self) -> None:
        assert parse_host_port("example.com:abc", default_port=443) == ("example.com:abc", 443)

    def test_build_result_extracts_certificate_fields(self) -> None:
        der = _der_cert("example.com", issuer_cn="Test CA",
                        san=["example.com", "www.example.com"], days_valid=90)
        r = build_result("example.com", 443, der, "TLSv1.3",
                         "TLS_AES_256_GCM_SHA384", 256)
        assert r.subject == "CN=example.com"
        assert r.issuer == "CN=Test CA"
        assert r.san == ["example.com", "www.example.com"]
        assert r.tls_version == "TLSv1.3"
        assert r.key_bits == 256
        assert r.not_before.tzinfo is None
        assert 88 <= r.days_until_expiry <= 90

    def test_build_result_reports_ec_key(self) -> None:
        r = build_result("example.com", 443, _der_cert(), "TLSv1.3", "X", 256)
        assert (r.public_key_type, r.public_key_bits) == ("EC", 256)

    def test_build_result_reports_rsa_key(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        r = build_result("example.com", 443, _der_cert(key=key), "TLSv1.3", "X", 256)
        assert (r.public_key_type, r.public_key_bits) == ("RSA", 2048)

    def test_build_result_reports_ed25519_key(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        r = build_result("example.com", 443, _der_cert(key=key), "TLSv1.3", "X", 256)
        assert r.public_key_type == "Ed25519"

    def test_build_result_without_san_extension(self) -> None:
        r = build_result("example.com", 443, _der_cert(san=None), "TLSv1.3", "X", 256)
        assert r.san == []

    def test_build_result_rejects_garbage(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            build_result("example.com", 443, b"not a certificate", "TLSv1.3", "X", 256)

    def test_self_signed_cert_end_to_end(self) -> None:
        r = build_result("example.com", 443, _der_cert(san=["example.com"]),
                         "TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)
        CertChecker().check(r)
        assert [i.issue_type for i in r.issues] == [IssueType.SELF_SIGNED]

    def test_scan_parses_certificate_from_socket(self) -> None:
        from nst.tls_inspector.scanner import scan

        der = _der_cert("example.com", issuer_cn="Test CA", san=["example.com"])
        tls = MagicMock()
        tls.getpeercert.return_value = der
        tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        tls.__enter__.return_value = tls
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        raw = MagicMock()
        raw.__enter__.return_value = raw

        with patch("socket.create_connection", return_value=raw), \
             patch("ssl.create_default_context", return_value=ctx):
            result = scan("example.com", port=443, timeout=1)

        tls.getpeercert.assert_called_once_with(binary_form=True)
        assert result.error is None
        assert result.is_ok
        assert result.public_key_type == "EC"

    def test_scan_returns_error_when_no_certificate(self) -> None:
        from nst.tls_inspector.scanner import scan

        tls = MagicMock()
        tls.getpeercert.return_value = None
        tls.cipher.return_value = None
        tls.__enter__.return_value = tls
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        raw = MagicMock()
        raw.__enter__.return_value = raw

        with patch("socket.create_connection", return_value=raw), \
             patch("ssl.create_default_context", return_value=ctx):
            result = scan("example.com", port=443, timeout=1)

        assert result.error is not None
        assert "certificate" in result.error.lower()

    def test_scan_returns_error_on_timeout(self) -> None:
        from nst.tls_inspector.scanner import scan
        import socket

        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = scan("10.255.255.1", port=443, timeout=1)
        assert result.error is not None
        assert "timed" in result.error.lower()

    def test_scan_returns_error_on_refused(self) -> None:
        from nst.tls_inspector.scanner import scan

        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = scan("127.0.0.1", port=1, timeout=1)
        assert result.error is not None
        assert "refused" in result.error.lower()


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestTLSScanCLI:
    def test_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["tls-scan", "--help"])
        assert result.exit_code == 0
        assert "tls" in result.output.lower()

    def test_no_hosts_exits_one(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["tls-scan"])
        assert result.exit_code == 1

    def test_appears_in_top_level_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert "tls-scan" in result.output

    def test_ok_result_exits_zero(self) -> None:
        import nst.tls_inspector.scanner as _scanner_mod

        ok_result = _result(host="github.com", days_until_expiry=200)
        runner = CliRunner()
        with patch.object(_scanner_mod, "scan", return_value=ok_result):
            result = runner.invoke(cli, ["tls-scan", "github.com"])
        assert result.exit_code == 0
        assert "github.com" in result.output

    def test_critical_result_exits_one(self) -> None:
        import nst.tls_inspector.scanner as _scanner_mod

        bad_result = _result(host="expired.com", days_until_expiry=-5)
        CertChecker().check(bad_result)
        runner = CliRunner()
        with patch.object(_scanner_mod, "scan", return_value=bad_result):
            result = runner.invoke(cli, ["tls-scan", "expired.com"])
        assert result.exit_code == 1
