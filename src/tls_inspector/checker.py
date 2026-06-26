"""
Certificate validation rules.

CertChecker.check() is a pure function from the caller's perspective:
it reads a TLSScanResult and appends CertIssue objects to result.issues.
Each rule is a separate private method so it can be tested in isolation.
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.tls_inspector.result import CertIssue, IssueType, TLSScanResult

_WEAK_CIPHERS = frozenset({"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "RC2"})
_WEAK_TLS    = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
_EXPIRY_WARN = 30    # days
_MIN_KEY     = 2048  # bits


class CertChecker:
    """
    Runs all validation rules against a TLSScanResult and populates
    result.issues in-place.

    Usage
    ─────
        checker = CertChecker()
        checker.check(result)
        # result.issues now contains any detected problems
    """

    def check(self, result: TLSScanResult) -> None:
        """Run every rule.  result.issues is extended, never replaced."""
        self._check_expiry(result)
        self._check_self_signed(result)
        self._check_tls_version(result)
        self._check_cipher(result)
        self._check_key_size(result)
        self._check_hostname(result)

    # ── Rules ────────────────────────────────────────────────────────────

    def _check_expiry(self, result: TLSScanResult) -> None:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if result.not_after < now:
            days_ago = (now - result.not_after).days
            result.issues.append(CertIssue(
                issue_type=IssueType.EXPIRED,
                severity="critical",
                detail=(
                    f"Certificate expired {days_ago} day(s) ago "
                    f"({result.not_after.date()})"
                ),
            ))
        elif result.days_until_expiry <= _EXPIRY_WARN:
            result.issues.append(CertIssue(
                issue_type=IssueType.EXPIRING_SOON,
                severity="high",
                detail=(
                    f"Certificate expires in {result.days_until_expiry} day(s) "
                    f"({result.not_after.date()})"
                ),
            ))

    def _check_self_signed(self, result: TLSScanResult) -> None:
        if result.subject and result.issuer and result.subject == result.issuer:
            result.issues.append(CertIssue(
                issue_type=IssueType.SELF_SIGNED,
                severity="high",
                detail="Certificate is self-signed (issuer equals subject)",
            ))

    def _check_tls_version(self, result: TLSScanResult) -> None:
        if result.tls_version in _WEAK_TLS:
            result.issues.append(CertIssue(
                issue_type=IssueType.WEAK_TLS_VERSION,
                severity="high",
                detail=(
                    f"Weak TLS version: {result.tls_version} "
                    f"(TLS 1.2 or higher required)"
                ),
            ))

    def _check_cipher(self, result: TLSScanResult) -> None:
        suite_upper = result.cipher_suite.upper()
        for token in _WEAK_CIPHERS:
            if token in suite_upper:
                result.issues.append(CertIssue(
                    issue_type=IssueType.WEAK_CIPHER,
                    severity="high",
                    detail=(
                        f"Weak cipher suite: {result.cipher_suite} "
                        f"(contains {token})"
                    ),
                ))
                return

    def _check_key_size(self, result: TLSScanResult) -> None:
        if 0 < result.key_bits < _MIN_KEY:
            result.issues.append(CertIssue(
                issue_type=IssueType.WEAK_KEY_SIZE,
                severity="medium",
                detail=(
                    f"Effective key size {result.key_bits} bits is below "
                    f"the minimum ({_MIN_KEY} bits)"
                ),
            ))

    def _check_hostname(self, result: TLSScanResult) -> None:
        if not result.san:
            return
        host = result.host.lower()
        for name in result.san:
            name = name.lower()
            if name == host:
                return
            if name.startswith("*."):
                suffix = name[2:]
                parts = host.split(".", 1)
                if len(parts) == 2 and parts[1] == suffix:
                    return
        san_preview = ", ".join(result.san[:5])
        if len(result.san) > 5:
            san_preview += "…"
        result.issues.append(CertIssue(
            issue_type=IssueType.HOSTNAME_MISMATCH,
            severity="critical",
            detail=(
                f"Hostname '{result.host}' not found in certificate "
                f"SANs: {san_preview}"
            ),
        ))
