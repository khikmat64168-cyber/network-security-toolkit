"""
Plaintext credential detector.

Scans packet payloads for credentials transmitted without encryption.
Supports HTTP Basic Auth, HTTP POST form fields, and FTP USER/PASS.

Design decisions
────────────────
* FTP spreads USER and PASS across two separate packets.  _ftp_users
  keeps the username keyed by src_ip so we can pair it with the PASS
  packet that follows.  Entries are evicted after _FTP_USER_TTL packets
  to prevent unbounded growth on long captures.
* Passwords are stored in CredentialFinding as captured — this is a
  security tool and the whole point is to show what an attacker can see.
* regex patterns are compiled once at class level, not per call.
* HTTP POST scanning uses a non-greedy match to avoid false positives
  from long bodies with many parameters.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.core.logger import get_logger
from src.sniffer.parsers.base import ParsedPacket, Protocol

logger = get_logger(__name__)

_FTP_USER_TTL = 500   # evict stale FTP usernames after this many packets

# ──────────────────────────────────────────────────────────────────────────────
# Pre-compiled patterns
# ──────────────────────────────────────────────────────────────────────────────

_RE_HTTP_BASIC = re.compile(
    rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE
)
_RE_HTTP_POST_CREDS = re.compile(
    rb"(?:username|user|login|email)=([^&\r\n]{1,64})"
    rb".{0,256}?"
    rb"(?:password|passwd|pass|pwd)=([^&\r\n]{1,64})",
    re.IGNORECASE | re.DOTALL,
)
_RE_FTP_USER = re.compile(rb"^USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_RE_FTP_PASS = re.compile(rb"^PASS\s+(\S+)", re.IGNORECASE | re.MULTILINE)

_FTP_PORTS = frozenset({20, 21})


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CredentialFinding:
    """A credential pair detected in plaintext network traffic."""

    src_ip: str
    dst_ip: str
    protocol: str         # "HTTP", "FTP", etc.
    kind: str             # "HTTP Basic Auth", "FTP Password", "HTTP POST"
    username: str
    password: str
    context: str          # brief snippet of the raw line that triggered detection


# ──────────────────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────────────────

class CredentialDetector:
    """
    Scans ParsedPacket payloads for cleartext credentials.

    Call scan() for every packet; it returns a (possibly empty) list of
    CredentialFinding instances.
    """

    def __init__(self) -> None:
        # src_ip → (username, packets_since_seen)
        self._ftp_users: Dict[str, tuple[str, int]] = {}
        self._packet_counter: int = 0

    def scan(self, packet: ParsedPacket) -> List[CredentialFinding]:
        """Return all credentials found in *packet*'s payload."""
        self._packet_counter += 1
        self._evict_stale_ftp_users()

        if not packet.payload:
            return []

        findings: List[CredentialFinding] = []

        findings.extend(self._check_http_basic_auth(packet))
        findings.extend(self._check_http_post(packet))
        findings.extend(self._check_ftp(packet))

        if findings:
            logger.warning(
                "CREDENTIAL DETECTED — %d finding(s) from %s",
                len(findings),
                packet.src_ip,
            )

        return findings

    # ── Private helpers ────────────────────────────────────────────────────────

    def _check_http_basic_auth(self, packet: ParsedPacket) -> List[CredentialFinding]:
        match = _RE_HTTP_BASIC.search(packet.payload)
        if not match:
            return []

        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
        except Exception:
            return []

        if ":" not in decoded:
            return []

        username, _, password = decoded.partition(":")
        context = f"Authorization: Basic {match.group(1).decode()[:16]}..."

        return [
            CredentialFinding(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol="HTTP",
                kind="HTTP Basic Auth",
                username=username.strip(),
                password=password.strip(),
                context=context,
            )
        ]

    def _check_http_post(self, packet: ParsedPacket) -> List[CredentialFinding]:
        if b"POST " not in packet.payload[:10]:
            return []

        match = _RE_HTTP_POST_CREDS.search(packet.payload)
        if not match:
            return []

        username = match.group(1).decode("utf-8", errors="replace")
        password = match.group(2).decode("utf-8", errors="replace")

        return [
            CredentialFinding(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol="HTTP",
                kind="HTTP POST Credentials",
                username=username,
                password=password,
                context="HTTP POST body",
            )
        ]

    def _check_ftp(self, packet: ParsedPacket) -> List[CredentialFinding]:
        findings: List[CredentialFinding] = []
        payload = packet.payload

        src = packet.src_ip

        # Capture USER command
        user_match = _RE_FTP_USER.search(payload)
        if user_match:
            username = user_match.group(1).decode("utf-8", errors="replace")
            self._ftp_users[src] = (username, self._packet_counter)

        # Capture PASS command and pair with stored USER
        pass_match = _RE_FTP_PASS.search(payload)
        if pass_match:
            password = pass_match.group(1).decode("utf-8", errors="replace")
            stored = self._ftp_users.pop(src, None)
            username = stored[0] if stored else "(unknown)"

            findings.append(
                CredentialFinding(
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    protocol="FTP",
                    kind="FTP Password",
                    username=username,
                    password=password,
                    context=f"PASS {password[:8]}...",
                )
            )

        return findings

    def _evict_stale_ftp_users(self) -> None:
        """Remove FTP username entries that are older than _FTP_USER_TTL packets."""
        stale = [
            ip
            for ip, (_, seen_at) in self._ftp_users.items()
            if self._packet_counter - seen_at > _FTP_USER_TTL
        ]
        for ip in stale:
            del self._ftp_users[ip]
