# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] — Initial Release

### Packet Sniffer & Analyzer (`nst sniff`)
- Live packet capture on any network interface via Scapy
- Protocol parsers for TCP, UDP, HTTP, and DNS with a priority-based dispatcher
- Traffic statistics: protocol breakdown, top talkers, top destination ports
- Plaintext credential detection (HTTP Basic Auth, HTTP POST forms, FTP USER/PASS)
- Threat detection: port scanning, DNS tunneling, suspicious port usage
- Rich-formatted real-time CLI output and session summaries
- BPF filter support and PCAP file export

### Live Dashboard (`nst dashboard`)
- Full-screen Rich Live view of protocol share, top source / destination
  IPs, packet rate, recent packets and alert count

### ARP Spoofing Detector (`nst arp-watch`)
- ARP binding table seeded from the OS ARP cache at startup
- MAC/IP change detection with gateway-aware severity escalation
- Gratuitous ARP detection
- Combined-signal MITM suspicion detection
- Trusted IP allowlist
- Structured event logging and Rich-formatted alert panels
- Session summary of all observed ARP bindings

### DNS Spoofing Detector (`nst dns-watch`)
- IP change, unsolicited response, zero-TTL and multiple-IP detection
- Trusted domain allowlist; query tracking can be disabled

### MAC Flooding Detector (`nst mac-watch`)
- Sliding-window detection of new-MAC bursts (CAM table overflow)
- Table-limit overflow alert

### TLS Certificate Inspector (`nst tls-scan`)
- Expiry, self-signed, hostname/SAN mismatch, weak TLS version and weak
  cipher checks
- Public key type and size checks (RSA/DSA ≥ 2048 bits, EC ≥ 224 bits),
  using `cryptography` to parse the DER certificate

### Web Console (`nst web`)
- FastAPI backend (optional `[web]` extra) bound to loopback only, with a
  per-launch bearer token, loopback Host-header checks, WebSocket origin
  checks and a strict Content-Security-Policy
- Sensors wrap the existing pipelines (traffic analyzer, ARP / DNS / MAC
  detectors) unchanged and stream their findings as normalized
  `security.event`-style records; plaintext credentials are redacted
- Live findings board, traffic statistics and chart, detector tables, TLS
  scanning, GeoIP and sandboxed HTML report viewing in a React + TypeScript
  console (separate Networkscan-front repository, bundled into the package
  by CI via `scripts/fetch_frontend.sh`)
- Capture permission is probed with a real capture socket; blocked and
  unavailable features are shown explicitly

### Reporting & GeoIP (`nst report`, `nst geoip`)
- Self-contained HTML security report with TLS findings and interfaces
- Optional country / ISP enrichment via ip-api.com; private addresses
  are never sent

### Core Infrastructure
- Importable package `nst` in a `src/` layout; bundled `default.yaml` and
  `logging.yaml` ship as package data, so installed wheels are
  self-contained
- Config discovery: `--config` → `$NST_CONFIG` → `~/.config/nst/config.yaml`
  → bundled defaults, plus `NST_INTERFACE` / `NST_LOG_LEVEL` overrides
- Rotating file logging under `~/.local/state/nst/` with per-module level
  overrides; falls back to console-only logging when the file is not
  writable, and avoids leaving root-owned directories in the user's HOME
  after `sudo` runs
- Typed exception hierarchy for predictable error handling
- Click-based CLI with eleven subcommands
- Captures run through a stoppable sniff loop, so monitors stop immediately
  even on a quiet interface

### Fixes found while building the web console
- macOS ARP cache seeding never worked (`arp -a` reverse DNS exceeded the
  timeout and short MAC octets did not match); now `arp -an` with
  normalized MACs
- GeoIP no longer caches failed lookups

### Production Hardening
- Top-level exception guard (`nst.cli.main:main`) used by both
  `python main.py` and the installed `nst` console script — no raw
  Python tracebacks reach the user (they go to the log file; the console
  shows them only with `--debug`)
- Malformed configuration files produce a clear error panel; a missing
  `--config` file is rejected up front
- mypy (strict) and flake8 clean
- MIT license and this changelog added for public release

### Testing
- 555 Python unit and integration tests (89% line coverage), covering
  configuration, logging, packet parsing, traffic analysis, every
  detector, TLS certificate parsing, reporting, the web API (auth,
  validation, redaction, sensor lifecycle, WebSocket) and end-to-end CLI flows
- No root privileges or live network access required to run the test suite
