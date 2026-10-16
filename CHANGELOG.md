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
- Click-based CLI with ten subcommands

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
- 426 unit and integration tests (89% line coverage) covering
  configuration, logging, packet parsing, traffic analysis, every
  detector, TLS certificate parsing, reporting, and end-to-end CLI flows
- No root privileges or live network access required to run the test suite
