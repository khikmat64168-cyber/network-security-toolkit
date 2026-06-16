# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] — Initial Release

### Module 1 — Packet Sniffer & Analyzer
- Live packet capture on any network interface via Scapy
- Protocol parsers for TCP, UDP, HTTP, and DNS with a priority-based dispatcher
- Traffic statistics: protocol breakdown, top talkers, top destination ports
- Plaintext credential detection (HTTP Basic Auth, HTTP POST forms, FTP USER/PASS)
- Threat detection: port scanning, DNS tunneling, suspicious port usage
- Rich-formatted real-time CLI output and session summaries
- BPF filter support and PCAP file export

### Module 2 — ARP Spoofing Detector
- ARP binding table seeded from the OS ARP cache at startup
- MAC/IP change detection with gateway-aware severity escalation
- Gratuitous ARP detection
- Combined-signal MITM suspicion detection
- Trusted IP allowlist
- Structured event logging and Rich-formatted alert panels
- Session summary of all observed ARP bindings

### Core Infrastructure
- YAML-based configuration with environment variable overrides
- Rotating file logging with per-module level overrides
- Typed exception hierarchy for predictable error handling
- Click-based CLI (`sniff`, `arp-watch`, `interfaces`, `status`)

### Production Hardening
- Top-level exception guard (`src/cli/main.py:main`) used by both
  `python main.py` and the installed `nst` console script — no raw
  Python tracebacks ever reach the user
- Malformed configuration files now produce a clear error panel
  instead of an uncaught exception
- MIT license and this changelog added for public release

### Testing
- 140 unit and integration tests covering configuration, logging, packet
  parsing, traffic analysis, ARP spoofing detection, and end-to-end CLI
  and cross-module pipelines
- No root privileges or live network access required to run the test suite
