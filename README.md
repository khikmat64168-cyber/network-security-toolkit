# Network Security Toolkit

A professional, modular network security toolkit built in Python 3.12 with Scapy and Rich.

## Features

### Module 1 — Packet Sniffer & Analyzer
- Live packet capture on any network interface
- Deep packet inspection (TCP, UDP, DNS, HTTP)
- Credential detection in plaintext traffic (FTP, Telnet, HTTP Basic Auth)
- Port scan detection and suspicious traffic alerts
- BPF filter support
- PCAP file export
- Real-time Rich CLI dashboard

### Module 2 — ARP Spoofing Detector
- Continuous ARP table monitoring
- MAC/IP binding verification
- ARP cache poisoning detection
- MITM attack detection and alerting
- Trusted IP allowlist
- Structured event logging

---

## Architecture

```
src/
├── core/           # Config, logging, exceptions (shared infrastructure)
├── sniffer/        # Packet capture engine and protocol parsers
├── analyzer/       # Traffic analysis, credential detection, alerts
├── arp_detector/   # ARP monitoring and MITM detection
└── cli/            # Click-based CLI and Rich UI
```

---

## Requirements

- Python 3.12+
- Linux or macOS
- Root / sudo privileges (required by Scapy for raw socket access)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/network-security-toolkit.git
cd network-security-toolkit

# 2. Create and activate a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# 3. Install runtime dependencies
pip install -r requirements.txt

# 4. Install the package in editable mode (enables `nst` CLI command)
pip install -e .

# 5. (Optional) Install development dependencies
pip install -r requirements-dev.txt
```

---

## Usage

All commands require root privileges for raw socket access.

```bash
# Show help
sudo nst --help

# List available network interfaces
sudo nst interfaces

# Capture packets on the default interface (unlimited)
sudo nst sniff

# Capture 100 packets on eth0, filter for HTTP traffic
sudo nst sniff -i eth0 -c 100 -f "tcp port 80"

# Capture and save to a PCAP file
sudo nst sniff -i eth0 -o capture.pcap

# Start ARP spoofing monitor on eth0
sudo nst arp-watch -i eth0

# Show current configuration
sudo nst status

# Enable debug logging
sudo nst --debug sniff -i eth0
```

---

## Configuration

Edit `config/default.yaml` to customise behaviour:

```yaml
network:
  interface: eth0        # set a fixed interface instead of auto-detect
  promiscuous: true

analyzer:
  detect_credentials: true
  suspicious_port_scan_threshold: 10

arp_detector:
  check_interval: 1.0
  trusted_ips:
    - 192.168.1.1        # router — never flag this IP
```

Override any setting via environment variables:

| Variable        | Effect                         |
|-----------------|--------------------------------|
| `NST_INTERFACE` | Override network interface     |
| `NST_LOG_LEVEL` | Override log level             |

---

## Running Tests

```bash
# Run full test suite
pytest

# With coverage report
pytest --cov=src --cov-report=term-missing
```

---

## Security Notes

- **Root required**: Scapy opens raw sockets, which requires elevated privileges.
- **Authorised use only**: Use this toolkit only on networks you own or have explicit written permission to test.
- **Credential detection**: The analyzer can capture plaintext credentials. Captured data should be stored securely and deleted after testing.
- **Legal**: Unauthorised packet sniffing may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or equivalent laws in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
