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
- Continuous ARP table monitoring, seeded from the OS ARP cache at startup
- MAC/IP binding verification with gateway-aware severity escalation
- Gratuitous ARP detection
- Combined-signal MITM attack detection and alerting
- Trusted IP allowlist
- Structured event logging and a post-session bindings summary

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

# Monitor ARP traffic and flag MAC changes for the gateway as critical
sudo nst arp-watch -i eth0 --gateway 192.168.1.1

# Whitelist known routers / printers so they never trigger an alert
sudo nst arp-watch -i eth0 --trusted-ip 192.168.1.1 --trusted-ip 192.168.1.254

# Show current configuration
sudo nst status

# Enable debug logging
sudo nst --debug sniff -i eth0
```

---

## How ARP Spoofing Detection Works

`arp-watch` builds a live table of IP → MAC bindings from observed ARP
traffic, seeded at startup from the operating system's own ARP cache. Each
incoming ARP packet is checked against this table:

| Signal | Trigger | Severity |
|---|---|---|
| **MAC change** | A known IP suddenly maps to a different MAC address | High |
| **Gateway MAC change** | The above, but for the configured `--gateway` IP | Critical |
| **Gratuitous ARP** | An unsolicited ARP reply where sender IP == target IP | Medium |
| **MITM suspected** | The same host triggers both a MAC change *and* a gratuitous ARP in one session | Critical |

Hosts listed with `--trusted-ip` are recorded but never evaluated, so
known infrastructure (routers, printers, NAS devices with static MACs)
won't generate noise. When the session ends (Ctrl+C), a summary table
shows every IP/MAC binding observed during the run.

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
    - 192.168.1.254      # router — never flag this IP
  gateway_ip: 192.168.1.1  # MAC changes here are escalated to critical
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

## Troubleshooting

**"Permission Error: Root privileges required"**
Packet capture and ARP monitoring open raw sockets, which both Linux and
macOS restrict to uid 0. Re-run the command with `sudo`.

**`nst: command not found`**
The `nst` script is only installed after `pip install -e .` inside the
active virtual environment. Either re-run that step, or use
`python main.py <command>` instead, which works without installation.

**No packets / no interfaces shown**
Run `sudo nst interfaces` to confirm the toolkit can see your adapter.
On macOS, Wi-Fi interfaces sometimes require disabling "Limit IP address
tracking" or running with `sudo` even for `interfaces` if the OS hides
MAC/IP details from unprivileged processes.

**`arp-watch` runs but never raises any alerts**
This is expected on a healthy network — alerts only fire on MAC changes,
gratuitous ARP, or combined MITM signals, not on ordinary traffic. Check
the session summary after Ctrl+C to confirm packets were actually seen.

**A configuration file error appears on startup**
The `Configuration Error` panel means the YAML file passed via `--config`
either doesn't parse or doesn't exist. Validate it with
`python -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" config/default.yaml`.

---

## Security Notes

- **Root required**: Scapy opens raw sockets, which requires elevated privileges.
- **Authorised use only**: Use this toolkit only on networks you own or have explicit written permission to test.
- **Credential detection**: The analyzer can capture plaintext credentials. Captured data should be stored securely and deleted after testing.
- **Legal**: Unauthorised packet sniffing may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or equivalent laws in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

See [CHANGELOG.md](CHANGELOG.md) for release history.
