# Network Security Toolkit

A modular network security toolkit built in Python 3.12+ with Scapy and Rich.
It captures and analyses live traffic, detects common LAN attacks (ARP
spoofing, DNS spoofing, MAC flooding), audits TLS certificates, and produces
self-contained HTML security reports — all from a single `nst` command.

## Features

### Packet Sniffer & Analyzer — `nst sniff`
- Live packet capture on any network interface
- Protocol parsing for TCP, UDP, DNS and HTTP
- Plaintext credential detection: HTTP Basic Auth, HTTP POST form fields, FTP USER/PASS
- Threat detection: port scanning, DNS tunneling (abnormally long query names), traffic to ports used by common RATs / C2 frameworks
- BPF filter support and PCAP file export
- Session summary: protocol breakdown, top talkers, top destination ports

### Live Dashboard — `nst dashboard`
- Full-screen, auto-refreshing view of protocol share, top source / destination IPs, packet rate and recent packets
- Same analysis engine as `sniff`, with a live alert counter

### ARP Spoofing Detector — `nst arp-watch`
- IP → MAC binding table seeded from the OS ARP cache at startup
- MAC change detection with gateway-aware severity escalation
- Gratuitous ARP detection and combined-signal MITM detection
- Trusted IP allowlist and a post-session bindings summary

### DNS Spoofing Detector — `nst dns-watch`
- IP change for a previously resolved domain
- Unsolicited responses (no matching query transaction ID)
- Zero-TTL responses (a classic cache-poisoning vector)
- Domains resolving to multiple IPs in one session
- Trusted domain allowlist (e.g. CDNs with legitimate anycast IPs)

### MAC Flooding Detector — `nst mac-watch`
- Sliding-window detection of bursts of previously unseen source MACs (CAM table overflow attacks)
- Critical alert when the tracked-MAC limit is reached

### TLS Certificate Inspector — `nst tls-scan`
- Expired / soon-to-expire certificates
- Self-signed certificates and hostname / SAN mismatches
- Weak protocol versions (SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites
- Weak public keys (RSA/DSA < 2048 bits, EC < 224 bits)
- Works against hosts with invalid certificates — problems are reported, not raised

### Web Console — `nst web`
- Local browser console on `127.0.0.1` (loopback only, never exposed to the network)
- Start and stop the traffic, ARP, DNS and MAC sensors per interface, with BPF filters for traffic
- Live findings board over WebSocket: new findings stay highlighted until opened; each opens as a "pass" with the full evidence
- Live traffic chart, protocol mix, top talkers and ports, recent packets; ARP / DNS / MAC tables from the running detectors
- TLS scans, GeoIP lookups, and HTML reports viewed in a sandboxed frame
- Capture permission is probed by really opening a capture socket; blocked and unavailable features are labelled as such
- Plaintext passwords and raw credential lines are redacted before they reach the browser

### HTML Reports & GeoIP — `nst report`, `nst geoip`
- Single-file HTML report with TLS findings and network interfaces
- Optional country / ISP enrichment of TLS findings via ip-api.com
- Stand-alone IP / hostname geolocation lookup (private ranges are never sent to the API)

---

## Architecture

```
src/nst/
├── core/           # Config, logging, filesystem paths, exceptions (shared infrastructure)
├── config/         # Bundled default.yaml and logging.yaml (package data)
├── sniffer/        # Packet capture engine, interface discovery, protocol parsers
├── analyzer/       # Traffic statistics, credential and threat detection, alerts
├── dashboard/      # Live Rich dashboard (stats, renderer, display)
├── arp_detector/   # ARP monitoring and MITM detection
├── dns_detector/   # DNS spoofing / cache-poisoning detection
├── mac_detector/   # MAC flooding detection
├── tls_inspector/  # TLS certificate retrieval and checks
├── geoip/          # Cached IP geolocation client
├── reporter/       # HTML report builder, renderer and writer
├── web/            # `nst web`: FastAPI backend, sensors, event store, bundled UI
└── cli/            # Click-based CLI and Rich UI

scripts/fetch_frontend.sh   # installs the web console build into src/nst/web/static/
frontend.version            # Networkscan-front release bundled by CI
```

The web console's source lives in its own repository,
[Networkscan-front](https://github.com/khikmat64168-cyber/Networkscan-front).

Each detector follows the same shape: a `monitor` that owns the Scapy sniff
loop, a pure `detector` that turns packets into typed events, a `table` of
observed state, an `events` log and an `alerts` manager for Rich output.

---

## Requirements

- Python 3.12+
- Linux or macOS
- Root / sudo privileges for the capture commands (`sniff`, `dashboard`,
  `arp-watch`, `dns-watch`, `mac-watch`). `tls-scan`, `report`, `geoip`,
  `interfaces` and `status` run as a normal user.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/khikmat64168-cyber/network-security-toolkit.git
cd network-security-toolkit

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the toolkit (provides the `nst` command)
pip install .

# Development: editable install plus test / lint tools
pip install -e . -r requirements-dev.txt
```

You can also run straight from the checkout without installing:
`python main.py <command>`.

Because the capture commands run under `sudo`, call the virtual
environment's script explicitly so root uses the same interpreter:

```bash
sudo .venv/bin/nst sniff
```

---

## Usage

```bash
# Show help (works for every subcommand: nst <command> --help)
nst --help

# List available network interfaces
nst interfaces

# Capture packets on the default interface (unlimited)
sudo nst sniff

# Capture 100 packets on eth0, filter for HTTP traffic, save to PCAP
sudo nst sniff -i eth0 -c 100 -f "tcp port 80" -o capture.pcap

# Live full-screen traffic dashboard
sudo nst dashboard -i eth0

# ARP spoofing monitor; MAC changes for the gateway are critical
sudo nst arp-watch -i eth0 --gateway 192.168.1.1 --trusted-ip 192.168.1.254

# DNS spoofing monitor, ignoring a CDN domain
sudo nst dns-watch -i eth0 --trusted-domain cdn.example.com

# MAC flooding monitor: alert on 30 new MACs within 5 seconds
sudo nst mac-watch -i eth0 --threshold 30 --window 5

# Inspect TLS certificates (no root needed)
nst tls-scan github.com example.com:8443

# HTML report with TLS findings, geolocation, opened in the browser
nst report --tls github.com --tls google.com --geo -o report.html --open

# Geolocate IPs / hostnames
nst geoip 8.8.8.8 github.com

# Show the effective configuration (including the resolved log file path)
nst status

# Enable debug logging for one run
sudo nst --debug sniff -i eth0
```

`tls-scan` and `report` exit with status 1 when a critical issue is found
(`tls-scan` also when a host cannot be scanned),
so they can be used as checks in scripts.

---

## Web Console

```bash
# Install with the web extra (FastAPI + uvicorn)
pip install '.[web]'

# Start the console; it opens the browser on a one-time tokenized link
sudo .venv/bin/nst web

# Other port / no browser
nst web --port 9000 --no-browser
```

The console listens on loopback only (`127.0.0.1`, `::1` or `localhost`);
any other bind address is refused. Each start prints a new link of the form
`http://127.0.0.1:8765/#token=…`. The token sits in the URL fragment, so it is
never sent in a request line or written to logs; the page moves it into
session storage and removes it from the address bar. Every API call and the
WebSocket must present it, requests with a non-loopback `Host` header are
rejected (DNS-rebinding protection), and WebSocket connections must come
from the console's own origin.

Packet capture needs the same privileges as the CLI capture commands. The
console checks this by opening a real capture socket rather than looking at
the user id, so it is also correct on hosts where capture is granted without
root (Linux `CAP_NET_RAW`, macOS `access_bpf`). TLS scans, GeoIP and reports
work without capture rights.

Reports generated from the console are stored in `~/.local/state/nst/reports/`.

### Getting the web console

The console's source is the separate
[Networkscan-front](https://github.com/khikmat64168-cyber/Networkscan-front)
repository. Its build is not committed here; put it in place with one of:

```bash
# the release pinned in frontend.version (what CI and releases use)
./scripts/fetch_frontend.sh --release
```

```bash
# a local checkout of Networkscan-front (Node 18.18+), for development
./scripts/fetch_frontend.sh --from ../Networkscan-front
```

Without it, `nst web` still serves the API and shows a "frontend not built"
page. For live frontend development see the Networkscan-front README.

---

## Deployment

The public demo runs on a VPS as a Coolify app (Traefik provides HTTPS);
the private console runs on the same VPS on loopback and is opened through
an SSH tunnel. Both are deployed from git tags by GitHub Actions (Docker
images on GHCR). The runbook — one-time setup, secrets, release order — is
in [deploy/README.md](deploy/README.md).

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

Settings are read from the first file that exists:

1. `--config FILE` on the command line
2. The file named by the `NST_CONFIG` environment variable
3. `~/.config/nst/config.yaml` (or `$XDG_CONFIG_HOME/nst/config.yaml`)
4. The bundled defaults in `src/nst/config/default.yaml`

To customise, copy the bundled file and edit the copy — every key is
optional, missing keys keep their defaults:

```bash
mkdir -p ~/.config/nst
cp src/nst/config/default.yaml ~/.config/nst/config.yaml
```

```yaml
network:
  interface: eth0          # set a fixed interface instead of auto-detect

analyzer:
  detect_credentials: true
  suspicious_port_scan_threshold: 10

arp_detector:
  trusted_ips:
    - 192.168.1.254        # router — never flag this IP
  gateway_ip: 192.168.1.1  # MAC changes here are escalated to critical

dns_detector:
  trusted_domains: [cdn.example.com]

mac_detector:
  flood_threshold: 50
  window_secs: 5.0
```

Environment variable overrides:

| Variable        | Effect                                        |
|-----------------|-----------------------------------------------|
| `NST_CONFIG`    | Path of the config file to load               |
| `NST_INTERFACE` | Network interface (when not set in the file)  |
| `NST_LOG_LEVEL` | Log level (`DEBUG`, `INFO`, `WARNING`, …)     |

### Log files

Logs rotate at 10 MB (5 backups by default). A relative `logging.file`
is stored under `~/.local/state/nst/` (or `$XDG_STATE_HOME/nst/`); an
absolute path is used as-is. `nst status` prints the resolved path.

Note that with `sudo`, Linux usually sets `HOME` to `/root`, so root's
config and log directories are used. Pass `--config` or use `sudo -E` to
keep your own.

---

## Running Tests

```bash
# Full test suite (no root or network access required)
pytest

# With coverage report
pytest --cov=nst --cov-report=term-missing

# Static checks
mypy src
flake8 src

```

Frontend tests run in the Networkscan-front repository.

---

## Troubleshooting

**"Permission Error: Root privileges required"**
Packet capture and the `*-watch` monitors open raw sockets, which both
Linux and macOS restrict to uid 0. Re-run the command with `sudo`.

**`nst: command not found` (or `sudo: nst: command not found`)**
The `nst` script lives in the virtual environment's `bin/` directory.
Activate the environment, call `.venv/bin/nst` directly (needed with
`sudo`), or use `python main.py <command>`.

**No packets / no interfaces shown**
Run `nst interfaces` to confirm the toolkit can see your adapter. On
macOS some interface details are hidden from unprivileged processes —
try `sudo nst interfaces`.

**`arp-watch` / `dns-watch` / `mac-watch` never raise any alerts**
This is expected on a healthy network — alerts only fire on the specific
anomalies listed above, not on ordinary traffic. Check the session
summary after Ctrl+C to confirm packets were actually seen.

**A configuration file error appears on startup**
The `Configuration Error` panel means the YAML file doesn't parse (or
`NST_CONFIG` points to a missing file). Validate it with
`python -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" FILE`.

**`nst web`: "Web dependencies are not installed"**
Install the extra: `pip install '.[web]'` (or `pip install -e '.[web]'` in a checkout).

**`nst web`: the page asks for an access token**
Each start of `nst web` issues a new token. Open the newest link printed in
the terminal; an old tab switches to the token screen when the server restarts.

**"log file … is not writable"**
The log file was created by another user (typically an earlier `sudo`
run). The command still works with console-only logging; fix ownership
with `sudo chown "$USER" ~/.local/state/nst/*.log`.

---

## Security Notes

- **Root required**: Scapy opens raw sockets, which requires elevated privileges.
- **Authorised use only**: Use this toolkit only on networks you own or have explicit written permission to test.
- **Credential detection**: The analyzer displays plaintext credentials it captures. Treat terminal output, logs and PCAP files as sensitive and delete them after testing.
- **GeoIP privacy**: `nst geoip` and `nst report --geo` send public IP addresses to [ip-api.com](https://ip-api.com) over plain HTTP (the free tier has no HTTPS). Private, loopback and link-local addresses are never sent. Don't use these features if the queried addresses are confidential.
- **TLS scanning**: `tls-scan` deliberately disables certificate verification so it can inspect broken certificates. It is an audit tool, not a trust decision.
- **Legal**: Unauthorised packet sniffing may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or equivalent laws in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

See [CHANGELOG.md](CHANGELOG.md) for release history.
