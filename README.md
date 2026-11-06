# FWSpoof

**Version:** 1.0.0
**Author:** t3ch (w4d4f4k at gmail dot com)
**License:** Modified Apache 2.0 — see [LICENSE](LICENSE)

A Python tool to detect and block SYN flood and SYN+RESET spoofing attacks on HTTP servers by analyzing `tcpdump` packet captures.

> **Note:** These attacks are often invisible in standard HTTP server logs and require packet-level analysis.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Example Output](#example-output)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Development](#development)
- [Changelog](#changelog)
- [Contributing](#contributing)

## Overview

FWSpoof reads `tcpdump` output from stdin (live capture or replayed file), parses packets into structured objects, tracks SYN patterns across IP ranges, and manages `iptables` DROP rules automatically.

### Attack Types Detected

| Attack | Pattern | Description |
|--------|---------|-------------|
| **SYN Flood** | Repeated `SYN` from same range | Packets never complete the TCP handshake |
| **SYN+RESET** | Alternating `SYN` / `RST` | Indicates spoofing, scanning, or RST injection |

Detection works at three levels:

- **Range `/16`** (`fto` = first two octets, e.g. `192.168`) — global threshold
- **Subnet `/24`** (`ftt` = first three octets, e.g. `192.168.1`) — per-range threshold
- **IP `/32`** (`sip` = full address) — per-IP tracking

A range is flagged only when the global threshold *and* at least one subnet/IP per-range threshold are exceeded.

## Architecture

```
.
├── main.py              # Entry point — CLI, stdin loop, cleanup
├── config.yaml          # Default configuration (YAML)
├── allowed.ips          # Optional whitelist (one IP per line)
├── requirements.txt     # Dependencies (PyYAML)
├── fwspoof/             # Package
│   ├── __init__.py      # Version metadata
│   ├── config.py        # Config dataclass (YAML + env vars + CLI merging)
│   ├── parser.py        # tcpdump line → Packet parsing
│   ├── detector.py      # Three-level attack detection engine
│   ├── blocker.py       # iptables integration
│   ├── stats.py         # Statistics collection & reporting
│   └── logger.py        # Logging utilities
├── tests/               # Unit tests (unittest)
│   ├── test_parser.py
│   └── test_detector.py
└── examples/            # Example captures & docs
    ├── sample.cap       # Sample tcpdump text (4 example lines)
    └── README.md
```

### Module Relationships

```
                    ┌────────────┐
  tcpdump ─────────►│   parser   │─► Packet(fto/ftt/sip, flags)
                    └─────┬──────┘
                          ▼
                    ┌────────────┐     ┌────────────┐     ┌──────────┐
                    │  detector  │────►│  blocker   │────►│ iptables │
                    │  (ranges)  │     │            │     └──────────┘
                    └─────┬──────┘     └─────┬──────┘
                          │                  │
                          ▼                  ▼
                    ┌────────────┐     ┌────────────┐
                    │   stats    │◄────│   logger   │
                    └────────────┘     └────────────┘
                          ▲                  ▲
                    ┌────────────┐     ┌────────────┐
                    │   config   │────►│   main.py  │
                    └────────────┘     └────────────┘
```

1. **parser.py** — Regex + fallback parsing of tcpdump lines into `Packet` objects; handles `IP.12345 > IP.80: Flags [S]` format.
2. **detector.py** — Tracks packets per range/subnet/IP using CRC32-hashed keys; detects SYN flood and SYN+RESET patterns.
3. **blocker.py** — Manages `iptables -A/-D` rules; supports range (`/24`) and specific-IP blocking; test/simulation mode.
4. **config.py** — Single `Config` dataclass loaded from YAML file, `FWSPOOF_*` env vars, and CLI args (CLI wins).
5. **stats.py** — Counts packets, unique IPs, blocks/unblocks, timing, top attackers.
6. **logger.py** — Colored stderr logging with verbose/debug levels.

## Installation

### Prerequisites

- Python 3.8+
- `tcpdump` (for capture)
- `iptables` + root privileges (for actual blocking; optional for analysis)

### Steps

```bash
# 1. Clone
git clone <repository-url> fwspoof
cd fwspoof

# 2. (Recommended) Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
# Only dependency: PyYAML>=6.0

# 4. (Optional) Make executable
chmod +x main.py

# 5. Verify
python3 main.py --help
python3 -m unittest discover tests/ -v
```

## Quick Start

```bash
# Analyze a saved capture (no root needed, test mode)
tcpdump -r examples/sample.cap -nn -s0 | python3 main.py -T -S -V

# Live monitoring (requires root for iptables)
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 and not port 22 | sudo python3 main.py -C INPUT -S

# Save live capture for later analysis
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 -w out.cap -G 1800 -W 10
tcpdump -r out.cap -nn -s0 | python3 main.py -S -m 2 -M 13 -D -C INPUT
```

## Usage

FWSpoof reads **tcpdump text output from stdin**. Always pipe `tcpdump` into it.

### Basic Usage

```bash
# Live capture
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | python3 main.py

# Replay saved capture file
tcpdump -r capture.cap -nn -s0 | python3 main.py -S

# Verbose + statistics
tcpdump -r out.cap -nn -s0 | python3 main.py -V -S

# Test mode (never touches iptables)
tcpdump -r out.cap -nn -s0 | python3 main.py -T -V -S
```

### tcpdump Capture Examples

```bash
# Capture live traffic (replace interface and IP)
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 and not port 22 | python3 main.py

# Only SYN packets (reduces noise)
sudo tcpdump -i eth0 -nn -s0 'tcp[tcpflags] & tcp-syn != 0 and dst 10.0.5.10' | python3 main.py

# Capture to rotating files (every 30 min, keep 10)
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 -w out.cap -G 1800 -W 10

# Analyze specific capture slice (first 10k packets)
tcpdump -r large.cap -nn -s0 -c 10000 | python3 main.py -T -S

# Filter existing capture then analyze
tcpdump -r large.cap -nn -s0 'tcp[tcpflags] & tcp-syn != 0' -w filtered.cap
tcpdump -r filtered.cap -nn -s0 | python3 main.py -S
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--max-flag-count` | `-M` | Global threshold — total SYN/SYN+RESET per `/16` range to trigger detection | `20` |
| `--max-flag-count-per-cidr` | `-m` | Per-subnet (`/24`) SYN threshold — individual subnet/IP must exceed this | `3` |
| `--max-flag-count-per-cidr-sr` | `-r` | Per-subnet SYN+RESET threshold | `5` |
| `--flags` | `-F` | TCP flags to monitor (comma-separated) | `[S],[R]` |
| `--con-type` | `-C` | iptables chain: `INPUT`, `FORWARD`, `OUTPUT` | `FORWARD` |
| `--allowed-ips` | `-a` | Path to whitelist file | `allowed.ips` |
| `--config` | `-c` | Configuration file path | `config.yaml` |
| `--verbose` | `-V` | Enable debug/verbose output (stderr) | `false` |
| `--stats` | `-S` | Show statistics summary at exit (stdout) | `false` |
| `--dont-unblock` | `-D` | Never auto-unblock; blocked stays blocked | `false` |
| `--test` | `-T` | Test mode — log iptables commands, don't execute | `false` |
| `--specific-ip` | `-s` | Block specific `/32` IPs instead of `/24` ranges | `false` |
| `--version` | `-v` | Show version | — |
| `--help` | `-h` | Show help | — |

> **Threshold logic:** A `/16` range is blocked only when *both* the global `-M` threshold *and* at least one subnet's per-CIDR threshold (`-m` for SYN, `-r` for SYN+RESET) are exceeded. Tune `-M`/`-m`/`-r` together.

## Configuration

Precedence: **CLI args > environment variables > YAML file > defaults**.

### Configuration File (config.yaml)

```yaml
# Attack detection thresholds
max_flag_count: 20              # Global threshold per /16 range
max_flag_count_per_cidr: 3      # Per-range SYN threshold (/24)
max_flag_count_per_cidr_sr: 5   # Per-range SYN+RESET threshold

# iptables chain
connection_type: "FORWARD"      # INPUT, FORWARD, or OUTPUT

# TCP flags to monitor (comma-separated)
flags: "[S],[R]"

# Behavior
dont_unblock: false             # Auto-unblock when attack stops
test_mode: false                # Don't execute iptables commands
specific_ip: false              # Block /24 ranges by default (true = /32)
verbose: false                  # Debug output
show_stats: false               # Statistics summary at exit
```

Load a custom config: `python3 main.py -c /path/to/config.yaml`

### Environment Variables

All options can be set via `FWSPOOF_` prefix (case-insensitive booleans: `true`/`yes`/`1`):

```bash
export FWSPOOF_MAX_FLAG_COUNT=50
export FWSPOOF_MAX_FLAG_COUNT_PER_CIDR=5
export FWSPOOF_CONNECTION_TYPE=INPUT
export FWSPOOF_VERBOSE=true
export FWSPOOF_DONT_UNBLOCK=true
export FWSPOOF_TEST_MODE=true

python3 main.py
```

### Allowed IPs File

Whitelist trusted sources — packets from these IPs are skipped entirely. Uses `allowed.ips` by default (customize with `-a`).

Create `allowed.ips` (one IP per line, `#` comments supported):

```
192.168.1.1
10.0.0.50
172.16.0.1
# Monitoring server
203.0.113.5
```

```bash
# Use default allowed.ips
tcpdump -r out.cap -nn -s0 | python3 main.py -a allowed.ips

# Custom whitelist
tcpdump -r out.cap -nn -s0 | python3 main.py -a /etc/fwspoof/whitelist.txt

# No whitelist (empty or missing file is handled gracefully)
tcpdump -r out.cap -nn -s0 | python3 main.py -a /dev/null
```

## Example Output

### Normal Operation with Statistics (`-S`)

```
$ tcpdump -r sample.cap -nn -s0 | python3 main.py -T -S

============================================================
                    FWSpoof Statistics
============================================================
  Execution Time:     0.02 seconds
  Packets/sec:        152.34

  Packet Processing:
    Total Packets:    797
    Unique Sources:   45

  Blocking Actions:
    Range Blocks:     2
    Single IP Blocks: 0
    Already Blocked:  0
    Unblocks:         0
    Currently Blocked: 2
============================================================

  Packets by Flag:
    [R]             12
    [S]             785

  Top Attackers:
    192.168.1.50         120 packets
    10.0.0.99             45 packets
============================================================
```

Statistics are printed to **stdout**; logs go to **stderr**, so you can redirect them separately.

### Verbose Mode (`-V`)

```
$ tcpdump -r sample.cap -nn -s0 | python3 main.py -T -V -S
09:36:11 [INFO] FWSpoof starting...
09:36:11 [DEBUG] Configuration: FWSpoof Configuration: ...
09:36:11 [DEBUG] [TEST] Would run: iptables -A FORWARD -s 192.168.1.0/24 -j DROP
09:36:11 [INFO] Blocked range: 192.168.1.0/24
09:36:11 [INFO] Attack detected from 192.168
09:36:11 [DEBUG]   Subnet: 192.168.1.0/24 (SYN: 5, SR: 0)
...
```

In test mode (`-T`) or when `iptables` is unavailable, commands are logged as `[TEST]` / `[SIMULATED]` and no firewall changes occur.

## Troubleshooting

### Permission Denied — `iptables: Permission denied`

**Cause:** Not running as root.
**Solution:**

```bash
sudo python3 main.py [options]
# Both tcpdump and fwspoof may need sudo when piping:
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | sudo python3 main.py
```

### No Attacks Detected

**Cause:** Thresholds too high, wrong tcpdump filter, or traffic has no SYN packets.
**Solution:**

```bash
# Check what's being parsed
tcpdump -r out.cap -nn -s0 | python3 main.py -V -T 2>&1 | head -20

# Lower thresholds for testing
tcpdump -r out.cap -nn -s0 | python3 main.py -T -V -M 5 -m 2

# Verify tcpdump output contains SYN flags
tcpdump -r out.cap -nn -s0 | grep "Flags \[S"
tcpdump -r out.cap -nn -s0 'tcp[tcpflags] & tcp-syn != 0' | head

# Ensure correct destination filter
sudo tcpdump -i eth0 -nn -s0 tcp and dst YOUR_SERVER_IP | python3 main.py -V
```

### iptables Chain Doesn't Exist

**Cause:** Invalid chain name.
**Solution:** Use one of `INPUT`, `FORWARD`, or `OUTPUT`:

```bash
python3 main.py -C INPUT
# Check available chains:
sudo iptables -L -n
```

### High Memory Usage on Large Captures

**Cause:** Large `.cap` files keep state for every unique IP.
**Solution:**

```bash
# Process in chunks
tcpdump -r large.cap -nn -s0 -c 10000 | python3 main.py -T -S

# Use rotating captures for live monitoring
sudo tcpdump -i eth0 -w capture.cap -G 300 -W 10  # 5min rotation, keep 10

# Filter before analyzing
tcpdump -r large.cap -nn -s0 'tcp[tcpflags] & tcp-syn != 0' -w filtered.cap
```

### Test Mode Shows Blocks But No Actual Blocking

**Cause:** `-T` flag is set, or not running as root / iptables not installed.
**Solution:**

```bash
# Remove -T and run with sudo for real blocking
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | sudo python3 main.py -C INPUT

# Check if iptables exists
iptables --version
which iptables
```

### `sample.cap` Contains Only Comments

The `examples/sample.cap` file is a **text placeholder** with 4 example tcpdump lines, not a binary pcap. To generate a real capture:

```bash
# Generate a real binary capture
sudo tcpdump -i eth0 -nn -s0 -w examples/real.cap -c 100
# Then replay as text:
tcpdump -r examples/real.cap -nn -s0 | python3 main.py -T -S
```

## Advanced Usage

### Systemd Service (Continuous Monitoring)

```ini
# /etc/systemd/system/fwspoof.service
[Unit]
Description=FWSpoof Attack Detector
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c '/usr/sbin/tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | /usr/bin/python3 /opt/fwspoof/main.py -C INPUT -S'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fwspoof.service
sudo journalctl -u fwspoof -f
```

### Custom Thresholds for Busy Servers

```yaml
# config.yaml for high-traffic web server
max_flag_count: 50              # Higher global threshold
max_flag_count_per_cidr: 5      # Less aggressive per-range
max_flag_count_per_cidr_sr: 10  # Higher SYN+RESET tolerance
connection_type: "INPUT"
dont_unblock: false             # Allow recovery
```

### Blocking Specific IPs Instead of Ranges

By default, entire `/24` subnets are blocked. For surgical blocking:

```bash
tcpdump -r out.cap -nn -s0 | python3 main.py -s -S  # Block /32 only
```

### Separating Logs and Stats

```bash
# Logs (stderr) to file, stats (stdout) to console
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.0.5 | sudo python3 main.py -S -V 2> fwspoof.log

# Stats to file
tcpdump -r out.cap -nn -s0 | python3 main.py -S > stats.txt 2> fwspoof.log
```

## Development

### Running Tests

```bash
# All tests (unittest)
python3 -m unittest discover tests/ -v

# Single module
python3 -m unittest tests.test_parser -v
python3 -m unittest tests.test_detector -v

# With pytest (if installed)
python3 -m pytest tests/ -v

# With coverage
pip install coverage
coverage run -m unittest discover tests/
coverage report
coverage html  # → htmlcov/index.html
```

Tests use synthetic packet generators and mock tcpdump lines to cover parsing, threshold logic, and edge cases (empty input, malformed lines, boundary conditions).

### Project Structure

```
fwspoof/
├── fwspoof/            # Package
│   ├── __init__.py     # Version
│   ├── config.py       # Configuration management
│   ├── parser.py       # Packet parsing
│   ├── detector.py     # Attack detection
│   ├── blocker.py      # iptables management
│   ├── stats.py        # Statistics
│   └── logger.py       # Logging
├── tests/              # Unit tests
├── examples/           # Sample captures
├── main.py             # Entry point & CLI
├── config.yaml         # Default config
├── allowed.ips         # Whitelist template
├── requirements.txt    # Dependencies
├── README.md           # This file
└── LICENSE             # License
```

### Adding New Features

1. Create a feature branch
2. Add tests in `tests/`
3. Run `python3 -m unittest discover tests/ -v` and ensure no regressions
4. Update this README if adding CLI options or config keys
5. Submit a pull request

## Changelog

### v1.0.0 (2026-07-13)

- Complete rewrite with modular architecture (`fwspoof/` package)
- Three-level tracking (range `/16` → subnet `/24` → IP `/32`) with CRC32-hashed keys
- SYN flood + SYN+RESET detection with independent thresholds
- Unified `Config` dataclass: YAML, `FWSPOOF_*` env vars, and CLI args with validation
- `allowed.ips` whitelist support (`-a` flag, graceful handling of missing file)
- Two blocking modes: range (`/24`) and specific IP (`/32` via `-s`)
- Test/simulation mode (`-T`) and auto-unblock (`-D`) logic
- Statistics collection (`-S`) with timing, per-flag breakdown, top attackers
- Colored logging (`-V`) with separate stdout/stderr streams
- 67 unit tests; `examples/` with sample capture
- Clean Markdown documentation, `.gitignore`, systemd example

### v0.2 (2026-02-12)

- Added SYN/RESET attack support
- Basic iptables blocking

### v0.1 (2026-02-07)

- Initial SYN attack detection (monolithic script)

## Contributing

Contributions welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Add tests for new functionality
4. Ensure `python3 -m unittest discover tests/` passes
5. Submit a pull request

## Support

- **Email:** w4d4f4k at gmail dot com
- **Issues:** GitHub Issues (link to repository)

## Acknowledgments

- `tcpdump` for packet capture
- `iptables` / `netfilter` for firewall management
- Python community and PyYAML maintainers
