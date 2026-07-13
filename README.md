# FWSpoof

**Version:** 1.0.0  
**Author:** t3ch (w4d4f4k at gmail dot com)  
**License:** See LICENSE file

A Python tool to detect and block SYN flood and SYN+RESET spoofing attacks on HTTP servers by analyzing tcpdump packet captures.

## Overview

FWSpoof analyzes network traffic captured by tcpdump to identify suspicious patterns characteristic of spoofed attacks. These attacks are often not visible in standard HTTP server logs, requiring packet-level analysis tools like tcpdump or Wireshark.

### Attack Types Detected

- **SYN Flood**: Repeated SYN packets from the same IP range without completing the handshake
- **SYN+RESET Attack**: Alternating SYN and RESET packets indicating potential spoofing or scanning behavior

## Architecture

```
fwspoof/
├── __init__.py          # Package initialization
├── config.py            # Configuration management (YAML, env vars, CLI)
├── parser.py            # tcpdump output parsing
├── detector.py          # Attack detection engine
├── blocker.py           # iptables integration
├── stats.py             # Statistics collection
└── logger.py            # Logging utilities

main.py                  # Entry point with CLI
tests/                   # Unit tests
config.yaml              # Default configuration
```

### Module Relationships

```
tcpdump → parser → detector → blocker → iptables
            ↓         ↓          ↓
         logger ←  stats  ←   logger
```

1. **parser.py**: Converts tcpdump lines into structured Packet objects
2. **detector.py**: Tracks packet patterns across IP ranges (fto/ftt/sip levels)
3. **blocker.py**: Manages iptables rules for blocking/unblocking
4. **config.py**: Centralized configuration from CLI args, YAML, or environment
5. **stats.py**: Collects and reports execution statistics
6. **logger.py**: Provides verbose/debug logging

## Installation

```bash
# Clone or copy the fwspoof directory
cd fwspoof

# Install dependencies
pip install -r requirements.txt

# Make main.py executable (optional)
chmod +x main.py
```

## Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- Root privileges (for iptables manipulation)
- tcpdump (for packet capture)

## Usage

### Basic Usage

```bash
# Capture live traffic and pipe to fwspoof
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | python3 main.py

# Analyze saved capture file
tcpdump -r capture.cap -nn -s0 | python3 main.py -S

# Verbose mode with statistics
tcpdump -r out.cap -nn -s0 | python3 main.py -V -S
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--max-flag-count` | `-M` | Global threshold for SYN/SYN+RESET attacks | 20 |
| `--max-flag-count-per-cidr` | `-m` | Per-range (/24) SYN threshold | 3 |
| `--max-flag-count-per-cidr-sr` | `-r` | Per-range SYN+RESET threshold | 5 |
| `--verbose` | `-V` | Enable debug output | False |
| `--stats` | `-S` | Show statistics at exit | False |
| `--con-type` | `-C` | iptables chain (INPUT/FORWARD/OUTPUT) | FORWARD |
| `--dont-unblock` | `-D` | Once blocked, stay blocked | False |
| `--test` | `-T` | Test mode (no iptables commands) | False |
| `--specific-ip` | `-s` | Block specific IPs instead of ranges | False |
| `--config` | `-c` | Configuration file path | config.yaml |
| `--version` | `-v` | Show version | - |
| `--help` | `-h` | Show help | - |

### tcpdump Capture Examples

```bash
# Capture live traffic (replace eth0 and IP)
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 and not port 22 | python3 main.py

# Capture to file for later analysis
sudo tcpdump -i eth0 -nn -s0 tcp and dst 10.0.5.10 -w out.cap -G 1800

# Analyze saved capture
tcpdump -r out.cap -nn -s0 | python3 main.py -S -m 2 -M 13 -D -C INPUT

# Continuous monitoring with verbose output
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | python3 main.py -V -S -C INPUT
```

## Configuration

### Configuration File (config.yaml)

```yaml
# Attack detection thresholds
max_flag_count: 20              # Global threshold
max_flag_count_per_cidr: 3      # Per-range SYN threshold
max_flag_count_per_cidr_sr: 5   # Per-range SYN+RESET threshold

# Connection type for iptables
connection_type: "FORWARD"      # INPUT, FORWARD, or OUTPUT

# TCP flags to monitor
flags: "[S],[R]"                # SYN and RESET

# Behavior settings
dont_unblock: false             # Auto-unblock when attack stops
test_mode: false                # Don't execute iptables commands
specific_ip: false              # Block ranges (/24) by default
verbose: false                  # Debug output
show_stats: false               # Statistics summary
```

### Environment Variables

All configuration options can be set via environment variables with `FWSPOOF_` prefix:

```bash
export FWSPOOF_MAX_FLAG_COUNT=50
export FWSPOOF_CONNECTION_TYPE=INPUT
export FWSPOOF_VERBOSE=true
export FWSPOOF_DONT_UNBLOCK=true

python3 main.py
```

### Allowed IPs File

Create `allowed.ips` to whitelist specific addresses (one per line):

```
192.168.1.1
10.0.0.50
172.16.0.1
# Comments supported
```

## Example Output

### Normal Operation

```
$ tcpdump -r sample.cap -nn -s0 | python3 main.py -S
============================================================
                    FWSpoof Statistics
============================================================
  Execution Time:     5.23 seconds
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
```

### Verbose Mode

```
$ tcpdump -r sample.cap -nn -s0 | python3 main.py -V -S
[TEST] Would run: iptables -A FORWARD -s 192.168.1.0/24 -j DROP
Blocked range: 192.168.1.0/24
INFO => Attack detected from 192.168
DEBUG => Subnet: 192.168.1.0/24 (SYN: 5, SR: 0)
...
============================================================
                    FWSpoof Statistics
============================================================
...
```

## Troubleshooting

### Permission Denied Errors

**Problem:** `iptables: Permission denied`  
**Solution:** Run with sudo or as root:
```bash
sudo python3 main.py [options]
```

### No Packets Detected

**Problem:** fwspoof processes but finds no attacks  
**Solution:** 
- Check tcpdump filter includes the correct destination IP
- Verify thresholds with `-V` flag to see parsed packets
- Ensure traffic actually contains SYN packets: `tcpdump ... 'tcp[tcpflags] & tcp-syn != 0'`

### iptables Chain Doesn't Exist

**Problem:** `iptables: No chain/target/match by that name`  
**Solution:** Use existing chain (INPUT, FORWARD, or OUTPUT):
```bash
python3 main.py -C INPUT
```

### High Memory Usage

**Problem:** Large capture files cause memory issues  
**Solution:** Process in chunks:
```bash
# Process first 10000 packets
tcpdump -r large.cap -nn -s0 -c 10000 | python3 main.py

# Or use -G with tcpdump for rotating captures
sudo tcpdump -i eth0 -w capture.cap -G 300 -W 10
```

### Test Mode Shows Blocks But No Actual Blocking

**Problem:** `-T` flag is set or not running as root  
**Solution:** Remove `-T` and run with sudo:
```bash
sudo tcpdump -i eth0 ... | sudo python3 main.py
```

## Advanced Usage

### Integration with Systemd

Create a systemd service for continuous monitoring:

```ini
# /etc/systemd/system/fwspoof.service
[Unit]
Description=FWSpoof Attack Detector
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c '/usr/sbin/tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | /usr/bin/python3 /opt/fwspoof/main.py -C INPUT'
Restart=always

[Install]
WantedBy=multi-user.target
```

### Custom Detection Logic

Modify thresholds in code or config for your environment:

```python
# In config.yaml or via CLI
max_flag_count: 50              # Higher threshold for busy servers
max_flag_count_per_cidr: 5      # Less aggressive per-range blocking
```

## Development

### Running Tests

```bash
# Run all tests
python3 -m unittest discover tests/

# Run specific test file
python3 -m unittest tests.test_parser -v

# Run with coverage (requires coverage package)
coverage run -m unittest discover tests/
coverage report
```

### Project Structure

```
fwspoof/
├── fwspoof/          # Main package
│   ├── __init__.py
│   ├── config.py      # Configuration
│   ├── parser.py      # Packet parsing
│   ├── detector.py    # Attack detection
│   ├── blocker.py     # iptables management
│   ├── stats.py       # Statistics
│   └── logger.py      # Logging
├── tests/             # Unit tests
├── main.py            # Entry point
├── config.yaml        # Default config
├── requirements.txt   # Dependencies
├── README.md          # This file
└── LICENSE            # License
```

## Changelog

### v1.0.0 (2026)
- Complete rewrite with modular architecture
- Added comprehensive configuration system (YAML, env vars, CLI)
- Improved attack detection with three-level tracking (fto/ftt/sip)
- Added specific IP blocking mode
- Enhanced statistics and logging
- Full unit test coverage
- Clean separation of concerns

### v0.2 (2026-02-12)
- Added SYN/RESET attack support

### v0.1 (2026-02-07)
- Initial SYN attack support

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Support

For issues, questions, or contributions:
- Email: w4d4f4k at gmail dot com
- GitHub: [repository link]

## Acknowledgments

- tcpdump for packet capture
- iptables for firewall management
- Python community for excellent libraries
