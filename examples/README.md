# FWSpoof Examples

This directory contains example files for testing FWSpoof.

## Files

- `sample.cap` — Sample tcpdump **text** output (12 packets, ready to pipe directly)
- `sample.pcap` — Binary pcap (create with `tcpdump -w` if needed)

## sample.cap

`sample.cap` is already in `tcpdump -nn -s0` **text** format, so pipe it directly with `cat`:

```bash
# Quick test (no root, no iptables)
cat examples/sample.cap | python3 main.py -T -V -S

# With custom thresholds (lower = more sensitive)
cat examples/sample.cap | python3 main.py -T -S -M 2 -m 1

# With whitelist
cat examples/sample.cap | python3 main.py -T -S -a allowed.ips
```

For a real binary capture:

```bash
# Create binary capture (requires traffic)
sudo tcpdump -i eth0 -nn -s0 -w examples/real.pcap -c 100 'tcp[tcpflags] & tcp-syn != 0'

# Replay binary capture (needs tcpdump to convert to text)
tcpdump -r examples/real.pcap -nn -s0 | python3 main.py -T -V -S
```

## Generating Test Captures

### Live Capture

```bash
# Capture SYN packets to your server
sudo tcpdump -i eth0 -nn -s0 'tcp[tcpflags] & tcp-syn != 0 and dst 192.168.1.1' -w test.pcap

# Capture all TCP to your server
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 -w test.pcap
```

### Filtering Existing Captures

```bash
# Keep only SYN packets
tcpdump -r large.pcap -nn -s0 'tcp[tcpflags] & tcp-syn != 0' -w filtered.pcap

# Text output for FWSpoof
tcpdump -r large.pcap -nn -s0 | python3 main.py -T -S
```

## Testing FWSpoof

```bash
# Test with sample capture (text)
cat examples/sample.cap | python3 main.py -T -V -S

# Test with allowed IPs whitelist
cat examples/sample.cap | python3 main.py -T -V -S -a allowed.ips

# Live monitoring (requires root)
sudo tcpdump -i eth0 -nn -s0 tcp and dst 192.168.1.1 | sudo python3 main.py -C INPUT -S
```
