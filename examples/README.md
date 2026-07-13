# FWSpoof Examples

This directory contains example files for testing FWSpoof.

## Files

- `sample.cap` - Sample tcpdump capture file (text format)
- `test_capture.sh` - Script to generate test traffic

## Generating Test Captures

### Live Capture
```bash
# Capture SYN packets to your server
sudo tcpdump -i eth0 -nn -s0 'tcp[tcpflags] & tcp-syn != 0 and dst 192.168.1.1' -w test.cap
```

### From Existing Capture
```bash
# Filter existing capture
tcpdump -r large.cap -nn -s0 'tcp[tcpflags] & tcp-syn != 0' -w filtered.cap
```

## Testing FWSpoof

```bash
# Test with sample capture
tcpdump -r examples/sample.cap -nn -s0 | python3 main.py -V -S

# Test with allowed IPs whitelist
tcpdump -r examples/sample.cap -nn -s0 | python3 main.py -a allowed.ips
```
