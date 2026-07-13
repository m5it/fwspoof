"""Packet parsing module for FWSpoof."""

import re
from dataclasses import dataclass
from typing import Optional, Tuple, List
from enum import Enum


class TCPFlag(Enum):
    """TCP flags as represented in tcpdump output."""
    SYN = "[S]"
    SYN_ACK = "[S.]"
    RST = "[R]"
    RST_ACK = "[R.]"
    ACK = "[.]"
    FIN = "[F]"
    PSH = "[P]"
    URG = "[U]"
    
    @classmethod
    def from_string(cls, flag_str: str) -> Optional["TCPFlag"]:
        """Convert string to TCPFlag enum."""
        try:
            return cls(flag_str)
        except ValueError:
            return None


@dataclass(frozen=True)
class Packet:
    """
    Represents a parsed network packet.
    
    Attributes:
        timestamp: Packet timestamp in seconds (HH:MM:SS.microseconds converted)
        source_ip: Source IP address with port (e.g., "192.168.1.1.443")
        dest_ip: Destination IP address with port (e.g., "10.0.0.1.80")
        flags: TCP flags string (e.g., "[S]", "[R]", "[S.]")
        fto: First two octets of source IP (e.g., "192.168")
        ftt: First three octets of source IP (e.g., "192.168.1")
        sip: Source IP without port (e.g., "192.168.1.1")
        sport: Source port number (optional)
        dip: Destination IP without port (optional)
        dport: Destination port number (optional)
    """
    timestamp: float
    source_ip: str
    dest_ip: str
    flags: str
    fto: str
    ftt: str
    sip: str
    sport: Optional[str] = None
    dip: Optional[str] = None
    dport: Optional[str] = None
    
    def __repr__(self) -> str:
        return f"Packet({self.sip}:{self.sport or '?'} -> {self.dip or '?'}:{self.dport or '?'}, flags={self.flags})"
    
    @property
    def has_syn(self) -> bool:
        """Check if packet has SYN flag."""
        return '[S' in self.flags
    
    @property
    def has_rst(self) -> bool:
        """Check if packet has RST flag."""
        return '[R' in self.flags


# Regex patterns for parsing tcpdump output
TIMESTAMP_PATTERN = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d+)')
IPV4_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
FLAGS_PATTERN = re.compile(r'Flags\s+(\[[^\]]+\])')
# More specific pattern for tcpdump lines
TCPDUMP_LINE_PATTERN = re.compile(
    r'^(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+.*Flags\s+(\[[^\]]+\])'
)


def parse_timestamp(ts_str: str) -> float:
    """
    Parse tcpdump timestamp to seconds.
    
    Format: HH:MM:SS.microseconds (e.g., "14:50:53.440085")
    
    Args:
        ts_str: Timestamp string from tcpdump
        
    Returns:
        Time in seconds since midnight with microsecond precision
        
    Examples:
        >>> parse_timestamp("14:50:53.440085")
        53453.440085
        >>> parse_timestamp("00:00:00.000001")
        0.000001
    """
    if not ts_str or not isinstance(ts_str, str):
        return 0.0
    
    try:
        parts = ts_str.split('.')
        if len(parts) < 2:
            return 0.0
            
        time_parts = parts[0].split(':')
        if len(time_parts) != 3:
            return 0.0
            
        hours, minutes, seconds = map(int, time_parts)
        microseconds = int(parts[1][:6].ljust(6, '0'))  # Ensure 6 digits
        
        if not (0 <= hours <= 23 and 0 <= minutes <= 59 and 0 <= seconds <= 59):
            return 0.0
            
        return hours * 3600 + minutes * 60 + seconds + microseconds / 1e6
        
    except (ValueError, IndexError, AttributeError):
        return 0.0


def extract_ip_port(addr: str) -> Tuple[str, Optional[str]]:
    """
    Extract IP and port from address string.
    
    Handles two formats:
    - tcpdump format: "192.168.1.1.443" (port as 5th octet)
    - standard format: "192.168.1.1:443" (colon separator)
    
    Args:
        addr: Address string potentially containing port
        
    Returns:
        Tuple of (ip_address, port_or_None)
        
    Examples:
        >>> extract_ip_port("192.168.1.1.443")
        ('192.168.1.1', '443')
        >>> extract_ip_port("192.168.1.1:443")
        ('192.168.1.1', '443')
        >>> extract_ip_port("192.168.1.1")
        ('192.168.1.1', None)
    """
    if not addr or not isinstance(addr, str):
        return "", None
    
    # Handle colon format first (more standard)
    if ':' in addr:
        try:
            ip, port = addr.rsplit(':', 1)
            # Validate port is numeric
            if port.isdigit():
                return ip, port
            return addr, None
        except ValueError:
            pass
    
    # Handle tcpdump format with dot separator
    parts = addr.split('.')
    if len(parts) >= 5:
        # Last part could be port number
        potential_port = parts[-1]
        if potential_port.isdigit():
            ip = '.'.join(parts[:-1])
            # Validate it's a valid IPv4
            if len(ip.split('.')) == 4:
                return ip, potential_port
    
    # No port found, return as-is
    return addr, None


def validate_ip(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IPv4, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except ValueError:
        return False


def calculate_octets(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Calculate first-two and first-three octets from IP.
    
    Args:
        ip: IPv4 address string
        
    Returns:
        Tuple of (fto, ftt) or (None, None) if invalid
        
    Examples:
        >>> calculate_octets("192.168.1.100")
        ('192.168', '192.168.1')
        >>> calculate_octets("10.0.0.1")
        ('10.0', '10.0.0')
    """
    if not validate_ip(ip):
        return None, None
    
    parts = ip.split('.')
    fto = '.'.join(parts[:2])
    ftt = '.'.join(parts[:3])
    return fto, ftt


def parse_line(line: str) -> Optional[Packet]:
    """
    Parse a tcpdump output line into a Packet.
    
    Expected formats:
    Standard: 14:50:53.440085 IP 192.168.1.100.54321 > 10.0.0.1.443: Flags [S], seq 12345, win 64240, length 0
    With options: 14:50:53.440085 IP 192.168.1.100.54321 > 10.0.0.1.443: Flags [S], seq 12345, win 64240, options [mss 1460], length 0
    
    Args:
        line: Single line from tcpdump output
        
    Returns:
        Packet object if parsing successful, None otherwise
    """
    if not line or not isinstance(line, str):
        return None
    
    line = line.strip()
    if not line:
        return None
    
    # Try regex pattern first for robustness
    match = TCPDUMP_LINE_PATTERN.match(line)
    if match:
        ts_str, src_addr, dst_addr, flags = match.groups()
    else:
        # Fallback to split-based parsing
        parts = line.split()
        if len(parts) < 7:
            return None
        
        # Basic validation
        if parts[1] != "IP":
            return None
        
        ts_str = parts[0]
        
        # Find arrow separator
        try:
            arrow_idx = parts.index('>')
            src_addr = parts[arrow_idx - 1]
            dst_addr = parts[arrow_idx + 1].rstrip(':') if arrow_idx + 1 < len(parts) else ""
        except ValueError:
            return None
        
        # Find flags
        flags = ""
        for i, part in enumerate(parts):
            if part == "Flags" and i + 1 < len(parts):
                flags = parts[i + 1].rstrip(',')
                break
    
    # Parse timestamp
    timestamp = parse_timestamp(ts_str)
    if timestamp == 0.0 and ts_str != "00:00:00.000000":
        # Likely invalid timestamp
        pass  # Continue anyway, might be edge case
    
    # Extract IPs and ports
    src_ip, src_port = extract_ip_port(src_addr)
    dst_ip, dst_port = extract_ip_port(dst_addr)
    
    # Validate source IP
    if not validate_ip(src_ip):
        return None
    
    # Calculate octets
    fto, ftt = calculate_octets(src_ip)
    if fto is None or ftt is None:
        return None
    
    return Packet(
        timestamp=timestamp,
        source_ip=src_addr,
        dest_ip=dst_addr,
        flags=flags,
        fto=fto,
        ftt=ftt,
        sip=src_ip,
        sport=src_port,
        dip=dst_ip if validate_ip(dst_ip) else None,
        dport=dst_port
    )


def parse_lines(lines: List[str]) -> List[Packet]:
    """
    Parse multiple tcpdump output lines.
    
    Args:
        lines: List of tcpdump output lines
        
    Returns:
        List of successfully parsed Packet objects
    """
    packets = []
    for line in lines:
        packet = parse_line(line)
        if packet is not None:
            packets.append(packet)
    return packets


def is_allowed(packet: Packet, allowed_ips: List[str]) -> bool:
    """
    Check if packet source IP is in allowed list.
    
    Args:
        packet: Packet to check
        allowed_ips: List of allowed IP addresses
        
    Returns:
        True if packet source IP is in allowed list
    """
    if not allowed_ips or not packet:
        return False
    return packet.sip in allowed_ips


def get_packet_summary(packet: Packet) -> str:
    """
    Get human-readable summary of packet.
    
    Args:
        packet: Packet to summarize
        
    Returns:
        Summary string
    """
    return (
        f"{packet.sip}:{packet.sport or '?'} -> "
        f"{packet.dip or '?'}:{packet.dport or '?'} "
        f"Flags: {packet.flags} "
        f"FTO: {packet.fto} FTT: {packet.ftt}"
    )
