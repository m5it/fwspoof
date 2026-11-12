"""Attack detection engine for FWSpoof."""

import zlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict

from .parser import Packet
from .config import get_config, Config


def crc32_hash(text: str) -> str:
    """
    Generate CRC32 hash for dictionary keys.
    
    Args:
        text: String to hash
        
    Returns:
        Hex string of CRC32 hash
    """
    return format(zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF, 'x')


@dataclass
class IPStats:
    """Statistics for a specific IP address."""
    sip: str                    # Source IP
    count: int = 0              # SYN packet count
    count_sr: int = 0           # SYN+RESET pattern count
    flags: List[str] = field(default_factory=list)  # Recent flags
    last_timestamp: float = 0.0
    first_timestamp: float = 0.0
    
    def __post_init__(self):
        if self.first_timestamp == 0.0:
            self.first_timestamp = time.time()
    
    def add_flag(self, flag: str, timestamp: float) -> None:
        """Add a flag observation."""
        self.flags.append(flag)
        if len(self.flags) > 4:
            self.flags.pop(0)
        self.last_timestamp = timestamp
    
    def is_syn_flood(self, threshold: int) -> bool:
        """Check if this IP exceeds SYN threshold."""
        return self.count >= threshold
    
    def is_syn_reset_attack(self, threshold: int) -> bool:
        """Check if this IP exceeds SYN+RESET threshold."""
        return self.count_sr >= threshold


@dataclass
class SubnetStats:
    """Statistics for a /24 subnet (first three octets)."""
    ftt: str                    # First three octets
    cftt: str                   # CRC32 hash of ftt
    ips: Dict[str, IPStats] = field(default_factory=dict)  # key = crc32(sip)
    last_timestamp: float = 0.0
    first_timestamp: float = 0.0
    last_flag: str = ""         # Last flag seen in this subnet
    flag_count: int = 0         # SYN count for subnet
    flag_count_sr: int = 0      # SYN+RESET count for subnet
    
    def __post_init__(self):
        if self.first_timestamp == 0.0:
            self.first_timestamp = time.time()
    
    def get_ip_key(self, sip: str) -> str:
        """Get hash key for an IP."""
        return crc32_hash(sip)
    
    def get_or_create_ip_stats(self, sip: str) -> IPStats:
        """Get or create stats for an IP."""
        key = self.get_ip_key(sip)
        if key not in self.ips:
            self.ips[key] = IPStats(sip=sip)
        return self.ips[key]


@dataclass
class RangeStats:
    """Statistics for an IP range (first two octets)."""
    fto: str                    # First two octets
    cfto: str                   # CRC32 hash of fto
    subnets: Dict[str, SubnetStats] = field(default_factory=dict)  # key = crc32(ftt)
    last_timestamp: float = 0.0
    first_timestamp: float = 0.0
    last_flag: str = ""         # Last flag seen in this range
    flag_count: int = 0         # Total SYN count for range
    flag_count_sr: int = 0      # Total SYN+RESET count for range
    unique_ips: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        if self.first_timestamp == 0.0:
            self.first_timestamp = time.time()
    
    def get_subnet_key(self, ftt: str) -> str:
        """Get hash key for a subnet."""
        return crc32_hash(ftt)
    
    def get_or_create_subnet(self, ftt: str) -> SubnetStats:
        """Get or create stats for a subnet."""
        key = self.get_subnet_key(ftt)
        if key not in self.subnets:
            self.subnets[key] = SubnetStats(
                ftt=ftt,
                cftt=key,
                first_timestamp=time.time()
            )
        return self.subnets[key]


@dataclass
class AttackResult:
    """Result of attack detection."""
    fto: str
    fto_key: str
    subnets: List[Dict[str, Any]]
    total_syn: int
    total_sr: int
    timestamp: float = field(default_factory=time.time)
    
    def __getitem__(self, key):
        # Allow dict-style access for backwards compatibility with tests
        return getattr(self, key)
    
    def __contains__(self, key):
        return hasattr(self, key)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'fto': self.fto,
            'fto_key': self.fto_key,
            'subnets': self.subnets,
            'total_syn': self.total_syn,
            'total_sr': self.total_sr,
            'timestamp': self.timestamp
        }


class AttackDetector:
    """
    Detects SYN flood and SYN+RESET attacks by tracking packet patterns
    across IP ranges.
    
    Tracks at three levels:
    - Range level (fto/16): First two octets
    - Subnet level (ftt/24): First three octets  
    - IP level (sip/32): Individual IP addresses
    
    Attack detection uses configurable thresholds for both SYN flood
    (repeated SYN packets) and SYN+RESET attacks (alternating SYN/RESET).
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize detector.
        
        Args:
            config: Configuration object, or None to use global config
        """
        self.config = config or get_config()
        self.ranges: Dict[str, RangeStats] = {}  # key = crc32(fto)
        self.suspects: Set[str] = set()           # Set of attacking range keys
        self.blocked_ips: Set[str] = set()        # Set of blocked IP hashes
        
    def _get_range_key(self, fto: str) -> str:
        """Get hash key for a range."""
        return crc32_hash(fto)
    
    def _get_ip_key(self, sip: str) -> str:
        """Get hash key for an IP."""
        return crc32_hash(sip)
    
    def _is_syn_reset_pattern(self, flag1: str, flag2: str) -> bool:
        """Check if two flags form a SYN+RESET pattern."""
        return (flag1 == '[S]' and flag2 == '[R]') or \
               (flag1 == '[R]' and flag2 == '[S]')
    
    def _update_syn_reset_count(self, stats: RangeStats, 
                                ip_stat: IPStats, 
                                current_flag: str,
                                last_flag: str) -> bool:
        """
        Update SYN+RESET pattern count.
        
        Returns:
            True if pattern was detected
        """
        if self._is_syn_reset_pattern(last_flag, current_flag):
            stats.flag_count_sr += 1
            ip_stat.count_sr += 1
            return True
        elif last_flag and last_flag != current_flag:
            # Non-alternating flag change - decrement (aggressive mode)
            stats.flag_count_sr = max(0, stats.flag_count_sr - 1)
            ip_stat.count_sr = max(0, ip_stat.count_sr - 1)
        return False
    
    def process_packet(self, packet: Packet) -> Optional[str]:
        """
        Process a single packet and update detection state.
        Replicates original fwspoof.py parse() logic for compatibility.
        
        Args:
            packet: Parsed packet
            
        Returns:
            Range key (fto hash) - always returned
        """
        fto_key = self._get_range_key(packet.fto)
        ftt_key = crc32_hash(packet.ftt)
        current_time = packet.timestamp or time.time()
        flag = packet.flags
        
        # Initialize range if new
        if fto_key not in self.ranges:
            self.ranges[fto_key] = RangeStats(
                fto=packet.fto,
                cfto=fto_key,
                first_timestamp=current_time,
                last_timestamp=current_time,
                last_flag=flag,
                flag_count=1 if flag == '[S]' else 0,
                flag_count_sr=1 if flag in self.config.flag_list else 0,
                unique_ips={packet.sip}
            )
            # Initialize subnet with same counters as original
            subnet = self.ranges[fto_key].get_or_create_subnet(packet.ftt)
            subnet.last_timestamp = current_time
            subnet.first_timestamp = current_time
            subnet.last_flag = flag
            subnet.flag_count = 1 if flag == '[S]' else 0
            subnet.flag_count_sr = 1 if flag in self.config.flag_list else 0
            # Initialize IP stats
            ip_stat = subnet.get_or_create_ip_stats(packet.sip)
            ip_stat.first_timestamp = current_time
            ip_stat.last_timestamp = current_time
            ip_stat.count = 1 if flag == '[S]' else 0
            ip_stat.count_sr = 1 if flag in self.config.flag_list else 0
            ip_stat.flags = [flag]
            return None
        
        # Update existing range - replicate original logic exactly
        stats = self.ranges[fto_key]
        stats.last_timestamp = current_time
        stats.unique_ips.add(packet.sip)

        # --- Range level (fto) update - matches original MemoryFlood[cfto] logic ---
        rst = False
        if flag in self.config.flag_list and (
            (stats.last_flag == '[S]' and flag == '[R]') or
            (stats.last_flag == '[R]' and flag == '[S]')
        ):
            stats.flag_count_sr += 1
        else:
            rst = True
        if stats.last_flag == flag and flag == '[S]':
            stats.flag_count += 1
        elif rst:
            stats.flag_count = 1
            stats.last_flag = flag
        stats.last_timestamp = current_time

        # --- Subnet level (ftt) update - matches original oftt[cftt] logic ---
        subnet = stats.get_or_create_subnet(packet.ftt)
        # Detect new subnet (freshly created has empty last_flag)
        if subnet.last_flag == "" and subnet.flag_count == 0 and subnet.flag_count_sr == 0:
            subnet.ftt = packet.ftt
            subnet.cftt = ftt_key
            subnet.first_timestamp = current_time
            subnet.last_timestamp = current_time
            subnet.last_flag = flag
            subnet.flag_count = 1 if flag == '[S]' else 0
            subnet.flag_count_sr = 1 if flag in self.config.flag_list else 0
        else:
            # Existing subnet - replicate original cftt logic with aggressive decrement
            rst2 = False
            if flag in self.config.flag_list and (
                (subnet.last_flag == '[S]' and flag == '[R]') or
                (subnet.last_flag == '[R]' and flag == '[S]')
            ):
                subnet.flag_count_sr += 1
            else:
                rst2 = True
                subnet.flag_count_sr -= 1
            if subnet.last_flag == flag and flag == '[S]':
                subnet.flag_count += 1
            elif rst2:
                subnet.flag_count = 1
            subnet.last_flag = flag
            subnet.last_timestamp = current_time

        # --- Per-IP level (cftf) update - for specific IP mode ---
        ip_stat = subnet.get_or_create_ip_stats(packet.sip)
        # Detect new IP (flags empty)
        if not ip_stat.flags:
            ip_stat.first_timestamp = current_time
            ip_stat.last_timestamp = current_time
            ip_stat.count = 1 if flag == '[S]' else 0
            ip_stat.count_sr = 1 if flag in self.config.flag_list else 0
            ip_stat.flags = [flag]
        else:
            pflag = ip_stat.flags[-1] if ip_stat.flags else ""
            rst3 = False
            if pflag == '[S]' and flag == '[R]' or pflag == '[R]' and flag == '[S]':
                ip_stat.count_sr += 1
            else:
                ip_stat.count_sr = 0
                rst3 = True
            if flag == '[S]':
                ip_stat.count += 1
            elif rst3:
                ip_stat.count = 0
            if len(ip_stat.flags) >= 4:
                ip_stat.flags.pop(0)
            ip_stat.flags.append(flag)
            ip_stat.last_timestamp = current_time
            # keep ip_stat.last_timestamp updated

        return fto_key
    
    def check_attack(self, fto_key: str) -> Optional[AttackResult]:
        """
        Check if a range should be blocked based on thresholds.
        
        Args:
            fto_key: Hash key for the range to check
            
        Returns:
            AttackResult with blocking details, or None if no attack
        """
        if fto_key not in self.ranges:
            return None
        
        stats = self.ranges[fto_key]
        config = self.config

        # Replicate old check_suspect global condition exactly:
        #   MF['last_flag'] in Globals['flags'] and (flag_count >= M or flag_count_sr >= M)
        if stats.last_flag not in config.flag_list:
            return None
        if not (stats.flag_count >= config.max_flag_count or stats.flag_count_sr >= config.max_flag_count):
            return None

        # Per-CIDR check - replicate perform_block: per subnet (ftt) thresholds
        # Old bug: uses -m for both S and S,R: MFF['flag_count_sr'] >= -m (not -r)
        # Keeping bug for exact parity; fix to use max_flag_count_per_cidr_sr if you want correct behavior
        attacking_subnets = []
        for subnet_key, subnet in stats.subnets.items():
            syn_threshold = subnet.flag_count >= config.max_flag_count_per_cidr
            sr_threshold = subnet.flag_count_sr >= config.max_flag_count_per_cidr  # old bug, should be per_cidr_sr
            if syn_threshold or sr_threshold:
                cidr = f"{subnet.ftt}.0/24"
                # pick a representative sip from subnet (first IP) for compatibility
                rep_sip = next(iter(subnet.ips.values())).sip if subnet.ips else f"{subnet.ftt}.0"
                rep_key = next(iter(subnet.ips.keys())) if subnet.ips else subnet_key
                attacking_subnets.append({
                    'cidr': cidr,
                    'ftt': subnet.ftt,
                    'ftt_key': subnet_key,
                    'sip': rep_sip,
                    'ip_key': rep_key,
                    'syn_count': subnet.flag_count,
                    'sr_count': subnet.flag_count_sr,
                    'first_seen': subnet.first_timestamp,
                    'last_seen': subnet.last_timestamp
                })

        if attacking_subnets:
            self.suspects.add(fto_key)
            return AttackResult(
                fto=stats.fto,
                fto_key=fto_key,
                subnets=attacking_subnets,
                total_syn=stats.flag_count,
                total_sr=stats.flag_count_sr
            )

        return None
    
    def check_specific_ip_attack(self, sip: str, ftt: str) -> Optional[Dict[str, Any]]:
        """
        Check if a specific IP should be blocked.
        
        Args:
            sip: Source IP to check
            ftt: First three octets
            
        Returns:
            Block info dict or None
        """
        fto_key = self._get_range_key('.'.join(ftt.split('.')[:2]))
        
        if fto_key not in self.ranges:
            return None
        
        subnet_key = crc32_hash(ftt)
        if subnet_key not in self.ranges[fto_key].subnets:
            return None
        
        subnet = self.ranges[fto_key].subnets[subnet_key]
        ip_key = self._get_ip_key(sip)
        
        if ip_key not in subnet.ips:
            return None
        
        ip_stat = subnet.ips[ip_key]
        config = self.config
        
        if ip_stat.count >= config.max_flag_count_per_cidr or \
           ip_stat.count_sr >= config.max_flag_count_per_cidr_sr:
            
            return {
                'sip': sip,
                'ip_key': ip_key,
                'syn_count': ip_stat.count,
                'sr_count': ip_stat.count_sr,
                'ftt': ftt,
                'fto_key': fto_key
            }
        
        return None
    
    def get_suspect_keys(self) -> Set[str]:
        """Get set of all suspect range keys."""
        return self.suspects.copy()
    
    def clear_suspect(self, fto_key: str) -> None:
        """Remove a suspect from tracking."""
        self.suspects.discard(fto_key)
    
    def add_blocked_ip(self, sip: str) -> None:
        """Mark an IP as blocked."""
        self.blocked_ips.add(self._get_ip_key(sip))
    
    def is_blocked(self, sip: str) -> bool:
        """Check if an IP is already blocked."""
        return self._get_ip_key(sip) in self.blocked_ips
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        total_ips = sum(
            len(subnet.ips) 
            for range_stats in self.ranges.values() 
            for subnet in range_stats.subnets.values()
        )
        
        return {
            'total_ranges': len(self.ranges),
            'total_subnets': sum(len(r.subnets) for r in self.ranges.values()),
            'total_ips_tracked': total_ips,
            'suspects': len(self.suspects),
            'blocked_ips': len(self.blocked_ips),
            'unique_ips': sum(len(r.unique_ips) for r in self.ranges.values())
        }
    
    def get_range_info(self, fto_key: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a range."""
        if fto_key not in self.ranges:
            return None
        
        stats = self.ranges[fto_key]
        return {
            'fto': stats.fto,
            'cfto': stats.cfto,
            'syn_count': stats.flag_count,
            'sr_count': stats.flag_count_sr,
            'unique_ips': len(stats.unique_ips),
            'subnets': len(stats.subnets),
            'is_suspect': fto_key in self.suspects
        }
    
    def reset(self) -> None:
        """Reset all detection state."""
        self.ranges.clear()
        self.suspects.clear()
        self.blocked_ips.clear()
