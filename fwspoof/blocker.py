"""IP blocking management using iptables."""

import subprocess
import time
import zlib
import re
from typing import Dict, Set, Optional, List, Any
from dataclasses import dataclass, field
from enum import Enum

from .config import get_config, Config
from .logger import debug, info, warning, error


class BlockType(Enum):
    """Type of block applied."""
    RANGE = "range"
    SPECIFIC = "specific"


@dataclass
class BlockedEntry:
    """Represents a blocked IP or range."""
    cidr: str
    fto: str
    ftt: str
    timestamp: float = field(default_factory=time.time)
    block_type: BlockType = BlockType.RANGE
    hit_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cidr': self.cidr,
            'fto': self.fto,
            'ftt': self.ftt,
            'timestamp': self.timestamp,
            'block_type': self.block_type.value,
            'hit_count': self.hit_count
        }


class IPBlocker:
    """Manages IP blocking via iptables."""
    
    IPTABLES_DROP_PATTERN = re.compile(r'^DROP\s+all\s+--\s+(\S+)\s+0\.0\.0\.0/0')
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.blocked: Dict[str, BlockedEntry] = {}
        self.blocked_ips: Dict[str, BlockedEntry] = {}
        self.iptables_available: bool = self._check_iptables()
        
    def _check_iptables(self) -> bool:
        """Check if iptables is available."""
        try:
            subprocess.run(['iptables', '--version'], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            warning("iptables not found - blocking will be simulated")
            return False
    
    def _crc32_key(self, text: str) -> str:
        """Generate CRC32 hash key."""
        return format(zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF, 'x')
    
    def _run_iptables(self, command: List[str]) -> bool:
        """Run iptables command."""
        if self.config.test_mode:
            debug(f"[TEST] Would run: iptables {' '.join(command)}")
            return True
        
        if not self.iptables_available:
            debug(f"[SIMULATED] iptables {' '.join(command)}")
            return True
        
        try:
            result = subprocess.run(['iptables'] + command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                error(f"iptables failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            error(f"iptables error: {e}")
            return False
    
    def load_blocks(self) -> int:
        """Load currently blocked IPs from iptables."""
        self.blocked.clear()
        self.blocked_ips.clear()
        
        if self.config.test_mode or not self.iptables_available:
            debug("Skipping iptables load (test mode or not available)")
            return 0
        
        try:
            output = subprocess.check_output(
                ['iptables', '-L', self.config.connection_type, '-n'],
                stderr=subprocess.DEVNULL, text=True
            )
            
            count = 0
            for line in output.split('\n'):
                match = self.IPTABLES_DROP_PATTERN.match(line.strip())
                if match:
                    cidr = match.group(1)
                    count += self._process_loaded_cidr(cidr)
            
            info(f"Loaded {count} existing blocks from iptables")
            return count
            
        except subprocess.CalledProcessError as e:
            warning(f"Failed to load iptables rules: {e}")
            return 0
        except Exception as e:
            warning(f"Error loading iptables rules: {e}")
            return 0

    # Alias for backwards compatibility with main.py
    def load_existing_blocks(self) -> int:
        """Alias for load_blocks()."""
        return self.load_blocks()
    
    def _process_loaded_cidr(self, cidr: str) -> int:
        """Process a loaded CIDR entry."""
        if '/' in cidr:
            ip_parts = cidr.split('.')
            if len(ip_parts) < 3:
                return 0
            fto = '.'.join(ip_parts[:2])
            ftt = '.'.join(ip_parts[:3])
            key = self._crc32_key(fto)
            self.blocked[key] = BlockedEntry(
                cidr=cidr, fto=fto, ftt=ftt, timestamp=0, block_type=BlockType.RANGE
            )
            return 1
        else:
            ip_parts = cidr.split('.')
            if len(ip_parts) != 4:
                return 0
            fto = '.'.join(ip_parts[:2])
            ftt = '.'.join(ip_parts[:3])
            key = self._crc32_key(cidr)
            self.blocked_ips[key] = BlockedEntry(
                cidr=cidr, fto=fto, ftt=ftt, timestamp=0, block_type=BlockType.SPECIFIC
            )
            return 1
    
    def block_ip(self, cidr_or_ip: str, fto: str = "", ftt: str = "") -> bool:
        """Block an IP or range."""
        if '/' in cidr_or_ip:
            return self._block_range(cidr_or_ip, fto, ftt)
        else:
            return self._block_specific(cidr_or_ip, fto, ftt)

    # Compatibility aliases used by main.py
    def block_cidr(self, cidr: str, fto: str = "", ftt: str = "") -> bool:
        """Alias for blocking a CIDR range."""
        return self._block_range(cidr, fto, ftt)

    def block_specific_ip(self, sip: str, fto: str = "", ftt: str = "") -> bool:
        """Alias for blocking a specific IP."""
        return self._block_specific(sip, fto, ftt)

    def unblock_cidr(self, cidr: str, fto: str = "") -> bool:
        """Alias for unblocking a CIDR range."""
        return self._unblock_range(cidr, fto)
    
    def _block_range(self, cidr: str, fto: str = "", ftt: str = "") -> bool:
        """Block an IP range (/24 CIDR)."""
        if not fto or not ftt:
            ip_parts = cidr.split('.')
            if len(ip_parts) < 3:
                error(f"Invalid CIDR format: {cidr}")
                return False
            fto = '.'.join(ip_parts[:2])
            ftt = '.'.join(ip_parts[:3])
        
        key = self._crc32_key(fto)
        
        if key in self.blocked:
            self.blocked[key].hit_count += 1
            debug(f"Range {cidr} already blocked")
            return True
        
        if not self._run_iptables(['-A', self.config.connection_type, '-s', cidr, '-j', 'DROP']):
            return False
        
        self.blocked[key] = BlockedEntry(cidr=cidr, fto=fto, ftt=ftt, block_type=BlockType.RANGE)
        info(f"Blocked range: {cidr}")
        return True
    
    def _block_specific(self, sip: str, fto: str = "", ftt: str = "") -> bool:
        """Block a specific IP address."""
        if not fto or not ftt:
            ip_parts = sip.split('.')
            if len(ip_parts) != 4:
                error(f"Invalid IP format: {sip}")
                return False
            fto = '.'.join(ip_parts[:2])
            ftt = '.'.join(ip_parts[:3])
        
        key = self._crc32_key(sip)
        
        if key in self.blocked_ips:
            self.blocked_ips[key].hit_count += 1
            debug(f"IP {sip} already blocked")
            return True
        
        if not self._run_iptables(['-A', self.config.connection_type, '-s', sip, '-j', 'DROP']):
            return False
        
        self.blocked_ips[key] = BlockedEntry(cidr=sip, fto=fto, ftt=ftt, block_type=BlockType.SPECIFIC)
        info(f"Blocked IP: {sip}")
        return True
    
    def unblock_ip(self, cidr_or_ip: str, fto: str = "") -> bool:
        """Unblock an IP or range."""
        if '/' in cidr_or_ip:
            return self._unblock_range(cidr_or_ip, fto)
        else:
            return self._unblock_specific(cidr_or_ip)
    
    def _unblock_range(self, cidr: str, fto: str = "") -> bool:
        """Unblock a range."""
        if not fto:
            ip_parts = cidr.split('.')
            if len(ip_parts) < 2:
                return False
            fto = '.'.join(ip_parts[:2])
        
        key = self._crc32_key(fto)
        
        if key not in self.blocked:
            return True
        
        if not self._run_iptables(['-D', self.config.connection_type, '-s', cidr, '-j', 'DROP']):
            return False
        
        del self.blocked[key]
        info(f"Unblocked range: {cidr}")
        return True
    
    def _unblock_specific(self, sip: str) -> bool:
        """Unblock a specific IP."""
        key = self._crc32_key(sip)
        
        if key not in self.blocked_ips:
            return True
        
        if not self._run_iptables(['-D', self.config.connection_type, '-s', sip, '-j', 'DROP']):
            return False
        
        del self.blocked_ips[key]
        info(f"Unblocked IP: {sip}")
        return True
    
    def is_blocked(self, cidr_or_ip: str) -> bool:
        """Check if an IP or range is blocked."""
        if '/' in cidr_or_ip:
            ip_parts = cidr_or_ip.split('.')
            if len(ip_parts) < 2:
                return False
            fto = '.'.join(ip_parts[:2])
            key = self._crc32_key(fto)
            return key in self.blocked
        else:
            key = self._crc32_key(cidr_or_ip)
            return key in self.blocked_ips
    
    def is_range_blocked(self, fto: str) -> bool:
        """Check if a range (by fto) is blocked."""
        key = self._crc32_key(fto)
        return key in self.blocked
    
    def is_ip_blocked(self, sip: str) -> bool:
        """Check if a specific IP is blocked."""
        key = self._crc32_key(sip)
        return key in self.blocked_ips
    
    def check_unblock_needed(self, active_suspects: Set[str]) -> List[BlockedEntry]:
        """Check which blocked ranges should be unblocked."""
        if self.config.dont_unblock:
            return []
        
        to_unblock = []
        for key, entry in list(self.blocked.items()):
            if key not in active_suspects:
                to_unblock.append(entry)
        return to_unblock
    
    def get_blocked_count(self) -> int:
        """Get total number of blocked entries."""
        return len(self.blocked) + len(self.blocked_ips)
    
    def get_range_count(self) -> int:
        """Get number of blocked ranges."""
        return len(self.blocked)
    
    def get_specific_count(self) -> int:
        """Get number of specifically blocked IPs."""
        return len(self.blocked_ips)
    
    def get_all_blocked(self) -> List[BlockedEntry]:
        """Get all blocked entries."""
        return list(self.blocked.values()) + list(self.blocked_ips.values())
    
    def clear_all(self) -> int:
        """Clear all blocks."""
        count = 0
        for entry in list(self.blocked.values()):
            if self._unblock_range(entry.cidr, entry.fto):
                count += 1
        for entry in list(self.blocked_ips.values()):
            if self._unblock_specific(entry.cidr):
                count += 1
        return count
