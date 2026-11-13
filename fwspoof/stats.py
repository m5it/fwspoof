"""Statistics collection for FWSpoof."""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from collections import defaultdict

from .logger import info, debug


@dataclass
class Statistics:
    """
    Tracks various statistics during execution.
    
    Attributes:
        all_packets: Total packets processed
        unique_ips: Unique source IPs seen
        single_blocking: Single IPs blocked
        single_already: Single IPs already blocked (duplicate)
        range_blocking: Range blocks performed
        range_unblocking: Range unblocks performed
        blocked: Currently blocked count
        start_time: Execution start timestamp
        packets_by_flag: Count of packets by flag type
        top_attackers: Top attacking IPs by packet count
    """
    
    # Core counters
    all_packets: int = 0
    unique_ips: int = 0
    single_blocking: int = 0
    single_already: int = 0
    range_blocking: int = 0
    range_unblocking: int = 0
    blocked: int = 0
    
    # Timing
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    
    # Detailed tracking
    packets_by_flag: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    unique_ip_set: set = field(default_factory=set, repr=False)
    top_attackers: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def __post_init__(self):
        if not self.start_time:
            self.start_time = time.time()
    
    def increment(self, stat_name: str, count: int = 1) -> None:
        """
        Increment a statistic by name.
        
        Args:
            stat_name: Name of the statistic to increment
            count: Amount to increment by (default: 1)
        """
        if hasattr(self, stat_name) and isinstance(getattr(self, stat_name), int):
            current = getattr(self, stat_name)
            setattr(self, stat_name, current + count)
    
    def record_packet(self, packet: Any) -> None:
        """
        Record a packet in statistics.
        
        Args:
            packet: Packet object with flags attribute
        """
        self.all_packets += 1
        
        # Track unique IPs
        if hasattr(packet, 'sip'):
            if packet.sip not in self.unique_ip_set:
                self.unique_ip_set.add(packet.sip)
                self.unique_ips = len(self.unique_ip_set)
            
            # Track top attackers
            self.top_attackers[packet.sip] += 1
        
        # Track by flag
        if hasattr(packet, 'flags'):
            self.packets_by_flag[packet.flags] += 1
    
    def record_block(self, is_range: bool = True, is_new: bool = True) -> None:
        """
        Record a block action.
        
        Args:
            is_range: True for range block, False for specific IP
            is_new: True if new block, False if already blocked
        """
        if is_range:
            if is_new:
                self.range_blocking += 1
                self.blocked += 1
            else:
                self.single_already += 1  # Actually range_already but using same counter
        else:
            if is_new:
                self.single_blocking += 1
                self.blocked += 1
            else:
                self.single_already += 1
    
    def record_unblock(self, is_range: bool = True) -> None:
        """
        Record an unblock action.
        
        Args:
            is_range: True for range unblock, False for specific IP
        """
        if is_range:
            self.range_unblocking += 1
        # Note: single unblocking not tracked separately
        
        self.blocked = max(0, self.blocked - 1)
    
    def finalize(self) -> None:
        """Finalize statistics collection."""
        self.end_time = time.time()
    
    @property
    def duration(self) -> float:
        """Get execution duration in seconds."""
        end = self.end_time or time.time()
        return end - self.start_time
    
    @property
    def packets_per_second(self) -> float:
        """Calculate packets per second."""
        dur = self.duration
        return self.all_packets / dur if dur > 0 else 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of all statistics.
        
        Returns:
            Dictionary with all statistics
        """
        return {
            'all_packets': self.all_packets,
            'unique_ips': self.unique_ips,
            'single_blocking': self.single_blocking,
            'single_already': self.single_already,
            'range_blocking': self.range_blocking,
            'range_unblocking': self.range_unblocking,
            'blocked': self.blocked,
            'duration_seconds': round(self.duration, 2),
            'packets_per_second': round(self.packets_per_second, 2),
            'packets_by_flag': dict(self.packets_by_flag),
            'top_attackers': dict(sorted(
                self.top_attackers.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])  # Top 10
        }
    
    def print_summary(self) -> None:
        """Print formatted statistics summary to stdout."""
        self.finalize()
        summary = self.get_summary()
        
        # Build output lines
        lines = [
            "",
            "=" * 60,
            "                    FWSpoof Statistics",
            "=" * 60,
            f"  Execution Time:     {summary['duration_seconds']:.2f} seconds",
            f"  Packets/sec:        {summary['packets_per_second']:.2f}",
            "",
            "  Packet Processing:",
            f"    Total Packets:    {summary['all_packets']:,}",
            f"    Unique Sources:   {summary['unique_ips']:,}",
            "",
            "  Blocking Actions:",
            f"    Range Blocks:     {summary['range_blocking']}",
            f"    Single IP Blocks: {summary['single_blocking']}",
            f"    Already Blocked:  {summary['single_already']}",
            f"    Unblocks:         {summary['range_unblocking']}",
            f"    Currently Blocked: {summary['blocked']}",
            "=" * 60,
        ]
        
        # Add flag breakdown if verbose
        if self.packets_by_flag:
            lines.extend([
                "",
                "  Packets by Flag:",
            ])
            for flag, count in sorted(self.packets_by_flag.items()):
                lines.append(f"    {flag:15} {count:,}")
        
        # Add top IPs if any (renamed from Top Attackers - attacker definition is S-only or S,R alternating per fwspoof logic)
        if self.top_attackers:
            lines.extend([
                "",
                "  Top IP by packets:",
            ])
            for ip, count in list(sorted(
                self.top_attackers.items(),
                key=lambda x: x[1],
                reverse=True
            ))[:5]:
                lines.append(f"    {ip:20} {count:,} packets")
        
        lines.append("=" * 60)
        
        # Print to stdout (not stderr)
        print('\n'.join(lines))
    
    def log_summary(self) -> None:
        """Log summary using the logging system."""
        self.finalize()
        info("Statistics Summary:")
        info(f"  Packets processed: {self.all_packets}")
        info(f"  Unique IPs: {self.unique_ips}")
        info(f"  Duration: {self.duration:.2f}s")
        info(f"  Rate: {self.packets_per_second:.2f} pkt/s")


# Global statistics instance
_stats: Optional[Statistics] = None


def get_stats() -> Statistics:
    """Get or create global statistics instance."""
    global _stats
    if _stats is None:
        _stats = Statistics()
    return _stats


def reset_stats() -> None:
    """Reset all statistics."""
    global _stats
    _stats = Statistics()


def init_stats() -> Statistics:
    """Initialize fresh statistics."""
    reset_stats()
    return get_stats()


# Convenience functions for common operations
def record_packet(packet: Any) -> None:
    """Record a packet in global stats."""
    get_stats().record_packet(packet)


def record_block(is_range: bool = True, is_new: bool = True) -> None:
    """Record a block in global stats."""
    get_stats().record_block(is_range, is_new)


def record_unblock(is_range: bool = True) -> None:
    """Record an unblock in global stats."""
    get_stats().record_unblock(is_range)


def increment(stat_name: str, count: int = 1) -> None:
    """Increment a statistic."""
    get_stats().increment(stat_name, count)
