#!/usr/bin/env python3
"""
FWSpoof - Network Attack Prevention Tool

Analyzes tcpdump packet captures to detect and block SYN flood
and SYN+RESET spoofing attacks on HTTP servers.

Usage:
    tcpdump -i eth0 -nn -s0 tcp and dst <server_ip> | python3 main.py [options]
    tcpdump -r capture.cap -nn -s0 | python3 main.py [options]
"""

import sys
import argparse
import atexit
import os
from typing import Optional, List

from fwspoof.config import Config, set_config, get_config
from fwspoof.parser import parse_line, is_allowed
from fwspoof.detector import AttackDetector
from fwspoof.blocker import IPBlocker
from fwspoof.stats import get_stats, Statistics
from fwspoof.logger import log, debug, info, warning, error


def load_allowed_ips(filepath: str = "allowed.ips") -> List[str]:
    """
    Load allowed IPs from file.
    
    Args:
        filepath: Path to allowed IPs file
        
    Returns:
        List of allowed IP addresses
    """
    allowed_ips: List[str] = []
    
    if not os.path.exists(filepath):
        debug(f"Allowed IPs file not found: {filepath}")
        return allowed_ips
    
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                # Basic validation - must look like an IP
                if '.' in line and len(line.split('.')) == 4:
                    allowed_ips.append(line)
                    debug(f"Loaded allowed IP: {line}")
                else:
                    warning(f"Skipping invalid IP in {filepath}:{line_num}: {line}")
        
        info(f"Loaded {len(allowed_ips)} allowed IPs from {filepath}")
        
    except IOError as e:
        warning(f"Could not read {filepath}: {e}")
    except Exception as e:
        error(f"Error loading allowed IPs: {e}")
    
    return allowed_ips


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='FWSpoof - Detect and block SYN flood attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tcpdump -r out.cap -nn -s0 | python3 main.py -S -m 2 -M 13 -D -C INPUT
  tcpdump -i eth0 -nn -s0 | python3 main.py -V -T
  
  Load allowed IPs from file:
  tcpdump -i eth0 -nn -s0 | python3 main.py --allowed-ips allowed.ips
        """
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    parser.add_argument(
        '-M', '--max-flag-count',
        type=int,
        default=20,
        help='Global threshold for SYN/SYN+RESET attacks (default: 20)'
    )
    
    parser.add_argument(
        '-m', '--max-flag-count-per-cidr',
        type=int,
        default=3,
        help='Per-range SYN threshold (default: 3)'
    )
    
    parser.add_argument(
        '-r', '--max-flag-count-per-cidr-sr',
        type=int,
        default=5,
        help='Per-range SYN+RESET threshold (default: 5)'
    )
    
    parser.add_argument(
        '-V', '--verbose',
        action='store_true',
        help='Enable verbose/debug output'
    )
    
    parser.add_argument(
        '-S', '--stats',
        action='store_true',
        help='Show statistics at exit'
    )
    
    parser.add_argument(
        '-F', '--flags',
        default='[S],[R]',
        help='TCP flags to monitor (default: [S],[R])'
    )
    
    parser.add_argument(
        '-C', '--con-type',
        default='FORWARD',
        choices=['INPUT', 'FORWARD', 'OUTPUT'],
        help='iptables chain to use (default: FORWARD)'
    )
    
    parser.add_argument(
        '-D', '--dont-unblock',
        action='store_true',
        help='Once blocked, stay blocked (no auto-unblock)'
    )
    
    parser.add_argument(
        '-T', '--test',
        action='store_true',
        help='Test mode - do not execute iptables commands'
    )
    
    parser.add_argument(
        '-s', '--specific-ip',
        action='store_true',
        help='Block specific IPs instead of ranges'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Configuration file path (default: config.yaml)'
    )
    
    parser.add_argument(
        '-a', '--allowed-ips',
        default='allowed.ips',
        help='Path to allowed IPs whitelist file (default: allowed.ips)'
    )

    parser.add_argument(
        '--no-comment',
        action='store_true',
        help='Disable iptables comment tagging'
    )
    
    parser.add_argument(
        '--comment-prefix',
        default=None,
        help='Prefix for iptables comment (default: fwspoof)'
    )
    
    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> Config:
    """Create Config object from parsed arguments."""
    # Try to load from YAML first
    config = Config.from_yaml(args.config)
    
    # Override with command line arguments
    config.max_flag_count = args.max_flag_count
    config.max_flag_count_per_cidr = args.max_flag_count_per_cidr
    config.max_flag_count_per_cidr_sr = args.max_flag_count_per_cidr_sr
    config.verbose = args.verbose
    config.show_stats = args.stats
    config.flags = args.flags
    config.connection_type = args.con_type
    config.dont_unblock = args.dont_unblock
    config.test_mode = args.test
    config.specific_ip = args.specific_ip
    if args.no_comment:
        config.iptables_comment = False
    if args.comment_prefix:
        config.iptables_comment_prefix = args.comment_prefix
    
    # Load allowed IPs from file
    config.allowed_ips = load_allowed_ips(args.allowed_ips)
    
    return config


def cleanup(detector: AttackDetector, blocker: IPBlocker) -> None:
    """Cleanup function called at exit."""
    stats = get_stats()
    
    # Check for ranges to unblock
    if not get_config().dont_unblock:
        suspects = detector.get_suspect_keys()
        to_unblock = blocker.check_unblock_needed(suspects)
        
        for entry in to_unblock:
            info(f"Unblocking {entry.cidr}")
            if blocker.unblock_cidr(entry.cidr, entry.fto):
                stats.record_unblock(is_range=True)
    
    # Sync currently blocked count with actual blocker state
    try:
        stats.blocked = blocker.get_blocked_count()
    except:
        pass

    # Print statistics if requested
    if get_config().show_stats:
        stats.print_summary()


def main() -> int:
    """Main entry point."""
    # Parse arguments and setup config
    args = parse_args()
    config = create_config_from_args(args)
    set_config(config)
    
    # Log startup info
    info("FWSpoof starting...")
    debug(f"Configuration: {config}")
    if config.allowed_ips:
        debug(f"Allowed IPs: {config.allowed_ips}")
    
    # Initialize components
    detector = AttackDetector()
    blocker = IPBlocker()
    
    # Load existing blocks
    blocker.load_existing_blocks()
    debug(f"Loaded {blocker.get_blocked_count()} existing blocks")
    
    # Register cleanup
    atexit.register(cleanup, detector, blocker)
    
    # Process packets from stdin
    stats = get_stats()
    skipped_allowed = 0
    
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            
            # Parse packet
            packet = parse_line(line)
            if packet is None:
                debug(f"Failed to parse: {line[:50]}...")
                continue
            
            # Check if source IP is in allowed list - skip if so (must be before stats, like old fwspoof.py:408)
            if is_allowed(packet, config.allowed_ips):
                skipped_allowed += 1
                if config.verbose and skipped_allowed <= 5:  # Limit verbose output
                    debug(f"Skipping allowed IP: {packet.sip}")
                continue

            stats.record_packet(packet)
            
            # Process packet in detector
            range_key = detector.process_packet(packet)
            if range_key is None:
                continue
            
            # Check for attack
            attack_info = detector.check_attack(range_key)
            if attack_info is None:
                continue
            
            # Handle blocking (AttackResult is a dataclass)
            info(f"Attack detected from {attack_info.fto}")
            
            for subnet in attack_info.subnets:
                if config.specific_ip:
                    # Block specific IP
                    if blocker.is_ip_blocked(subnet['sip']):
                        stats.record_block(is_range=False, is_new=False)
                    elif blocker.block_specific_ip(subnet['sip'], attack_info.fto, subnet['ftt']):
                        stats.record_block(is_range=False, is_new=True)
                        info(f"Blocked IP: {subnet['sip']}")
                else:
                    # Block CIDR range - pass correct fto and ftt
                    if blocker.is_blocked(subnet['cidr']):
                        stats.record_block(is_range=True, is_new=False)
                    elif blocker.block_cidr(subnet['cidr'], attack_info.fto, subnet['ftt']):
                        stats.record_block(is_range=True, is_new=True)
                        info(f"Blocked range: {subnet['cidr']}")
                    
        # Final check for any remaining blocks to process (replicates old check_suspect after all packets)
        for key in list(detector.ranges.keys()):
            attack_info = detector.check_attack(key)
            if attack_info:
                for subnet in attack_info.subnets:
                    if not config.specific_ip:
                        if blocker.is_blocked(subnet['cidr']):
                            continue
                        if blocker.block_cidr(subnet['cidr'], attack_info.fto, subnet['ftt']):
                            stats.record_block(is_range=True, is_new=True)
                        
    except KeyboardInterrupt:
        info("Interrupted by user")
    except BrokenPipeError:
        # Handle broken pipe gracefully (e.g., when piping to head)
        pass
    except Exception as e:
        error(f"Error: {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        if skipped_allowed > 0:
            debug(f"Total packets skipped (allowed IPs): {skipped_allowed}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
