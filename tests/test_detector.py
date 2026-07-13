"""Unit tests for attack detector."""

import unittest
from unittest.mock import patch, MagicMock

from fwspoof.detector import (
    AttackDetector, RangeStats, SubnetStats, IPStats,
    crc32_hash, AttackResult
)
from fwspoof.parser import Packet


# Synthetic test data
def create_syn_packet(sip, timestamp, sport="54321"):
    """Create a SYN packet."""
    octets = sip.split('.')
    fto = '.'.join(octets[:2])
    ftt = '.'.join(octets[:3])
    return Packet(
        timestamp=timestamp,
        source_ip=f"{sip}.{sport}",
        dest_ip="10.0.0.1.443",
        flags="[S]",
        fto=fto,
        ftt=ftt,
        sip=sip,
        sport=sport,
        dip="10.0.0.1",
        dport="443"
    )


def create_rst_packet(sip, timestamp, sport="54321"):
    """Create a RST packet."""
    octets = sip.split('.')
    fto = '.'.join(octets[:2])
    ftt = '.'.join(octets[:3])
    return Packet(
        timestamp=timestamp,
        source_ip=f"{sip}.{sport}",
        dest_ip="10.0.0.1.443",
        flags="[R]",
        fto=fto,
        ftt=ftt,
        sip=sip,
        sport=sport,
        dip="10.0.0.1",
        dport="443"
    )


def create_ack_packet(sip, timestamp, sport="54321"):
    """Create an ACK packet."""
    octets = sip.split('.')
    fto = '.'.join(octets[:2])
    ftt = '.'.join(octets[:3])
    return Packet(
        timestamp=timestamp,
        source_ip=f"{sip}.{sport}",
        dest_ip="10.0.0.1.443",
        flags="[.]",
        fto=fto,
        ftt=ftt,
        sip=sip,
        sport=sport,
        dip="10.0.0.1",
        dport="443"
    )


class TestCRC32Hash(unittest.TestCase):
    """Test CRC32 hashing functionality."""
    
    def test_crc32_hash_consistency(self):
        """Test that same input produces same hash."""
        hash1 = crc32_hash("192.168")
        hash2 = crc32_hash("192.168")
        self.assertEqual(hash1, hash2)
    
    def test_crc32_hash_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = crc32_hash("192.168")
        hash2 = crc32_hash("10.0")
        hash3 = crc32_hash("172.16")
        
        self.assertNotEqual(hash1, hash2)
        self.assertNotEqual(hash2, hash3)
        self.assertNotEqual(hash1, hash3)
    
    def test_crc32_hash_format(self):
        """Test hash is hexadecimal string."""
        hash_val = crc32_hash("192.168")
        self.assertIsInstance(hash_val, str)
        self.assertTrue(all(c in '0123456789abcdef' for c in hash_val))


class TestIPStats(unittest.TestCase):
    """Test IPStats dataclass."""
    
    def test_ip_stats_initialization(self):
        """Test IPStats initialization."""
        stats = IPStats(sip="192.168.1.1")
        self.assertEqual(stats.sip, "192.168.1.1")
        self.assertEqual(stats.count, 0)
        self.assertEqual(stats.count_sr, 0)
        self.assertEqual(len(stats.flags), 0)
    
    def test_ip_stats_add_flag(self):
        """Test adding flags."""
        stats = IPStats(sip="192.168.1.1")
        stats.add_flag("[S]", 1000.0)
        
        self.assertEqual(len(stats.flags), 1)
        self.assertEqual(stats.flags[0], "[S]")
        self.assertEqual(stats.last_timestamp, 1000.0)
    
    def test_ip_stats_flag_limit(self):
        """Test that flags list is limited to 4 entries."""
        stats = IPStats(sip="192.168.1.1")
        
        for i in range(10):
            stats.add_flag(f"[{i}]", float(i))
        
        self.assertEqual(len(stats.flags), 4)
        # Should have last 4 flags
        self.assertEqual(stats.flags, ["[6]", "[7]", "[8]", "[9]"])
    
    def test_ip_stats_syn_flood_detection(self):
        """Test SYN flood threshold detection."""
        stats = IPStats(sip="192.168.1.1")
        self.assertFalse(stats.is_syn_flood(threshold=5))
        
        stats.count = 5
        self.assertTrue(stats.is_syn_flood(threshold=5))
        self.assertFalse(stats.is_syn_flood(threshold=6))
    
    def test_ip_stats_sr_attack_detection(self):
        """Test SYN+RESET attack threshold detection."""
        stats = IPStats(sip="192.168.1.1")
        self.assertFalse(stats.is_syn_reset_attack(threshold=3))
        
        stats.count_sr = 3
        self.assertTrue(stats.is_syn_reset_attack(threshold=3))


class TestAttackDetectorInitialization(unittest.TestCase):
    """Test detector initialization."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 20
        self.config_mock.max_flag_count_per_cidr = 3
        self.config_mock.max_flag_count_per_cidr_sr = 5
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
    
    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            detector = AttackDetector()
            
            self.assertEqual(len(detector.ranges), 0)
            self.assertEqual(len(detector.suspects), 0)
            self.assertEqual(len(detector.blocked_ips), 0)
    
    def test_detector_with_custom_config(self):
        """Test detector with custom config."""
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            detector = AttackDetector(config=self.config_mock)
            self.assertEqual(detector.config, self.config_mock)


class TestSYNFloodDetection(unittest.TestCase):
    """Test SYN flood attack detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 5
        self.config_mock.max_flag_count_per_cidr = 3
        self.config_mock.max_flag_count_per_cidr_sr = 5
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
        
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            self.detector = AttackDetector()
    
    def test_single_syn_no_attack(self):
        """Test single SYN doesn't trigger detection."""
        packet = create_syn_packet("192.168.1.1", 1000.0)
        result = self.detector.process_packet(packet)
        
        # First packet creates range but doesn't trigger
        self.assertIsNone(result)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNone(attack)
    
    def test_syn_flood_threshold_exact(self):
        """Test SYN flood at exact threshold."""
        # Send exactly threshold number of SYNs
        for i in range(3):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNotNone(attack)
        self.assertEqual(attack['fto'], "192.168")
    
    def test_syn_flood_below_threshold(self):
        """Test below threshold doesn't trigger."""
        for i in range(2):  # One less than threshold
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNone(attack)
    
    def test_syn_flood_multiple_ranges(self):
        """Test SYN flood in multiple ranges."""
        # Range 1
        for i in range(3):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        # Range 2
        for i in range(3):
            packet = create_syn_packet(f"10.0.0.{100+i}", 2000.0 + i)
            self.detector.process_packet(packet)
        
        attack1 = self.detector.check_attack(crc32_hash("192.168"))
        attack2 = self.detector.check_attack(crc32_hash("10.0"))
        
        self.assertIsNotNone(attack1)
        self.assertIsNotNone(attack2)
    
    def test_syn_flood_same_ip_multiple_times(self):
        """Test same IP sending multiple SYNs."""
        # Same IP, multiple SYNs
        for i in range(5):
            packet = create_syn_packet("192.168.1.100", 1000.0 + i)
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNotNone(attack)
        
        # Should have one subnet entry
        self.assertEqual(len(attack['subnets']), 1)
        self.assertEqual(attack['subnets'][0]['sip'], "192.168.1.100")


class TestSYNResetDetection(unittest.TestCase):
    """Test SYN+RESET attack detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 20
        self.config_mock.max_flag_count_per_cidr = 3
        self.config_mock.max_flag_count_per_cidr_sr = 3
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
        
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            self.detector = AttackDetector()
    
    def test_syn_reset_pattern(self):
        """Test SYN+RESET pattern detection."""
        # Create SYN-RESET-SYN-RESET pattern
        packets = [
            create_syn_packet("192.168.1.1", 1000.0),
            create_rst_packet("192.168.1.2", 1001.0),
            create_syn_packet("192.168.1.3", 1002.0),
            create_rst_packet("192.168.1.4", 1003.0),
        ]
        
        for packet in packets:
            self.detector.process_packet(packet)
        
        key = crc32_hash("192.168")
        stats = self.detector.ranges[key]
        
        # Should have SR count > 0
        self.assertGreater(stats.flag_count_sr, 0)
    
    def test_syn_reset_threshold(self):
        """Test SYN+RESET threshold triggering."""
        # Create pattern: S-R-S-R-S-R
        for i in range(6):
            if i % 2 == 0:
                packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            else:
                packet = create_rst_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNotNone(attack)
    
    def test_non_alternating_pattern(self):
        """Test that non-alternating patterns don't count."""
        # S-S-S-R-R-R (not alternating)
        for i in range(3):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        for i in range(3):
            packet = create_rst_packet(f"192.168.1.{103+i}", 1003.0 + i)
            self.detector.process_packet(packet)
        
        key = crc32_hash("192.168")
        stats = self.detector.ranges[key]
        
        # SR count should be low (only 1 transition)
        self.assertLess(stats.flag_count_sr, 3)
    
    def test_mixed_syn_and_reset(self):
        """Test mixed SYN and RESET from same range."""
        packets = [
            create_syn_packet("192.168.1.1", 1000.0),
            create_syn_packet("192.168.1.2", 1001.0),
            create_rst_packet("192.168.1.3", 1002.0),
            create_syn_packet("192.168.1.4", 1003.0),
            create_rst_packet("192.168.1.5", 1004.0),
        ]
        
        for packet in packets:
            self.detector.process_packet(packet)
        
        key = crc32_hash("192.168")
        stats = self.detector.ranges[key]
        
        # Should have both SYN and SR counts
        self.assertGreater(stats.flag_count, 0)
        self.assertGreater(stats.flag_count_sr, 0)


class TestSpecificIPBlocking(unittest.TestCase):
    """Test specific IP blocking mode."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 20
        self.config_mock.max_flag_count_per_cidr = 2
        self.config_mock.max_flag_count_per_cidr_sr = 2
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
        
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            self.detector = AttackDetector()
    
    def test_specific_ip_attack_detection(self):
        """Test specific IP attack detection."""
        # Single IP sending multiple SYNs
        for i in range(3):
            packet = create_syn_packet("192.168.1.100", 1000.0 + i)
            self.detector.process_packet(packet)
        
        result = self.detector.check_specific_ip_attack("192.168.1.100", "192.168.1")
        
        self.assertIsNotNone(result)
        self.assertEqual(result['sip'], "192.168.1.100")
        self.assertGreaterEqual(result['syn_count'], 2)
    
    def test_specific_ip_no_attack(self):
        """Test specific IP below threshold."""
        packet = create_syn_packet("192.168.1.100", 1000.0)
        self.detector.process_packet(packet)
        
        result = self.detector.check_specific_ip_attack("192.168.1.100", "192.168.1")
        self.assertIsNone(result)
    
    def test_specific_ip_wrong_subnet(self):
        """Test specific IP in wrong subnet."""
        packet = create_syn_packet("192.168.1.100", 1000.0)
        self.detector.process_packet(packet)
        
        # Check with wrong subnet
        result = self.detector.check_specific_ip_attack("192.168.1.100", "10.0.0")
        self.assertIsNone(result)


class TestDetectorStateManagement(unittest.TestCase):
    """Test detector state management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 20
        self.config_mock.max_flag_count_per_cidr = 3
        self.config_mock.max_flag_count_per_cidr_sr = 5
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
        
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            self.detector = AttackDetector()
    
    def test_get_suspect_keys(self):
        """Test getting suspect keys."""
        # Initially empty
        self.assertEqual(len(self.detector.get_suspect_keys()), 0)
        
        # Add some suspects
        for i in range(3):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        self.detector.check_attack(crc32_hash("192.168"))
        self.assertGreater(len(self.detector.get_suspect_keys()), 0)
    
    def test_clear_suspect(self):
        """Test clearing suspect."""
        for i in range(3):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        key = crc32_hash("192.168")
        self.detector.check_attack(key)
        
        self.assertIn(key, self.detector.suspects)
        
        self.detector.clear_suspect(key)
        self.assertNotIn(key, self.detector.suspects)
    
    def test_blocked_ip_tracking(self):
        """Test blocked IP tracking."""
        self.assertFalse(self.detector.is_blocked("192.168.1.1"))
        
        self.detector.add_blocked_ip("192.168.1.1")
        
        self.assertTrue(self.detector.is_blocked("192.168.1.1"))
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        # Add some data
        for i in range(5):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        stats = self.detector.get_stats()
        
        self.assertIn('total_ranges', stats)
        self.assertIn('suspects', stats)
        self.assertIn('unique_ips', stats)
        self.assertEqual(stats['total_ranges'], 1)
    
    def test_reset(self):
        """Test detector reset."""
        for i in range(5):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        self.assertGreater(len(self.detector.ranges), 0)
        
        self.detector.reset()
        
        self.assertEqual(len(self.detector.ranges), 0)
        self.assertEqual(len(self.detector.suspects), 0)
        self.assertEqual(len(self.detector.blocked_ips), 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_mock = MagicMock()
        self.config_mock.max_flag_count = 3
        self.config_mock.max_flag_count_per_cidr = 2
        self.config_mock.max_flag_count_per_cidr_sr = 2
        self.config_mock.flag_list = ["[S]", "[R]"]
        self.config_mock.dont_unblock = False
        
        with patch('fwspoof.detector.get_config', return_value=self.config_mock):
            self.detector = AttackDetector()
    
    def test_empty_detector(self):
        """Test operations on empty detector."""
        attack = self.detector.check_attack("nonexistent_key")
        self.assertIsNone(attack)
        
        stats = self.detector.get_stats()
        self.assertEqual(stats['total_ranges'], 0)
    
    def test_threshold_boundary(self):
        """Test exact threshold boundary."""
        # Exactly at threshold
        for i in range(2):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0 + i)
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNotNone(attack)
    
    def test_rapid_packets_same_timestamp(self):
        """Test multiple packets with same timestamp."""
        for i in range(5):
            packet = create_syn_packet(f"192.168.1.{100+i}", 1000.0)  # Same timestamp
            self.detector.process_packet(packet)
        
        attack = self.detector.check_attack(crc32_hash("192.168"))
        self.assertIsNotNone(attack)
    
    def test_concurrent_ranges(self):
        """Test many concurrent ranges."""
        for i in range(100):
            packet = create_syn_packet(f"192.{i % 256}.1.100", float(i))
            self.detector.process_packet(packet)
        
        stats = self.detector.get_stats()
        self.assertGreater(stats['total_ranges'], 1)


if __name__ == '__main__':
    unittest.main()
