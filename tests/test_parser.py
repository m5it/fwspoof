"""Unit tests for packet parser."""

import unittest
from fwspoof.parser import (
    parse_line, parse_timestamp, extract_ip_port, is_allowed,
    validate_ip, calculate_octets, TCPFlag, Packet, parse_lines,
    get_packet_summary
)


# Mock tcpdump data for testing
MOCK_TCPDUMP_LINES = [
    # Standard SYN packet
    "14:50:53.440085 IP 192.168.1.100.54321 > 10.0.0.1.443: Flags [S], seq 12345, win 64240, length 0",
    # SYN-ACK packet
    "14:50:53.441000 IP 10.0.0.1.443 > 192.168.1.100.54321: Flags [S.], seq 67890, ack 12346, win 65535, length 0",
    # RST packet
    "14:50:54.123456 IP 10.0.0.50.12345 > 192.168.1.1.80: Flags [R], seq 0, win 0, length 0",
    # ACK packet
    "14:50:55.000001 IP 192.168.1.100.54321 > 10.0.0.1.443: Flags [.], ack 1, win 64240, length 0",
    # Packet with options
    "14:50:56.123456 IP 192.168.1.200.12345 > 10.0.0.2.80: Flags [S], seq 12345, win 64240, options [mss 1460,sackOK,TS val 12345 ecr 0,nop,wscale 7], length 0",
    # Different timestamp format edge case
    "00:00:00.000001 IP 10.0.0.1.12345 > 192.168.1.1.80: Flags [S], length 0",
    # High port numbers
    "23:59:59.999999 IP 192.168.255.255.65535 > 10.255.255.255.65535: Flags [S], length 0",
]


class TestTimestampParsing(unittest.TestCase):
    """Test timestamp parsing functionality."""
    
    def test_parse_timestamp_standard(self):
        """Test standard timestamp parsing."""
        self.assertAlmostEqual(parse_timestamp("14:50:53.440085"), 53453.440085, places=5)
        self.assertAlmostEqual(parse_timestamp("00:00:00.000001"), 0.000001, places=6)
        self.assertAlmostEqual(parse_timestamp("23:59:59.999999"), 86399.999999, places=5)
    
    def test_parse_timestamp_midnight(self):
        """Test midnight timestamp."""
        self.assertEqual(parse_timestamp("00:00:00.000000"), 0.0)
    
    def test_parse_timestamp_noon(self):
        """Test noon timestamp."""
        self.assertAlmostEqual(parse_timestamp("12:00:00.000000"), 43200.0, places=5)
    
    def test_parse_timestamp_invalid(self):
        """Test timestamp parsing with invalid input."""
        self.assertEqual(parse_timestamp("invalid"), 0.0)
        self.assertEqual(parse_timestamp(""), 0.0)
        self.assertEqual(parse_timestamp(None), 0.0)  # type: ignore
        self.assertEqual(parse_timestamp("25:00:00.000000"), 0.0)  # Invalid hour
        self.assertEqual(parse_timestamp("12:60:00.000000"), 0.0)  # Invalid minute
        self.assertEqual(parse_timestamp("12:30"), 0.0)  # Missing seconds
    
    def test_parse_timestamp_microsecond_precision(self):
        """Test microsecond precision handling."""
        # Various microsecond lengths
        self.assertAlmostEqual(parse_timestamp("12:00:00.1"), 43200.1, places=1)
        self.assertAlmostEqual(parse_timestamp("12:00:00.12"), 43200.12, places=2)
        self.assertAlmostEqual(parse_timestamp("12:00:00.123"), 43200.123, places=3)
        self.assertAlmostEqual(parse_timestamp("12:00:00.1234567"), 43200.123456, places=6)


class TestIPExtraction(unittest.TestCase):
    """Test IP and port extraction."""
    
    def test_extract_ip_port_tcpdump_format(self):
        """Test IP extraction from tcpdump format (dot-separated port)."""
        ip, port = extract_ip_port("192.168.1.1.443")
        self.assertEqual(ip, "192.168.1.1")
        self.assertEqual(port, "443")
        
        ip, port = extract_ip_port("10.0.0.1.80")
        self.assertEqual(ip, "10.0.0.1")
        self.assertEqual(port, "80")
        
        # High port number
        ip, port = extract_ip_port("192.168.1.1.65535")
        self.assertEqual(ip, "192.168.1.1")
        self.assertEqual(port, "65535")
    
    def test_extract_ip_port_colon_format(self):
        """Test IP extraction from colon format."""
        ip, port = extract_ip_port("192.168.1.1:443")
        self.assertEqual(ip, "192.168.1.1")
        self.assertEqual(port, "443")
        
        ip, port = extract_ip_port("10.0.0.1:22")
        self.assertEqual(ip, "10.0.0.1")
        self.assertEqual(port, "22")
    
    def test_extract_ip_port_no_port(self):
        """Test IP extraction without port."""
        ip, port = extract_ip_port("192.168.1.1")
        self.assertEqual(ip, "192.168.1.1")
        self.assertIsNone(port)
    
    def test_extract_ip_port_ipv6_colon(self):
        """Test handling of IPv6-like addresses (should fail gracefully)."""
        # IPv6 format should return as-is without port
        ip, port = extract_ip_port("2001:db8::1")
        self.assertEqual(ip, "2001:db8::1")
        # Port extraction depends on implementation
    
    def test_extract_ip_port_edge_cases(self):
        """Test edge cases."""
        # Empty string
        ip, port = extract_ip_port("")
        self.assertEqual(ip, "")
        self.assertIsNone(port)
        
        # Just a port number (invalid but should handle gracefully)
        ip, port = extract_ip_port("443")
        self.assertEqual(ip, "443")
        self.assertIsNone(port)


class TestIPValidation(unittest.TestCase):
    """Test IP address validation."""
    
    def test_validate_ip_valid(self):
        """Test valid IPv4 addresses."""
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("255.255.255.255"))
        self.assertTrue(validate_ip("0.0.0.0"))
    
    def test_validate_ip_invalid(self):
        """Test invalid IPv4 addresses."""
        self.assertFalse(validate_ip("256.1.1.1"))  # Out of range
        self.assertFalse(validate_ip("192.168.1"))   # Missing octet
        self.assertFalse(validate_ip("192.168.1.1.1"))  # Extra octet
        self.assertFalse(validate_ip("192.168.1.a"))  # Non-numeric
        self.assertFalse(validate_ip(""))  # Empty
        self.assertFalse(validate_ip("not.an.ip.addr"))  # Non-numeric
    
    def test_validate_ip_edge_cases(self):
        """Test edge cases."""
        self.assertFalse(validate_ip("192.168.-1.1"))  # Negative
        self.assertFalse(validate_ip(" 192.168.1.1 "))  # With spaces (should fail)


class TestOctetCalculation(unittest.TestCase):
    """Test octet calculations."""
    
    def test_calculate_octets_standard(self):
        """Test standard octet calculation."""
        fto, ftt = calculate_octets("192.168.1.100")
        self.assertEqual(fto, "192.168")
        self.assertEqual(ftt, "192.168.1")
    
    def test_calculate_octets_different_ranges(self):
        """Test different IP ranges."""
        fto, ftt = calculate_octets("10.0.0.1")
        self.assertEqual(fto, "10.0")
        self.assertEqual(ftt, "10.0.0")
        
        fto, ftt = calculate_octets("172.16.255.255")
        self.assertEqual(fto, "172.16")
        self.assertEqual(ftt, "172.16.255")
    
    def test_calculate_octets_invalid(self):
        """Test invalid IP handling."""
        fto, ftt = calculate_octets("invalid")
        self.assertIsNone(fto)
        self.assertIsNone(ftt)


class TestPacketParsing(unittest.TestCase):
    """Test packet line parsing."""
    
    def test_parse_line_valid_syn(self):
        """Test parsing a valid SYN packet line."""
        line = MOCK_TCPDUMP_LINES[0]
        packet = parse_line(line)
        
        self.assertIsNotNone(packet)
        self.assertAlmostEqual(packet.timestamp, 53453.440085, places=5)
        self.assertEqual(packet.source_ip, "192.168.1.100.54321")
        self.assertEqual(packet.dest_ip, "10.0.0.1.443")
        self.assertEqual(packet.flags, "[S]")
        self.assertEqual(packet.fto, "192.168")
        self.assertEqual(packet.ftt, "192.168.1")
        self.assertEqual(packet.sip, "192.168.1.100")
        self.assertEqual(packet.sport, "54321")
    
    def test_parse_line_valid_reset(self):
        """Test parsing a valid RST packet line."""
        line = MOCK_TCPDUMP_LINES[2]
        packet = parse_line(line)
        
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags, "[R]")
        self.assertEqual(packet.fto, "10.0")
        self.assertEqual(packet.ftt, "10.0.0")
        self.assertEqual(packet.sip, "10.0.0.50")
    
    def test_parse_line_syn_ack(self):
        """Test parsing SYN-ACK packet."""
        line = MOCK_TCPDUMP_LINES[1]
        packet = parse_line(line)
        
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags, "[S.]")
    
    def test_parse_line_with_options(self):
        """Test parsing packet with TCP options."""
        line = MOCK_TCPDUMP_LINES[4]
        packet = parse_line(line)
        
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags, "[S]")
        self.assertEqual(packet.sip, "192.168.1.200")
    
    def test_parse_line_empty(self):
        """Test parsing empty line."""
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   "))
        self.assertIsNone(parse_line("\n"))
    
    def test_parse_line_too_short(self):
        """Test parsing line with too few fields."""
        self.assertIsNone(parse_line("14:50:53 IP 192.168.1.1"))
        self.assertIsNone(parse_line("just some text"))
    
    def test_parse_line_no_ip_keyword(self):
        """Test parsing line without IP keyword."""
        line = "14:50:53.440085 192.168.1.1.443 > 10.0.0.1.80: Flags [S]"
        self.assertIsNone(parse_line(line))
    
    def test_parse_line_no_flags(self):
        """Test parsing line without flags."""
        line = "14:50:53.440085 IP 192.168.1.1.80 > 10.0.0.1.443: length 0"
        packet = parse_line(line)
        
        # Should still parse but with empty flags
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags, "")
    
    def test_parse_line_malformed_ip(self):
        """Test parsing line with malformed IP."""
        line = "14:50:53.440085 IP not.an.ip.addr.443 > 10.0.0.1.80: Flags [S]"
        self.assertIsNone(parse_line(line))
    
    def test_parse_lines_batch(self):
        """Test batch parsing."""
        packets = parse_lines(MOCK_TCPDUMP_LINES[:4])
        self.assertEqual(len(packets), 4)
        
        # Check all packets parsed correctly
        for packet in packets:
            self.assertIsNotNone(packet)
            self.assertIsNotNone(packet.sip)
    
    def test_get_packet_summary(self):
        """Test packet summary generation."""
        line = MOCK_TCPDUMP_LINES[0]
        packet = parse_line(line)
        
        summary = get_packet_summary(packet)
        self.assertIn("192.168.1.100", summary)
        self.assertIn("[S]", summary)


class TestTCPFlag(unittest.TestCase):
    """Test TCPFlag enum."""
    
    def test_tcp_flag_from_string(self):
        """Test parsing flags from strings."""
        self.assertEqual(TCPFlag.from_string("[S]"), TCPFlag.SYN)
        self.assertEqual(TCPFlag.from_string("[R]"), TCPFlag.RST)
        self.assertEqual(TCPFlag.from_string("[S.]"), TCPFlag.SYN_ACK)
        self.assertIsNone(TCPFlag.from_string("[X]"))  # Unknown flag
    
    def test_tcp_flag_properties(self):
        """Test packet flag properties."""
        syn_packet = parse_line(MOCK_TCPDUMP_LINES[0])
        self.assertTrue(syn_packet.has_syn)
        self.assertFalse(syn_packet.has_rst)
        
        rst_packet = parse_line(MOCK_TCPDUMP_LINES[2])
        self.assertFalse(rst_packet.has_syn)
        self.assertTrue(rst_packet.has_rst)


class TestIsAllowed(unittest.TestCase):
    """Test allowed IP checking."""
    
    def setUp(self):
        """Create test packet."""
        self.packet = Packet(
            timestamp=0.0,
            source_ip="192.168.1.1.80",
            dest_ip="10.0.0.1.443",
            flags="[S]",
            fto="192.168",
            ftt="192.168.1",
            sip="192.168.1.1"
        )
    
    def test_is_allowed_true(self):
        """Test IP in allowed list."""
        self.assertTrue(is_allowed(self.packet, ["192.168.1.1", "10.0.0.1"]))
    
    def test_is_allowed_false(self):
        """Test IP not in allowed list."""
        self.assertFalse(is_allowed(self.packet, ["10.0.0.1"]))
        self.assertFalse(is_allowed(self.packet, []))
    
    def test_is_allowed_empty_list(self):
        """Test with empty allowed list."""
        self.assertFalse(is_allowed(self.packet, []))
    
    def test_is_allowed_partial_match(self):
        """Test partial IP match (should not match)."""
        self.assertFalse(is_allowed(self.packet, ["192.168.1"]))
        self.assertFalse(is_allowed(self.packet, ["192.168"]))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def test_boundary_timestamps(self):
        """Test boundary timestamp values."""
        # Midnight boundary
        packet = parse_line("00:00:00.000000 IP 192.168.1.1.80 > 10.0.0.1.443: Flags [S]")
        self.assertEqual(packet.timestamp, 0.0)
        
        # Just before midnight
        packet = parse_line("23:59:59.999999 IP 192.168.1.1.80 > 10.0.0.1.443: Flags [S]")
        self.assertAlmostEqual(packet.timestamp, 86399.999999, places=5)
    
    def test_very_long_line(self):
        """Test parsing very long lines."""
        long_options = "options [" + ",".join([f"opt{i}" for i in range(100)]) + "]"
        line = f"14:50:53.440085 IP 192.168.1.1.80 > 10.0.0.1.443: Flags [S], {long_options}, length 0"
        packet = parse_line(line)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags, "[S]")
    
    def test_unicode_in_line(self):
        """Test handling of unicode characters."""
        # This might fail depending on implementation, but shouldn't crash
        line = "14:50:53.440085 IP 192.168.1.1.80 > 10.0.0.1.443: Flags [S], window ∞"
        packet = parse_line(line)
        # Should either parse or return None, not crash
        self.assertTrue(packet is None or packet.flags == "[S]")


if __name__ == '__main__':
    unittest.main()
