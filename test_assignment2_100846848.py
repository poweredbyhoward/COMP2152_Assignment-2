"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest
from assignment2_100846848 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        ps = PortScanner("127.0.0.1")
        self.assertEqual("127.0.0.1", ps.target , "Should be 127.0.0.1")
        self.assertEqual([], ps.scan_results,"Should be empty list []")

    def test_get_open_ports_filters_correctly(self):
        ps = PortScanner("127.0.0.1")
        ps.scan_results.extend([(22, "Open", "SSH"), (23, "Closed", "Telnet"), (80, "Open", "HTTP")])
        result = len(ps.get_open_ports())
        self.assertEqual(2, result, "Should return 2 items")

    def test_common_ports_dict(self):
        self.assertEqual("HTTP", common_ports[80])
        self.assertEqual("SSH", common_ports[22])

    def test_invalid_target(self):
        ps = PortScanner("127.0.0.1")
        ps.target = ""
        self.assertEqual("127.0.0.1", ps.target, "Should remain 127.0.0.1")

if __name__ == "__main__":
    unittest.main()
