"""
Unit tests cho classification
"""
import unittest
import pandas as pd
import numpy as np
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from classification.classification import extract_attack_type, extract_event_category


class TestClassification(unittest.TestCase):
    """Test cases cho classification patterns"""
    
    def test_brute_force_detection(self):
        """Test brute force pattern detection"""
        test_cases = [
            ("failed password for user", "brute_force"),
            ("authentication failure", "brute_force"),
            ("invalid user", "brute_force"),
            ("too many authentication failures", "brute_force"),
        ]
        
        for desc, expected in test_cases:
            result = extract_attack_type(desc)
            self.assertEqual(result, expected, f"Failed for: {desc}")
    
    def test_malware_detection(self):
        """Test malware pattern detection"""
        test_cases = [
            ("et malware win32 possible malware download", "malware"),
            ("et trojan possible c2 communication", "malware"),
            ("known malware ip", "malware"),
            ("suspicious inbound to mysql port 3306", "malware"),
        ]
        
        for desc, expected in test_cases:
            result = extract_attack_type(desc)
            self.assertEqual(result, expected, f"Failed for: {desc}")
    
    def test_port_scan_detection(self):
        """Test port scan pattern detection"""
        test_cases = [
            ("et scan suspicious inbound", "port_scan"),
            ("port scan detected", "port_scan"),
            ("nmap scan", "port_scan"),
            ("multiple connection attempts", "port_scan"),
        ]
        
        for desc, expected in test_cases:
            result = extract_attack_type(desc)
            self.assertEqual(result, expected, f"Failed for: {desc}")
    
    def test_event_category_detection(self):
        """Test event category detection"""
        test_cases = [
            ("sshd: authentication success", "authentication"),
            ("file modified", "file_integrity"),
            ("suricata alert", "network"),
        ]
        
        for desc, expected in test_cases:
            result = extract_event_category(desc)
            self.assertEqual(result, expected, f"Failed for: {desc}")

