#!/usr/bin/env python3
"""
Unit tests for privilege escalation detectors
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import PrivilegeEscalationDetector


class TestPrivilegeEscalationDetector(unittest.TestCase):
    """Test privilege escalation detection functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.detector = PrivilegeEscalationDetector()
    
    def test_config_loading(self):
        """Test configuration file loading"""
        self.assertIsNotNone(self.detector.config)
        self.assertIn('detection', self.detector.config)
        self.assertTrue(self.detector.config['detection']['enabled'])
    
    def test_patterns_initialization(self):
        """Test pattern initialization"""
        patterns = self.detector.suspicious_patterns
        self.assertEqual(len(patterns), 13)
        
        # Verify all techniques are present
        techniques = ['T1548', 'T1134', 'T1547', 'T1543', 'T1556', 'T1068', 
                     'T1574', 'T1070', 'T1547.014', 'T1574.008', 'T1053', 
                     'T1543.003', 'T1548.003']
        for tech in techniques:
            self.assertIn(tech, patterns)
    
    def test_pattern_matching_sudo(self):
        """Test pattern matching for sudo abuse"""
        test_cases = [
            ("sudo -u root /bin/bash", 'T1548', True),
            ("sudo -l", 'T1548.003', True),
            ("/usr/bin/id", 'T1548', False),
        ]
        
        for text, technique, expected in test_cases:
            result = self.detector._check_pattern(text, technique)
            self.assertEqual(result, expected, 
                           f"Pattern matching failed for {text} with {technique}")
    
    def test_pattern_matching_impersonation(self):
        """Test pattern matching for user impersonation"""
        test_cases = [
            ("su - root", 'T1070', True),
            ("sudo -u nobody id", 'T1070', True),
            ("/usr/bin/whoami", 'T1070', False),
        ]
        
        for text, technique, expected in test_cases:
            result = self.detector._check_pattern(text, technique)
            self.assertEqual(result, expected)
    
    def test_pattern_matching_library_hijacking(self):
        """Test pattern matching for library hijacking"""
        test_cases = [
            ("LD_PRELOAD=/tmp/lib.so ./app", 'T1574', True),
            ("LD_LIBRARY_PATH=/tmp ./app", 'T1574', True),
            ("./normal_app", 'T1574', False),
        ]
        
        for text, technique, expected in test_cases:
            result = self.detector._check_pattern(text, technique)
            self.assertEqual(result, expected)
    
    def test_detection_storage(self):
        """Test detection event storage"""
        self.detector._alert('T1548', 'Test sudo abuse', 1234, 0)
        
        self.assertIn('T1548', self.detector.detections)
        self.assertEqual(len(self.detector.detections['T1548']), 1)
        self.assertEqual(self.detector.detections['T1548'][0]['pid'], 1234)
    
    def test_technique_coverage(self):
        """Test coverage of all 13 techniques"""
        expected_techniques = {
            'T1548': 'Abuse Elevation Control Mechanism',
            'T1134': 'Access Token Manipulation',
            'T1547': 'Boot or Logon Autostart Execution',
            'T1543': 'Create or Modify System Process',
            'T1556': 'Modify Authentication Process',
            'T1068': 'Exploitation for Privilege Escalation',
            'T1574': 'Hijack Execution Flow',
            'T1070': 'Impersonate User/Process',
            'T1547.014': 'Modify Authentication Process (API Hooking)',
            'T1574.008': 'Library Search Order Hijacking',
            'T1053': 'Scheduled Task/Job',
            'T1543.003': 'Create or Modify System Process (Service)',
            'T1548.003': 'Sudo and Sudo Caching',
        }
        
        for technique, name in expected_techniques.items():
            self.assertIn(technique, self.detector.suspicious_patterns)
            self.assertEqual(self.detector.suspicious_patterns[technique]['name'], name)
    
    def test_baseline_creation(self):
        """Test baseline system state creation"""
        baseline = self.detector.baseline
        self.assertIn('processes', baseline)
        self.assertIn('users', baseline)
        self.assertIsInstance(baseline['processes'], set)
        self.assertGreater(len(baseline['processes']), 0)


class TestPatternMatching(unittest.TestCase):
    """Test specific pattern matching scenarios"""
    
    def setUp(self):
        self.detector = PrivilegeEscalationDetector()
    
    def test_t1548_patterns(self):
        """Test T1548 pattern variations"""
        patterns_to_match = [
            "sudo NOPASSWD:ALL",
            "sudo -u root whoami",
            "pkexec /bin/bash",
            "polkit-default-privs",
        ]
        
        for pattern in patterns_to_match:
            result = self.detector._check_pattern(pattern, 'T1548')
            self.assertTrue(result, f"Pattern '{pattern}' should match T1548")
    
    def test_t1053_patterns(self):
        """Test T1053 pattern variations"""
        patterns_to_match = [
            "crontab -e",
            "*/5 * * * * /bin/script.sh",
            "/etc/cron.d/",
            "systemd-timer",
        ]
        
        for pattern in patterns_to_match:
            result = self.detector._check_pattern(pattern, 'T1053')
            self.assertTrue(result, f"Pattern '{pattern}' should match T1053")


if __name__ == '__main__':
    unittest.main()
