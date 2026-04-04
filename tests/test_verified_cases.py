import time
import os
import json
from datetime import datetime
import sys
import unittest

# Ensure project root is in path
sys.path.append(os.getcwd())

from unittest.mock import patch, MagicMock
from src.analyzers.log_analyzer import LogAnalyzer
from src.models.threat_detector import ThreatDetector
from src.utils.response_manager import ResponseManager

class TestCyberForensicsAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.log_file = "test_simulation.log"
        cls.blacklist_file = "data/test_blacklist.json"
        # Ensure data directory exists
        os.makedirs("data", exist_ok=True)

    def setUp(self):
        # Mocking requests.get to avoid network errors
        self.patcher = patch('requests.get')
        self.mock_get = self.patcher.start()
        self.mock_get.return_value.status_code = 200
        self.mock_get.return_value.json.return_value = []

        # Clear log file and blacklist before each test
        with open(self.log_file, "w") as f:
            pass
        if os.path.exists(self.blacklist_file):
            os.remove(self.blacklist_file)
        
        self.analyzer = LogAnalyzer()
        self.detector = ThreatDetector()
        # Point detector's response manager to our test blacklist
        self.detector.response_manager = ResponseManager(blacklist_file=self.blacklist_file)

    def tearDown(self):
        # Stop mocking
        self.patcher.stop()
        # Cleanup
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        if os.path.exists(self.blacklist_file):
            os.remove(self.blacklist_file)

    def inject_log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_file, "a") as f:
            f.write(f"{timestamp} - {message}\n")

    def test_tc001_port_scan(self):
        """TC-001: Port Scan Detection & Mitigation"""
        ip = "192.168.1.105"
        # Trigger condition: 50 ports hit (simulation sends one aggregated log or multiple)
        # Current app triggers on the pattern
        self.inject_log(f"firewall - WARNING - Network scan detected from {ip} using nmap -sS")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('PORT_SCAN_DETECTED', detected_patterns, "Alarm PORT_SCAN_DETECTED not fired")
        
        # Verify Stop Action (Blacklist)
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-001 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc002_ddos_flood(self):
        """TC-002: DDoS UDP Flood Detection & Mitigation"""
        ip = "172.16.0.45"
        self.inject_log(f"network_monitor - ALERT - DDoS flood attack identified from {ip} using hping3")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('DDOS_FLOOD_DETECTED', detected_patterns, "Alarm DDOS_FLOOD_DETECTED not fired")
        
        # Verify Stop Action
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-002 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc003_sql_injection(self):
        """TC-003: SQL Injection Detection & Block"""
        ip = "203.0.113.42"
        self.inject_log(f"web_server - ERROR - SQL Injection attempt blocked from {ip}: Payload ' OR 1=1 --")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('SQLI_ATTACK_DETECTED', detected_patterns, "Alarm SQLI_ATTACK_DETECTED not fired")
        
        # Verify Stop Action
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-003 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc004_brute_force(self):
        """TC-004: Brute Force Login Detection & Account Protection"""
        ip = "198.51.100.77"
        self.inject_log(f"auth - FAILED LOGIN attempt for user 'root' from {ip} via hydra SSH")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('BRUTE_FORCE_DETECTED', detected_patterns, "Alarm BRUTE_FORCE_DETECTED not fired")
        
        # Verify Stop Action
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-004 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc005_malware_c2(self):
        """TC-005: Malware Command & Control Beacon Detection"""
        ip = "10.0.0.44"
        self.inject_log(f"endpoint_security - CRITICAL - C2 Beacon indicators detected on host {ip} every 60s")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('C2_BEACON_DETECTED', detected_patterns, "Alarm C2_BEACON_DETECTED not fired")
        
        # Verify Stop Action
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-005 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc006_data_exfiltration(self):
        """TC-006: Data Exfiltration Detection & Prevention"""
        ip = "10.0.0.55"
        self.inject_log(f"dlp_service - ALERT - Data exfiltration detected from host {ip}: Bulk upload to external FTP")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events']]
        self.assertIn('DATA_EXFIL_DETECTED', detected_patterns, "Alarm DATA_EXFIL_DETECTED not fired")
        
        # Verify Stop Action
        self.assertTrue(self.detector.response_manager.is_blocked(ip), f"IP {ip} was not blacklisted")
        
        print(f"TC-006 PASS: Alarm fired and IP {ip} blocked.")

    def test_tc007_negative_test(self):
        """TC-007: Normal Traffic (Negative Test)"""
        ip = "10.0.0.10"
        self.inject_log(f"web_server - INFO - HTTP GET /index.html from {ip} - Success")
        
        findings = self.analyzer.analyze_logs()
        threats = self.detector.detect_threats(log_findings=findings)
        
        # Verify NO Alarm
        detected_patterns = [e['pattern'] for e in findings['suspicious_events'] if ip in e['content']]
        self.assertEqual(len(detected_patterns), 0, f"False alarm triggered for normal traffic: {detected_patterns}")
        
        # Verify NO Stop Action
        self.assertFalse(self.detector.response_manager.is_blocked(ip), f"Normal IP {ip} was incorrectly blacklisted")
        
        print("TC-007 PASS: No alarm fired for normal traffic.")

if __name__ == "__main__":
    unittest.main()
