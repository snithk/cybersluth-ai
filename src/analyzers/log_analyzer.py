import logging
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict
import json
import numpy as np
from src.models.ml_models import LogAnomalyDetector

logger = logging.getLogger(__name__)

class LogAnalyzer:
    def __init__(self):
        self.anomaly_detector = LogAnomalyDetector()
        self.suspicious_patterns = {
            'BRUTE_FORCE_DETECTED': r'failed login|authentication failure|hydra SSH',
            'PRIVILEGE_ESCALATION': r'sudo|su\s|runas',
            'SUSPICIOUS_PROCESS': r'cmd\.exe|powershell\.exe|bash',
            'PORT_SCAN_DETECTED': r'port scan|network scan|nmap -sS',
            'C2_BEACON_DETECTED': r'malware|virus|trojan|ransomware|C2 beacon',
            'SQLI_ATTACK_DETECTED': r'sql injection|select.*from|union.*select|or\s+1=1',
            'DDOS_FLOOD_DETECTED': r'ddos|flood|excessive traffic|hping3',
            'DATA_EXFIL_DETECTED': r'exfiltration|large data transfer|bulk upload'
        }
        self.event_counts = defaultdict(int)
        self.alert_threshold = 5
        self.time_window = timedelta(minutes=5)

    def analyze_logs(self):
        """Analyze system logs for suspicious activities"""
        findings = {
            'suspicious_events': [],
            'anomalies': [],
            'statistics': defaultdict(int)
        }

        try:
            # Analyze general log files
            self._analyze_log_files(findings)
            
            # Check for anomalies in log patterns
            self._detect_log_anomalies(findings)
            
            return findings
        
        except Exception as e:
            logger.error(f"Error during log analysis: {str(e)}")
            raise

    def _analyze_log_files(self, findings):
        """Analyze log files in common locations"""
        log_paths = [
            '.'  # Current directory only for faster analysis
        ]

        for path in log_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    # Exclude large/irrelevant directories
                    dirs[:] = [d for d in dirs if d not in ['env', '.git', '__pycache__', '.gemini', 'reports', 'models']]
                    for file in files:
                        if file.endswith(('.log', '.txt')):
                            self._analyze_log_file(os.path.join(root, file), findings)

    def _analyze_log_file(self, file_path, findings):
        """Analyze individual log file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    self._process_log_line(line, findings)
        except Exception as e:
            logger.error(f"Error analyzing log file {file_path}: {str(e)}")

    def _process_log_line(self, line, findings):
        """Process individual log line"""
        for pattern_name, pattern in self.suspicious_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                findings['suspicious_events'].append({
                    'timestamp': self._extract_timestamp(line),
                    'pattern': pattern_name,
                    'content': line.strip()
                })
                findings['statistics'][pattern_name] += 1

    def _detect_log_anomalies(self, findings):
        """Detect anomalies in log patterns using machine learning"""
        log_features = self._extract_log_features(findings)
        anomalies = self.anomaly_detector.detect(log_features)
        
        if anomalies:
            findings['anomalies'].extend(anomalies)

    def _extract_log_features(self, findings):
        """Extract features from log data for anomaly detection"""
        return {
            'event_frequency': len(findings['suspicious_events']),
            'time_of_day': datetime.now().hour,
            'severity_level': self._calculate_severity_level(findings),
            'source_ip_count': 0,  # Simplified for now
            'destination_ip_count': 0,  # Simplified for now
            'unique_users': 0,  # Simplified for now
            'error_count': findings['statistics'].get('failed_login', 0),
            'warning_count': findings['statistics'].get('network_scan', 0),
            'critical_count': findings['statistics'].get('malware_indicators', 0),
            'authentication_failures': findings['statistics'].get('failed_login', 0)
        }

    def _calculate_severity_level(self, findings):
        """Calculate overall severity level"""
        severity_score = 0
        severity_weights = {
            'C2_BEACON_DETECTED': 3,
            'PRIVILEGE_ESCALATION': 3,
            'SQLI_ATTACK_DETECTED': 3,
            'DATA_EXFIL_DETECTED': 3,
            'BRUTE_FORCE_DETECTED': 2,
            'PORT_SCAN_DETECTED': 2,
            'DDOS_FLOOD_DETECTED': 2,
            'SUSPICIOUS_PROCESS': 1
        }
        
        for pattern, count in findings['statistics'].items():
            severity_score += count * severity_weights.get(pattern, 1)
        
        return min(severity_score, 10)  # Cap at 10

    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}',
            r'\w{3}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4}'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return datetime.strptime(match.group(), '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
        return datetime.now()

    def monitor_realtime(self):
        """Monitor logs in real-time"""
        current_findings = self.analyze_logs()
        
        # Check for threshold violations
        for pattern, count in current_findings['statistics'].items():
            if count > self.alert_threshold:
                logger.warning(f"Alert: High frequency of {pattern} events detected")
        
        return current_findings 