import logging
import requests
import json
import re
from datetime import datetime
from src.utils.response_manager import ResponseManager

logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self):
        # Real feed URLs can be added here when available.
        # Placeholder/example URLs are intentionally skipped to avoid
        # NameResolutionError noise on startup.
        self.threat_intel_feeds = []
        self.threat_intel_data = self._load_static_threat_intel()
        self.response_manager = ResponseManager()

    def _load_static_threat_intel(self):
        """Return a static set of known-bad indicators used when no live feeds are configured."""
        return [
            {"type": "ip", "indicator": "198.51.100.1",  "severity": "high",   "description": "Known C2 server"},
            {"type": "ip", "indicator": "203.0.113.42",  "severity": "high",   "description": "Tor exit node"},
            {"type": "ip", "indicator": "192.0.2.100",   "severity": "medium", "description": "Suspicious scanner"},
            {"type": "hash", "indicator": "d41d8cd98f00b204e9800998ecf8427e", "severity": "high", "description": "Malware signature"},
        ]

    def _update_threat_intelligence(self):
        """Fetch updated threat intelligence from configured live feeds."""
        for feed_url in self.threat_intel_feeds:
            try:
                response = requests.get(feed_url, timeout=5)
                if response.status_code == 200:
                    self.threat_intel_data.extend(response.json())
                    logger.info(f"Loaded {len(response.json())} indicators from {feed_url}")
            except Exception as e:
                logger.error(f"Error fetching threat intelligence from {feed_url}: {str(e)}")

    def detect_threats(self, network_data=None, log_findings=None, artifact_findings=None):
        """Detect threats from various data sources"""
        threats = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }

        # Process network anomalies
        if network_data:
            self._process_network_threats(network_data, threats)

        # Process log anomalies
        if log_findings:
            self._process_log_threats(log_findings, threats)

        # Process artifact anomalies
        if artifact_findings:
            self._process_artifact_threats(artifact_findings, threats)

        return threats

    def _process_network_threats(self, network_data, threats):
        """Process network data for threats"""
        stats = network_data.get('system', {})
        
        # Check for high network activity
        if stats.get('bytes_sent', 0) > 1000000 or stats.get('bytes_recv', 0) > 1000000:
            threats['medium_priority'].append({
                'type': 'network_activity',
                'source': 'network_analyzer',
                'confidence': 0.75,
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'bytes_sent': stats.get('bytes_sent', 0),
                    'bytes_received': stats.get('bytes_recv', 0)
                }
            })

        # Check for suspicious connections
        if len(stats.get('connections', set())) > 50:
            threats['high_priority'].append({
                'type': 'excessive_connections',
                'source': 'network_analyzer',
                'confidence': 0.85,
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'connection_count': len(stats.get('connections', set()))
                }
            })

    def _process_log_threats(self, log_findings, threats):
        """Process log findings for threats"""
        for event in log_findings.get('suspicious_events', []):
            pattern = event.get('pattern', 'unknown')
            threat = {
                'type': pattern,
                'source': 'log_analyzer',
                'confidence': 0.8,
                'timestamp': event.get('timestamp', datetime.now().isoformat()),
                'details': event
            }
            
            # High priority threats that trigger immediate response
            high_priority_patterns = [
                'PRIVILEGE_ESCALATION', 
                'C2_BEACON_DETECTED', 
                'SQLI_ATTACK_DETECTED', 
                'DDOS_FLOOD_DETECTED', 
                'DATA_EXFIL_DETECTED'
            ]
            
            # Medium priority threats
            medium_priority_patterns = [
                'BRUTE_FORCE_DETECTED', 
                'PORT_SCAN_DETECTED'
            ]
            
            if pattern in high_priority_patterns:
                threats['high_priority'].append(threat)
                # Auto-block if an IP is found
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', event.get('content', ''))
                if ip_match:
                    self.response_manager.block_ip(ip_match.group(), reason=f"Critical threat detected: {pattern}")
            elif pattern in medium_priority_patterns:
                threats['medium_priority'].append(threat)
                # Auto-block for persistent medium threats
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', event.get('content', ''))
                if ip_match:
                    self.response_manager.block_ip(ip_match.group(), reason=f"Suspicious activity detected: {pattern}")
            else:
                threats['low_priority'].append(threat)

    def _process_artifact_threats(self, artifact_findings, threats):
        """Process artifact findings for threats"""
        for artifact in artifact_findings.get('suspicious_files', []):
            threat = {
                'type': 'suspicious_file',
                'source': 'artifact_analyzer',
                'confidence': 0.7,
                'timestamp': datetime.now().isoformat(),
                'details': artifact
            }
            
            if artifact.get('type') in ['application/x-msdownload', 'application/x-executable']:
                threats['high_priority'].append(threat)
            elif artifact.get('type') in ['application/x-shellscript', 'text/x-python']:
                threats['medium_priority'].append(threat)
            else:
                threats['low_priority'].append(threat)

    def analyze_realtime(self):
        """Analyze threats in real-time"""
        # Update threat intelligence periodically
        self._update_threat_intelligence()
        
        # Return empty threats for now (real-time analysis would be implemented here)
        return {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        } 