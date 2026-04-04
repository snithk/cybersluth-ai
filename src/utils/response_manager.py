import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class ResponseManager:
    def __init__(self, blacklist_file='data/blacklist.json'):
        self.blacklist_file = blacklist_file
        self._ensure_data_dir()
        self.blacklisted_ips = self._load_blacklist()

    def _ensure_data_dir(self):
        os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)

    def _load_blacklist(self):
        import json
        if os.path.exists(self.blacklist_file):
            try:
                with open(self.blacklist_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_blacklist(self):
        import json
        with open(self.blacklist_file, 'w') as f:
            json.dump(self.blacklisted_ips, f, indent=4)

    def block_ip(self, ip_address, reason="Suspicious activity"):
        """Simulate blocking an IP address"""
        if ip_address not in self.blacklisted_ips:
            self.blacklisted_ips[ip_address] = {
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
                'status': 'blocked'
            }
            self._save_blacklist()
            logger.warning(f"ACTION TAKEN: IP Address {ip_address} has been BLOCKED. Reason: {reason}")
            return True
        return False

    def is_blocked(self, ip_address):
        return ip_address in self.blacklisted_ips
