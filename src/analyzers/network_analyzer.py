import logging
import time
import psutil
from collections import defaultdict
import numpy as np
from src.models.ml_models import AnomalyDetector

logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    def __init__(self):
        self.network_stats = {
            'system': {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'connections': set()
            }
        }
        self.anomaly_detector = AnomalyDetector()
        self.baseline_established = False
        self.baseline_stats = None

    def _collect_network_stats(self):
        """Collect network statistics using psutil"""
        stats = self.network_stats['system']
        try:
            # Get network interface statistics
            net_io = psutil.net_io_counters()
            stats['bytes_sent'] = net_io.bytes_sent
            stats['bytes_recv'] = net_io.bytes_recv
            stats['packets_sent'] = net_io.packets_sent
            stats['packets_recv'] = net_io.packets_recv

            # Get detailed network connections
            # On Windows this requires running CMD/PowerShell as Administrator
            try:
                connections = psutil.net_connections(kind='inet')
            except psutil.AccessDenied:
                logger.warning(
                    "psutil.net_connections() access denied — "
                    "run CMD as Administrator to see live connections"
                )
                connections = []

            active_connections = []
            for conn in connections:
                try:
                    if conn.laddr and conn.raddr:
                        connection_info = {
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'status': conn.status,
                            'process_name': 'Unknown'
                        }
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                connection_info['process_name'] = process.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        active_connections.append(connection_info)
                except Exception as conn_err:
                    logger.debug(f"Error processing connection: {str(conn_err)}")
                    continue

            stats['detailed_connections'] = active_connections
            # Keep connections set in sync so _extract_features() works correctly
            stats['connections'] = set(
                (c['remote_ip'], c['remote_port']) for c in active_connections
            )
            logger.info(f"Active Network Connections: {len(active_connections)}")

        except Exception as e:
            logger.error(f"Error collecting network stats: {str(e)}")
            if 'detailed_connections' not in stats:
                stats['detailed_connections'] = []
            if 'connections' not in stats:
                stats['connections'] = set()

    def _check_anomalies(self):
        """Check for anomalous network behavior"""
        try:
            current_stats = self._extract_features()
            is_anomaly = self.anomaly_detector.detect(current_stats.reshape(1, -1))
            if is_anomaly:
                logger.warning("Anomalous network behavior detected")
                self._log_anomaly(current_stats)
        except Exception:
            # Silently skip if the saved model has a different feature count
            pass

    def _extract_features(self):
        """Extract features for anomaly detection"""
        stats = self.network_stats['system']
        return np.array([
            stats['bytes_sent'],
            stats['bytes_recv'],
            stats['packets_sent'],
            stats['packets_recv'],
            len(stats['connections'])
        ])

    def _establish_baseline(self, duration=3):
        """Establish baseline network behavior (fast 3-second snapshot)"""
        logger.info(f"Establishing baseline network behavior ({duration}s snapshot)")
        start_time = time.time()

        while time.time() - start_time < duration:
            self._collect_network_stats()
            time.sleep(1)

        self.baseline_stats = self._extract_features()
        self.baseline_established = True
        logger.info("Baseline established")

    def _log_anomaly(self, stats):
        """Log detailed information about detected anomalies"""
        logger.warning(f"""
        Anomaly detected:
        Bytes Sent: {stats[0]}
        Bytes Received: {stats[1]}
        Packets Sent: {stats[2]}
        Packets Received: {stats[3]}
        Active Connections: {stats[4]}
        """)

    def start_monitoring(self, duration=None):
        """Start network monitoring for a specified duration"""
        logger.info("Starting network monitoring")

        try:
            start_time = time.time()
            while True:
                self._collect_network_stats()
                if not self.baseline_established:
                    self.baseline_stats = self._extract_features()
                    self.baseline_established = True
                self._check_anomalies()

                if duration and time.time() - start_time >= duration:
                    break

                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Network monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in network monitoring: {str(e)}")

        return self.network_stats

    def monitor_realtime(self):
        """Monitor network traffic in real-time"""
        # Collect live stats immediately — no blocking wait
        self._collect_network_stats()

        # Establish baseline in the background after first real sample
        if not self.baseline_established:
            self.baseline_stats = self._extract_features()
            self.baseline_established = True

        self._check_anomalies()

        stats = self.network_stats['system']
        logger.info(
            f"Network — Sent: {stats['bytes_sent']:,}B  "
            f"Recv: {stats['bytes_recv']:,}B  "
            f"Connections: {len(stats.get('detailed_connections', []))}"
        )

        return self.network_stats

    def get_statistics(self):
        """Get current network statistics"""
        return self.network_stats

    def analyze_from_csv(self, filepath):
        """Analyze network traffic from an uploaded CSV file (for cloud/live deployment)"""
        import csv as csv_module

        try:
            connections = []
            bytes_sent = 0
            packets_sent = 0

            with open(filepath, 'r') as f:
                reader = csv_module.DictReader(f)
                for row in reader:
                    try:
                        pkt_len = int(row.get('packet_length', 0))
                        src_ip = row.get('src_ip', '')
                        dst_ip = row.get('dst_ip', '')
                        label = row.get('label', 'Benign')

                        bytes_sent += pkt_len
                        packets_sent += 1

                        conn_info = {
                            'local_ip': src_ip,
                            'local_port': int(row.get('src_port', 0)),
                            'remote_ip': dst_ip,
                            'remote_port': int(row.get('dst_port', 0)),
                            'status': 'ATTACK' if label != 'Benign' else 'ESTABLISHED',
                            'process_name': label
                        }
                        connections.append(conn_info)
                    except (ValueError, KeyError):
                        continue

            self.network_stats = {
                'system': {
                    'bytes_sent': bytes_sent,
                    'bytes_recv': 0,
                    'packets_sent': packets_sent,
                    'packets_recv': 0,
                    'connections': set(),
                    'detailed_connections': connections[:200]
                }
            }
            self.baseline_established = True

            logger.info(f"Analyzed {packets_sent} packets from CSV file")
            return self.network_stats

        except Exception as e:
            logger.error(f"Error analyzing CSV file: {str(e)}")
            return self.network_stats