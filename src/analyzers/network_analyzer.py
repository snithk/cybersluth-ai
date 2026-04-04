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
        try:
            # Get network interface statistics
            net_io = psutil.net_io_counters()
            
            # Get detailed network connections
            connections = psutil.net_connections(kind='inet')
            
            # Update statistics
            stats = self.network_stats['system']
            stats['bytes_sent'] = net_io.bytes_sent
            stats['bytes_recv'] = net_io.bytes_recv
            stats['packets_sent'] = net_io.packets_sent
            stats['packets_recv'] = net_io.packets_recv
            
            # Track detailed connection information
            active_connections = []
            for conn in connections:
                try:
                    if conn.laddr and conn.raddr:  # Only track established connections
                        connection_info = {
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'status': conn.status,
                            'process_name': 'Unknown'
                        }
                        # Get process name if possible
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
            logger.info(f"Active Network Connections: {len(active_connections)}")
            for conn in active_connections:
                logger.info(f"Connection: {conn['process_name']} ({conn['local_ip']}:{conn['local_port']} → {conn['remote_ip']}:{conn['remote_port']}) - {conn['status']}")
                
        except Exception as e:
            logger.error(f"Error collecting network stats: {str(e)}")
            # Ensure we always have valid statistics even on error
            if 'detailed_connections' not in stats:
                stats['detailed_connections'] = []

    def _check_anomalies(self):
        """Check for anomalous network behavior"""
        try:
            current_stats = self._extract_features()
            is_anomaly = self.anomaly_detector.detect(current_stats.reshape(1, -1))
            
            if is_anomaly:
                logger.warning("Anomalous network behavior detected")
                self._log_anomaly(current_stats)
        except Exception as e:
            logger.error(f"Error checking anomalies: {str(e)}")

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

    def _establish_baseline(self, duration=30):
        """Establish baseline network behavior"""
        logger.info(f"Establishing baseline network behavior for {duration} seconds")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            self._collect_network_stats()
            time.sleep(1)
        
        self.baseline_stats = self._extract_features()
        self.baseline_established = True
        logger.info("Baseline network behavior established")

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
        
        if not self.baseline_established:
            self._establish_baseline()
        
        try:
            start_time = time.time()
            while True:
                self._collect_network_stats()
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
        if not self.baseline_established:
            self._establish_baseline()
        
        self._collect_network_stats()
        self._check_anomalies()
        
        # Log network statistics
        stats = self.network_stats['system']
        logger.info(f"""
Network Statistics:
- Bytes Sent: {stats['bytes_sent']:,} bytes
- Bytes Received: {stats['bytes_recv']:,} bytes
- Packets Sent: {stats['packets_sent']:,}
- Packets Received: {stats['packets_recv']:,}
- Active Connections: {len(stats.get('detailed_connections', []))}
        """)
        
        return self.network_stats

    def get_statistics(self):
        """Get current network statistics"""
        return self.network_stats 