import os
import json
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        self.config = {
            'analyzer_mode': 'batch',  # 'batch' or 'realtime'
            'log_level': 'INFO',
            'storage_path': 'data',
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'scan_intervals': {
                'network': 60,  # seconds
                'logs': 300,    # seconds
                'artifacts': 3600  # seconds
            },
            'threat_intelligence': {
                'update_interval': 3600,  # seconds
                'feeds': [
                    'https://api.threatintel.example.com/v1/indicators',
                    'https://api.malware-db.example.com/v1/signatures'
                ]
            },
            'analysis_settings': {
                'network': {
                    'packet_capture_timeout': 300,  # seconds
                    'max_packets_per_ip': 10000,
                    'suspicious_ports': [22, 23, 445, 3389, 4444, 5900]
                },
                'logs': {
                    'max_log_age': 7 * 24 * 3600,  # 7 days in seconds
                    'batch_size': 1000,
                    'critical_events': [
                        'authentication failure',
                        'privilege escalation',
                        'firewall violation'
                    ]
                },
                'artifacts': {
                    'max_file_count': 10000,
                    'excluded_dirs': [
                        'System Volume Information',
                        '$Recycle.Bin',
                        'Windows'
                    ],
                    'high_risk_extensions': [
                        '.exe', '.dll', '.sys',
                        '.ps1', '.vbs', '.js'
                    ]
                }
            },
            'reporting': {
                'report_format': ['html', 'json'],
                'max_reports': 100,
                'cleanup_age': 30 * 24 * 3600  # 30 days in seconds
            },
            'ml_models': {
                'model_path': 'models',
                'update_interval': 7 * 24 * 3600,  # 7 days in seconds
                'confidence_threshold': 0.75
            }
        }
        
        self._load_config()
        self._load_environment_variables()

    def _load_config(self):
        """Load configuration from file"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    self._update_nested_dict(self.config, file_config)
                logger.info("Configuration loaded from file successfully")
            else:
                self._save_config()
                logger.info("Default configuration created")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")

    def _save_config(self):
        """Save current configuration to file"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")

    def _load_environment_variables(self):
        """Load configuration from environment variables"""
        try:
            load_dotenv()
            
            # Override configuration with environment variables
            env_mapping = {
                'ANALYZER_MODE': ('analyzer_mode', str),
                'LOG_LEVEL': ('log_level', str),
                'STORAGE_PATH': ('storage_path', str),
                'MAX_FILE_SIZE': ('max_file_size', int),
                'NETWORK_SCAN_INTERVAL': ('scan_intervals.network', int),
                'LOG_SCAN_INTERVAL': ('scan_intervals.logs', int),
                'ARTIFACT_SCAN_INTERVAL': ('scan_intervals.artifacts', int),
                'CONFIDENCE_THRESHOLD': ('ml_models.confidence_threshold', float)
            }

            for env_var, (config_path, type_converter) in env_mapping.items():
                value = os.getenv(env_var)
                if value is not None:
                    self._set_nested_value(config_path.split('.'), type_converter(value))

            logger.info("Environment variables loaded successfully")
        except Exception as e:
            logger.error(f"Error loading environment variables: {str(e)}")

    def _update_nested_dict(self, base_dict, update_dict):
        """Update nested dictionary recursively"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict:
                self._update_nested_dict(base_dict[key], value)
            else:
                base_dict[key] = value

    def _set_nested_value(self, path, value):
        """Set value in nested dictionary using path"""
        current = self.config
        for part in path[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[path[-1]] = value

    def get(self, key, default=None):
        """Get configuration value"""
        try:
            current = self.config
            for part in key.split('.'):
                current = current[part]
            return current
        except (KeyError, TypeError):
            return default

    def set(self, key, value):
        """Set configuration value"""
        try:
            self._set_nested_value(key.split('.'), value)
            self._save_config()
            logger.info(f"Configuration updated: {key} = {value}")
        except Exception as e:
            logger.error(f"Error updating configuration: {str(e)}")

    def reset(self):
        """Reset configuration to defaults"""
        try:
            self.__init__()
            self._save_config()
            logger.info("Configuration reset to defaults")
        except Exception as e:
            logger.error(f"Error resetting configuration: {str(e)}")

    def validate(self):
        """Validate configuration settings"""
        try:
            # Validate analyzer mode
            if self.config['analyzer_mode'] not in ['batch', 'realtime']:
                raise ValueError("Invalid analyzer_mode. Must be 'batch' or 'realtime'")

            # Validate log level
            if self.config['log_level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                raise ValueError("Invalid log_level")

            # Validate scan intervals
            for key, value in self.config['scan_intervals'].items():
                if not isinstance(value, int) or value <= 0:
                    raise ValueError(f"Invalid scan interval for {key}")

            # Validate file size limits
            if not isinstance(self.config['max_file_size'], int) or self.config['max_file_size'] <= 0:
                raise ValueError("Invalid max_file_size")

            # Validate ML model settings
            if not (0 < self.config['ml_models']['confidence_threshold'] <= 1):
                raise ValueError("Invalid confidence_threshold. Must be between 0 and 1")

            logger.info("Configuration validation successful")
            return True

        except Exception as e:
            logger.error(f"Configuration validation failed: {str(e)}")
            return False

    def get_all(self):
        """Get entire configuration"""
        return self.config.copy()

    def update(self, new_config):
        """Update multiple configuration values"""
        try:
            self._update_nested_dict(self.config, new_config)
            self._save_config()
            logger.info("Configuration updated successfully")
        except Exception as e:
            logger.error(f"Error updating configuration: {str(e)}")

    def get_storage_path(self, subfolder=None):
        """Get storage path with optional subfolder"""
        base_path = os.path.abspath(self.config['storage_path'])
        if subfolder:
            path = os.path.join(base_path, subfolder)
            os.makedirs(path, exist_ok=True)
            return path
        return base_path 