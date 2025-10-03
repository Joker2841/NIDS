# config.py - Enhanced Configuration Management

import os
import json
import yaml
from typing import Dict, Any, Optional
import logging

class NIDSConfig:
    """Enhanced configuration management for NIDS"""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'network': {
            'interface': 'eth0',
            'bpf_filter': 'tcp or arp or icmp or (udp and port 53)',
            'packet_queue_size': 2000,
            'enable_promiscuous_mode': True
        },
        'detection': {
            'port_scan': {
                'threshold': 20,
                'time_window': 10,
                'enabled': True
            },
            'syn_flood': {
                'threshold': 50,
                'time_window': 5,
                'enabled': True
            },
            'icmp_flood': {
                'threshold': 50,
                'time_window': 5,
                'enabled': True
            },
            'arp_spoofing': {
                'enabled': True,
                'monitor_gateway': True
            },
            'dns_monitoring': {
                'enabled': True,
                'max_query_length': 100,
                'flood_threshold': 100,
                'flood_time_window': 60
            }
        },
        'logging': {
            'log_file': 'nids_alerts.log',
            'log_level': 'INFO',
            'max_log_size': '10MB',
            'backup_count': 5,
            'json_format': True
        },
        'api': {
            'host': '0.0.0.0',
            'port': 5000,
            'secret_key': None,
            'cors_enabled': True,
            'max_history_size': 1000
        },
        'database': {
            'path': 'nids.db',
            'cleanup_days': 30,
            'backup_enabled': True
        },
        'geolocation': {
            'enabled': True,
            'cache_ttl': 3600,
            'timeout': 3,
            'services': ['ipinfo', 'ipapi']
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration management.
        
        Args:
            config_file: Path to configuration file (JSON or YAML)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file
        
        # Load configuration from file if provided
        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)
        
        # Override with environment variables
        self._load_from_environment()
        
        # Validate configuration
        self._validate_config()
        
        print(f"[*] Configuration loaded successfully")
    
    def _load_from_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    file_config = yaml.safe_load(f)
                else:
                    file_config = json.load(f)
            
            # Merge with default configuration
            self._deep_merge(self.config, file_config)
            print(f"[*] Configuration loaded from: {config_file}")
            
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            print(f"[!] Error parsing config file {config_file}: {e}")
            raise
        except Exception as e:
            print(f"[!] Error loading config file {config_file}: {e}")
            raise
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'NIDS_INTERFACE': ['network', 'interface'],
            'NIDS_LOG_FILE': ['logging', 'log_file'],
            'NIDS_LOG_LEVEL': ['logging', 'log_level'],
            'NIDS_API_PORT': ['api', 'port'],
            'NIDS_API_SECRET': ['api', 'secret_key'],
            'NIDS_DB_PATH': ['database', 'path'],
            'NIDS_PORT_SCAN_THRESHOLD': ['detection', 'port_scan', 'threshold'],
            'NIDS_SYN_FLOOD_THRESHOLD': ['detection', 'syn_flood', 'threshold']
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self._set_nested_value(self.config, config_path, self._convert_type(value))
                print(f"[*] Config override from environment: {env_var}")
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _set_nested_value(self, dictionary: Dict, path: list, value: Any):
        """Set a nested value in dictionary using path list"""
        for key in path[:-1]:
            dictionary = dictionary.setdefault(key, {})
        dictionary[path[-1]] = value
    
    def _convert_type(self, value: str) -> Any:
        """Convert string value to appropriate type"""
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def _validate_config(self):
        """Validate configuration values"""
        try:
            # Validate network interface
            interface = self.get('network.interface')
            if interface:
                try:
                    import netifaces
                    if interface not in netifaces.interfaces():
                        available = netifaces.interfaces()
                        print(f"[!] Warning: Interface '{interface}' not found. Available: {available}")
                except ImportError:
                    print("[!] Warning: netifaces not installed. Cannot validate interface.")
            
            # Validate port
            port = self.get('api.port')
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid API port: {port}")
            
            # Validate thresholds (must be positive)
            thresholds = [
                'detection.port_scan.threshold',
                'detection.syn_flood.threshold', 
                'detection.icmp_flood.threshold'
            ]
            
            for threshold_path in thresholds:
                value = self.get(threshold_path)
                if value is not None and value <= 0:
                    raise ValueError(f"Threshold must be positive: {threshold_path} = {value}")
            
            # Generate secret key if not provided
            if not self.get('api.secret_key'):
                import secrets
                self.config['api']['secret_key'] = secrets.token_hex(32)
                print("[*] Generated random API secret key")
            
        except Exception as e:
            print(f"[!] Configuration validation error: {e}")
            raise
    
    def get(self, key_path: str, default=None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to configuration value
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                value = value[key]
            
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to configuration value
            value: Value to set
        """
        keys = key_path.split('.')
        self._set_nested_value(self.config, keys, value)
    
    def save_to_file(self, filename: str):
        """Save current configuration to file"""
        try:
            with open(filename, 'w') as f:
                if filename.endswith('.yaml') or filename.endswith('.yml'):
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    json.dump(self.config, f, indent=2)
            print(f"[*] Configuration saved to: {filename}")
        except Exception as e:
            print(f"[!] Error saving configuration: {e}")
            raise
    
    def get_dict(self) -> Dict[str, Any]:
        """Get the entire configuration as a dictionary"""
        return self.config.copy()
    
    def print_config(self):
        """Print current configuration"""
        print("Current NIDS Configuration:")
        print(json.dumps(self.config, indent=2))

# Legacy compatibility class
class Config:
    """Legacy configuration class for backward compatibility"""
    
    def __init__(self, interface: str, log_file: str):
        self.config = NIDSConfig()
        self.config.set('network.interface', interface)
        self.config.set('logging.log_file', log_file)
        
        # Expose commonly used values as attributes
        self.INTERFACE = interface
        self.LOG_FILE = log_file
        
        # Detection thresholds for backward compatibility
        self.PORT_SCAN_THRESHOLD = self.config.get('detection.port_scan.threshold')
        self.PORT_SCAN_WINDOW = self.config.get('detection.port_scan.time_window')
        self.SYN_FLOOD_THRESHOLD = self.config.get('detection.syn_flood.threshold')
        self.SYN_FLOOD_WINDOW = self.config.get('detection.syn_flood.time_window')

# Example configuration file (config.yaml)
EXAMPLE_CONFIG_YAML = """
# NIDS Configuration File
network:
  interface: "eth0"
  bpf_filter: "tcp or arp or icmp or (udp and port 53)"
  packet_queue_size: 2000

detection:
  port_scan:
    threshold: 15
    time_window: 10
    enabled: true
  
  syn_flood:
    threshold: 50
    time_window: 5
    enabled: true

logging:
  log_file: "nids_alerts.log"
  log_level: "INFO"

api:
  port: 5000
  cors_enabled: true

database:
  path: "nids.db"
  cleanup_days: 30
"""

if __name__ == '__main__':
    # Test configuration management
    print("--- Testing Configuration Management ---")
    
    # Test default configuration
    config = NIDSConfig()
    print(f"Default interface: {config.get('network.interface')}")
    print(f"Port scan threshold: {config.get('detection.port_scan.threshold')}")
    
    # Test setting values
    config.set('network.interface', 'wlan0')
    config.set('detection.port_scan.threshold', 25)
    
    print(f"Updated interface: {config.get('network.interface')}")
    print(f"Updated threshold: {config.get('detection.port_scan.threshold')}")
    
    # Test legacy compatibility
    legacy_config = Config('eth1', 'test.log')
    print(f"Legacy interface: {legacy_config.INTERFACE}")
    
    print("--- Configuration Test Complete ---")