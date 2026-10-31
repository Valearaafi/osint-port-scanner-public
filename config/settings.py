import copy
import json
import os
from typing import Any, Dict

class Config:
    """Configuration management class"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.default_config = {
            "scan_settings": {
                "timeout": 5,
                "max_threads": 50,
                "rate_limit": 10,
                "common_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443],
                "extended_ports": list(range(1, 1025)),
                "stealth_mode": False,
                "enable_udp_scan": True,
                "banner_grabbing": True
            },
            "api_keys": {
                "shodan": "",
                "virustotal": "",
                "censys": "",
                "builtwith": ""
            },
            "database": {
                "type": "sqlite",
                "path": "scans.db",
                "backup_enabled": True,
                "max_history": 1000
            },
            "ui_settings": {
                "theme": "dark",
                "font_size": 10,
                "auto_save": True,
                "max_history": 100,
                "enable_notifications": True
            },
            "reporting": {
                "default_format": "pdf",
                "include_screenshots": False,
                "logo_path": "resources/logo.png",
                "template_path": "resources/templates/"
            },
            "security": {
                "ethical_mode": True,
                "rate_limiting": True,
                "user_agent": "Advanced-OSINT-Scanner-3.0-Educational",
                "respect_robots_txt": True
            }
        }
        self.config = {}
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                self._merge_with_defaults()
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading config: {e}")
                self.config = copy.deepcopy(self.default_config)
                self.save_config()
        else:
            self.config = copy.deepcopy(self.default_config)
            self.save_config()
    
    def save_config(self) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
        except IOError as e:
            print(f"Error saving config: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self.save_config()
    
    def _merge_with_defaults(self) -> None:
        """Merge loaded config with defaults"""
        def merge_dict(default: dict, loaded: dict) -> dict:
            for key, value in default.items():
                if key not in loaded:
                    loaded[key] = copy.deepcopy(value)
                elif isinstance(value, dict) and isinstance(loaded[key], dict):
                    merge_dict(value, loaded[key])
            return loaded
        
        self.config = merge_dict(self.default_config, self.config)