"""
Configuration module for BugHunter.
Handles application configuration and settings.
Author: Infosec_Viking
Repository: https://github.com/MaxFiveTen/BugHunter
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path
import logging


class Config:
    """Configuration management class."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config.json"
        self.logger = logging.getLogger(__name__)
        self.config = self._load_default_config()
        self._load_config_file()
        
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            "scanner": {
                "timeout": 30,
                "max_retries": 3,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "follow_redirects": True,
                "max_redirects": 5,
                "verify_ssl": False,
                "threads": 10,
                "delay": 0.1
            },
            "vulnerability_scans": {
                "sql_injection": {
                    "enabled": True,
                    "payloads": [
                        "' OR '1'='1",
                        "' OR 1=1--",
                        "'; DROP TABLE users; --",
                        "' UNION SELECT NULL, username, password FROM users--"
                    ],
                    "timeout": 10
                },
                "xss": {
                    "enabled": True,
                    "payloads": [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>",
                        "<svg onload=alert('XSS')>"
                    ],
                    "timeout": 10
                },
                "directory_traversal": {
                    "enabled": True,
                    "payloads": [
                        "../../../etc/passwd",
                        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
                    ],
                    "timeout": 10
                },
                "command_injection": {
                    "enabled": True,
                    "payloads": [
                        "; ls -la",
                        "| whoami",
                        "&& cat /etc/passwd"
                    ],
                    "timeout": 10
                },
                "ldap_injection": {
                    "enabled": True,
                    "payloads": [
                        "*",
                        "*)(uid=*",
                        "*)(|(uid=*"
                    ],
                    "timeout": 10
                },
                "xxe": {
                    "enabled": True,
                    "timeout": 10
                },
                "ssrf": {
                    "enabled": True,
                    "payloads": [
                        "http://127.0.0.1:22",
                        "http://localhost:80",
                        "http://169.254.169.254/latest/meta-data/"
                    ],
                    "timeout": 10
                }
            },
            "fuzzing": {
                "enabled": True,
                "max_payloads_per_type": 10,
                "endpoint_discovery": True,
                "parameter_discovery": True,
                "header_fuzzing": True,
                "method_fuzzing": True,
                "timeout": 15
            },
            "reconnaissance": {
                "enabled": True,
                "dns_enumeration": True,
                "subdomain_enumeration": True,
                "port_scanning": True,
                "technology_detection": True,
                "whois_lookup": True,
                "ssl_analysis": True,
                "timeout": 20
            },
            "network_scanning": {
                "enabled": True,
                "port_range": "1-1000",
                "common_ports_only": True,
                "service_detection": True,
                "os_fingerprinting": True,
                "vulnerability_scanning": True,
                "timeout": 5,
                "max_threads": 100
            },
            "reporting": {
                "output_dir": "reports",
                "formats": ["json", "html", "csv", "xml"],
                "include_summary": True,
                "include_recommendations": True,
                "severity_colors": {
                    "critical": "#dc3545",
                    "high": "#fd7e14",
                    "medium": "#ffc107",
                    "low": "#28a745"
                }
            },
            "logging": {
                "level": "INFO",
                "file": "bughunt.log",
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "advanced": {
                "custom_payloads": [],
                "custom_headers": {},
                "proxy": {
                    "enabled": False,
                    "host": "",
                    "port": 8080,
                    "username": "",
                    "password": ""
                },
                "rate_limiting": {
                    "enabled": False,
                    "requests_per_second": 10
                },
                "exclusions": {
                    "domains": [],
                    "ips": [],
                    "urls": [],
                    "parameters": []
                }
            }
        }
        
    def _load_config_file(self):
        """Load configuration from file."""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    self._merge_config(self.config, file_config)
                    self.logger.info(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading configuration file: {e}")
                self.logger.info("Using default configuration")
        else:
            self.logger.info(f"Configuration file not found: {self.config_file}")
            self.logger.info("Using default configuration")
            self._save_default_config()
            
    def _merge_config(self, default: Dict, custom: Dict):
        """Recursively merge configuration dictionaries."""
        for key, value in custom.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
                
    def _save_default_config(self):
        """Save default configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Default configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving default configuration: {e}")
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)."""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)."""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    def save(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            
    def get_scanner_config(self) -> Dict[str, Any]:
        """Get scanner configuration."""
        return self.get('scanner', {})
        
    def get_vulnerability_config(self, vuln_type: str) -> Dict[str, Any]:
        """Get vulnerability scan configuration."""
        return self.get(f'vulnerability_scans.{vuln_type}', {})
        
    def get_fuzzing_config(self) -> Dict[str, Any]:
        """Get fuzzing configuration."""
        return self.get('fuzzing', {})
        
    def get_reconnaissance_config(self) -> Dict[str, Any]:
        """Get reconnaissance configuration."""
        return self.get('reconnaissance', {})
        
    def get_network_scanning_config(self) -> Dict[str, Any]:
        """Get network scanning configuration."""
        return self.get('network_scanning', {})
        
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration."""
        return self.get('reporting', {})
        
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.get('logging', {})
        
    def get_advanced_config(self) -> Dict[str, Any]:
        """Get advanced configuration."""
        return self.get('advanced', {})
        
    def is_vulnerability_enabled(self, vuln_type: str) -> bool:
        """Check if vulnerability scan is enabled."""
        return self.get(f'vulnerability_scans.{vuln_type}.enabled', True)
        
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if feature is enabled."""
        return self.get(f'{feature}.enabled', True)
        
    def get_payloads(self, vuln_type: str) -> list:
        """Get payloads for vulnerability type."""
        return self.get(f'vulnerability_scans.{vuln_type}.payloads', [])
        
    def get_timeout(self, section: str, default: int = 30) -> int:
        """Get timeout for section."""
        return self.get(f'{section}.timeout', default)
        
    def get_user_agent(self) -> str:
        """Get user agent string."""
        return self.get('scanner.user_agent', 'BugHunt/1.0')
        
    def get_output_dir(self) -> str:
        """Get output directory."""
        return self.get('reporting.output_dir', 'reports')
        
    def get_report_formats(self) -> list:
        """Get report formats."""
        return self.get('reporting.formats', ['json', 'html'])
        
    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration."""
        return self.get('advanced.proxy', {})
        
    def get_exclusions(self) -> Dict[str, list]:
        """Get exclusions configuration."""
        return self.get('advanced.exclusions', {})
        
    def is_excluded(self, item_type: str, item: str) -> bool:
        """Check if item is excluded."""
        exclusions = self.get_exclusions()
        return item in exclusions.get(item_type, [])
        
    def validate_config(self) -> list:
        """Validate configuration and return errors."""
        errors = []
        
        # Validate timeout values
        scanner_timeout = self.get('scanner.timeout')
        if not isinstance(scanner_timeout, int) or scanner_timeout <= 0:
            errors.append("scanner.timeout must be a positive integer")
            
        # Validate thread count
        threads = self.get('scanner.threads')
        if not isinstance(threads, int) or threads <= 0:
            errors.append("scanner.threads must be a positive integer")
            
        # Validate output directory
        output_dir = self.get('reporting.output_dir')
        if not isinstance(output_dir, str):
            errors.append("reporting.output_dir must be a string")
            
        # Validate report formats
        formats = self.get('reporting.formats')
        valid_formats = ['json', 'html', 'csv', 'xml']
        if not isinstance(formats, list):
            errors.append("reporting.formats must be a list")
        else:
            for fmt in formats:
                if fmt not in valid_formats:
                    errors.append(f"Invalid report format: {fmt}")
                    
        return errors
