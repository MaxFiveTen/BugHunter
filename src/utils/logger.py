"""
Logging module for BugHunter.
Handles application logging configuration and management.
Author: Infosec_Viking
Repository: https://github.com/MaxFiveTen/BugHunter
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_size: str = "10MB",
    backup_count: int = 5,
    verbose: bool = False,
    quiet: bool = False,
    format_string: Optional[str] = None
):
    """Setup logging configuration for BugHunt."""
    
    # Determine log level
    if verbose:
        log_level = logging.DEBUG
    elif quiet:
        log_level = logging.ERROR
    else:
        log_level = getattr(logging, level.upper(), logging.INFO)
        
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Default log file
    if not log_file:
        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = logs_dir / f"bughunter_{timestamp}.log"
        
    # Convert max_size to bytes
    max_size_bytes = _parse_size(max_size)
    
    # Create formatter
    if not format_string:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
    formatter = logging.Formatter(format_string)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if not quiet:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
    # File handler with rotation
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}")
        
    # Set specific logger levels
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info("BugHunt logging initialized")
    logger.info(f"Log level: {level}")
    logger.info(f"Log file: {log_file}")
    logger.info(f"Max file size: {max_size}")
    logger.info(f"Backup count: {backup_count}")
    

def _parse_size(size_str: str) -> int:
    """Parse size string to bytes."""
    size_str = size_str.upper().strip()
    
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    elif size_str.endswith('B'):
        return int(size_str[:-1])
    else:
        # Assume bytes if no suffix
        return int(size_str)


def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return logging.getLogger(name)


def log_request(logger: logging.Logger, method: str, url: str, status: int, duration: float):
    """Log HTTP request details."""
    logger.debug(f"{method} {url} - {status} ({duration:.2f}s)")


def log_vulnerability(logger: logging.Logger, vuln_type: str, severity: str, description: str):
    """Log vulnerability discovery."""
    logger.warning(f"VULNERABILITY FOUND - {vuln_type} [{severity}]: {description}")


def log_scan_progress(logger: logging.Logger, current: int, total: int, current_item: str):
    """Log scan progress."""
    percentage = (current / total) * 100
    logger.info(f"Scan progress: {current}/{total} ({percentage:.1f}%) - {current_item}")


def log_scan_summary(logger: logging.Logger, total_vulns: int, critical: int, high: int, medium: int, low: int):
    """Log scan summary."""
    logger.info("=" * 60)
    logger.info("SCAN SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Total vulnerabilities found: {total_vulns}")
    logger.info(f"Critical: {critical}")
    logger.info(f"High: {high}")
    logger.info(f"Medium: {medium}")
    logger.info(f"Low: {low}")
    logger.info("=" * 60)


def log_error(logger: logging.Logger, error: Exception, context: str = ""):
    """Log error with context."""
    if context:
        logger.error(f"Error in {context}: {str(error)}", exc_info=True)
    else:
        logger.error(f"Error: {str(error)}", exc_info=True)


def log_warning(logger: logging.Logger, message: str, context: str = ""):
    """Log warning with context."""
    if context:
        logger.warning(f"Warning in {context}: {message}")
    else:
        logger.warning(message)


def log_info(logger: logging.Logger, message: str, context: str = ""):
    """Log info with context."""
    if context:
        logger.info(f"Info from {context}: {message}")
    else:
        logger.info(message)


def log_debug(logger: logging.Logger, message: str, context: str = ""):
    """Log debug with context."""
    if context:
        logger.debug(f"Debug from {context}: {message}")
    else:
        logger.debug(message)


class ScanLogger:
    """Custom logger for scan operations."""
    
    def __init__(self, name: str):
        self.logger = get_logger(name)
        self.scan_start_time = None
        self.vulnerabilities_found = []
        
    def start_scan(self, target: str):
        """Log scan start."""
        self.scan_start_time = datetime.now()
        self.vulnerabilities_found = []
        self.logger.info(f"Starting scan of target: {target}")
        self.logger.info(f"Scan started at: {self.scan_start_time}")
        
    def end_scan(self):
        """Log scan end."""
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            self.logger.info(f"Scan completed in: {duration}")
            self.logger.info(f"Total vulnerabilities found: {len(self.vulnerabilities_found)}")
            
    def log_vulnerability(self, vuln_type: str, severity: str, description: str, url: str = ""):
        """Log vulnerability discovery."""
        self.vulnerabilities_found.append({
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'url': url,
            'timestamp': datetime.now()
        })
        
        log_vulnerability(self.logger, vuln_type, severity, description)
        
    def log_scan_step(self, step: str, status: str = "started"):
        """Log scan step."""
        self.logger.info(f"Scan step: {step} - {status}")
        
    def log_error(self, error: Exception, step: str = ""):
        """Log scan error."""
        if step:
            log_error(self.logger, error, step)
        else:
            log_error(self.logger, error)
            
    def get_summary(self) -> dict:
        """Get scan summary."""
        if not self.vulnerabilities_found:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
        severity_counts = {}
        for vuln in self.vulnerabilities_found:
            severity = vuln['severity'].lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        return {
            'total': len(self.vulnerabilities_found),
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0)
        }
