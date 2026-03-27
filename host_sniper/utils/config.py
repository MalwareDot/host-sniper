"""
Configuration utilities
"""
import os
from pathlib import Path


class Config:
    """Configuration management"""
    
    # Default values
    DEFAULT_THREADS = 50
    DEFAULT_TIMEOUT = 3
    DEFAULT_PORTS = ['80', '443']
    DEFAULT_METHODS = ['GET', 'HEAD']
    
    # Common ports for scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        8443, 8888
    ]
    
    # Output directory
    OUTPUT_DIR = Path.home() / '.host_sniper'
    
    @classmethod
    def ensure_output_dir(cls):
        """Ensure output directory exists"""
        cls.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        return cls.OUTPUT_DIR

    @classmethod
    def get_config_path(cls):
        """Get config file path"""
        return cls.OUTPUT_DIR / 'config.json'
