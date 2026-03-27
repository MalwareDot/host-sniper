# Host Sniper - Quick Start Guide

## Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
# Option 1: Direct execution
python -m host_sniper.main

# Option 2: Install and run
pip install -e .
host-sniper
```

## Quick Examples

### Port Scanning
```
Menu Choice: 1 (PORT SCANNER)
Enter target: example.com
Select scan type: 1 (Common ports)
```

### Host Information
```
Menu Choice: 7 (HOST INFO)
Displays system hostname, platform, and architecture
```

### IP Lookup
```
Menu Choice: 3 (IP LOOKUP)
Enter target: 8.8.8.8 or google.com
Displays IP and domain information
```

### Subdomain Enumeration
```
Menu Choice: 2 (SUBDOMAIN FINDER)
Enter domain: example.com
Enumerates subdomains (requires sources)
```

### Host/CIDR Scanning
```
Menu Choice: 5 (HOST SCANNER)
Options: File, CIDR range, or single IP
Batch scan hosts with various methods
```

### DNS Records
```
Menu Choice: 6 (DNS RECORDS)
Enter domain: example.com
Query and display DNS records
```

## Command Line Usage

To run specific scanners programmatically:

```python
from host_sniper.scanners import port_scanner
from host_sniper.utils import validators

# Scan a target
open_ports = port_scanner.scan_host_ports("example.com", "common")
print(f"Open ports: {open_ports}")

# Validate input
is_valid = validators.Validators.is_valid_cidr("192.168.1.0/24")
```

## Project Structure

```
host_sniper/
├── core/          # Base scanner classes
├── scanners/      # Specific scanning tools
├── utils/         # Helper utilities
├── handler.py     # Command handlers
└── main.py        # CLI interface
```

## Key Features

✓ Multi-threaded scanning for speed
✓ CIDR range support
✓ Multiple HTTP methods
✓ Proxy support
✓ SSL/TLS validation
✓ User-friendly CLI interface
✓ Comprehensive error handling

## Troubleshooting

### Import Errors
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Verify Python version is 3.8+: `python --version`

### Scanning Issues
- Check target is reachable: `ping example.com`
- Verify firewall allows connections
- Increase timeout for slow networks

### File Operations
- Ensure file paths are absolute or relative to current directory
- Check file permissions for read/write operations

## Advanced Usage

### Custom Port List
Edit the `COMMON_PORTS` in `host_sniper/scanners/port_scanner.py`

### Thread Configuration
Modify `DEFAULT_THREADS` in `host_sniper/utils/config.py`

### Timeout Settings
Adjust `DEFAULT_TIMEOUT` for network conditions

## Support

For issues or feature requests, refer to:
- README.md - Full documentation
- STRUCTURE.md - Project architecture
- handler.py - Available commands

## License

MIT License - See LICENSE file
