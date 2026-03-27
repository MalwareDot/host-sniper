# Host Sniper

A comprehensive security scanning and reconnaissance tool that combines the functionality of BugScanner and BugScanX into a unified platform.

## Features

### Scanning & Enumeration
- **Port Scanner** - Fast multi-threaded port scanning with common and full range options
- **Host Scanner** - CIDR range and batch host scanning
- **Subdomain Finder** - Subdomain enumeration from multiple sources
- **IP Lookup** - IP address and domain information gathering
- **DNS Records** - DNS record enumeration
- **Host Info** - Local system information

### Advanced Capabilities
- Multi-threaded scanning for performance
- CIDR range support with batch processing
- Direct HTTP scanning with multiple methods
- Proxy-based scanning
- SSL/TLS certificate validation
- Configurable timeouts and retries

## Installation

### From Source
```bash
git clone https://github.com/malwaredot/host-sniper.git
cd host-sniper
pip install -r requirements.txt
python -m host_sniper.main
```

### Using pip
```bash
pip install host-sniper
host-sniper
```

## Usage

Run the interactive menu:
```bash
python -m host_sniper.main
```

Or directly:
```bash
host-sniper
```

### Menu Options

1. **PORT SCANNER** - Scan ports on a target host
   - Common ports (22 most common)
   - All ports (1-65535)

2. **SUBDOMAIN FINDER** - Find subdomains for a domain

3. **IP LOOKUP** - Get information about an IP/domain

4. **FILE TOOLKIT** - File analysis utilities

5. **HOST SCANNER** - Scan hosts and CIDR ranges

6. **DNS RECORDS** - Query DNS records

7. **HOST INFO** - Display local system information

8. **HELP** - Display help information

## Architecture

```
host_sniper/
├── core/
│   ├── bug_scanner.py      # Base scanner class
│   ├── direct_scanner.py   # Direct HTTP scanning
│   ├── proxy_scanner.py    # Proxy-based scanning
│   └── ssl_scanner.py      # SSL/TLS scanning
├── scanners/
│   ├── port_scanner.py     # Port enumeration
│   ├── host_scanner.py     # Host/CIDR scanning
│   ├── subfinder.py        # Subdomain enumeration
│   └── ip_lookup.py        # IP reconnaissance
├── utils/
│   ├── config.py           # Configuration management
│   ├── validators.py       # Input validation
│   └── http.py             # HTTP utilities
├── handler.py              # CLI handler
└── main.py                 # Entry point
```

## Requirements

- Python 3.8+
- requests >= 2.28.0
- rich >= 13.0.0
- urllib3 >= 1.26.0

## Configuration

Configuration is stored in `~/.host_sniper/config.json`

Default values:
- Threads: 50
- Timeout: 3 seconds
- Common ports: 22, 80, 443, 8080, 8443, and more

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please submit pull requests or open issues for bugs/features.

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.
