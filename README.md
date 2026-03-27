# Host Sniper

A comprehensive security scanning and reconnaissance tool that combines the functionality of tools into a unified platform.

### 
                            __  __           __     _____       _                
                           / / / /___  _____/ /_   / ___/____  (_)___  ___  _____
                          / /_/ / __ \/ ___/ __/   \__ \/ __ \/ / __ \/ _ \/ ___/
                         / __  / /_/ (__  ) /_    ___/ / / / / / /_/ /  __/ /    
                        /_/ /_/\____/____/\__/   /____/_/ /_/_/ .___/\___/_/     
                                                             /_/                 



## Features

### Tool Features
- **Port Scanner** - TCP port enumeration with common-port and full-range options; supports rate limiting, concurrency, and retry logic
- **Host Scanner** - CIDR range scanning and host availability checks using fast multithreaded workers
- **Subdomain Finder** - Enumerates subdomains via built-in services, brute-force candidate generation, and wildcard detection
- **IP Lookup** - Performs IP geolocation, ASN lookup, ping check, and reverse DNS results
- **Reverse IP Lookup** - Finds all domains hosted on a target IP using external lookup services
- **WHOIS Lookup** - Retrieves domain WHOIS data, expiry, registrar, and contact details
- **SSL Analysis** - Runs `sslscan` integration to collect certificate chain, supported protocols/ciphers, and expiry status
- **DNS Records** - Queries A, AAAA, MX, NS, TXT, and CNAME records with configurable DNS resolver
- **Host Info** - Displays local system details, network interfaces, and environment information

### Advanced Capabilities
- Configurable concurrency with thread pools and timeouts
- Built-in rate limiter and retry mechanism to avoid service throttling
- Proxy support for direct scan requests
- Rich CLI experience with progress bars, status updates, and error handling
- Portable architecture ready for packaging with setuptools and PyPI deployment

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


## Join us
[MalwareDot](https://t.me/malwaredot) \
[Telegram Group](https://t.me/Hack_institute_chat)
