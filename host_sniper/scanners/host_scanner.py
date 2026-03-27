"""
Host/CIDR scanner module
"""
import ipaddress
from rich import print


def read_cidrs_from_file(filepath):
    """Read and validate CIDR ranges from file"""
    valid_cidrs = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    valid_cidrs.append(line)
                except ValueError:
                    pass
            
        return valid_cidrs
    except Exception as e:
        print(f"[bold red]Error reading file: {e}[/bold red]")
        return []


def get_cidr_ranges_from_input(cidr_input):
    """Parse comma-separated CIDR ranges"""
    return [c.strip() for c in cidr_input.split(',')]


def validate_cidr(cidr):
    """Validate CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr_range):
    """Expand CIDR range to individual IPs"""
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def is_valid_domain(domain):
    """Validate domain name format"""
    if not domain or len(domain) > 253:
        return False
    
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
    return all(c in allowed for c in domain) and not domain.startswith('-') and not domain.endswith('-')
