"""
Input validation utilities
"""
import re
import ipaddress
import os


class Validators:
    """Input validation utilities"""
    
    @staticmethod
    def is_valid_ip(ip):
        """Validate IP address"""
        if not ip or not isinstance(ip, str):
            return False
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_cidr(cidr):
        """Validate CIDR notation"""
        if not cidr or not isinstance(cidr, str):
            return False
        cidr = cidr.strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain):
        """Validate domain name"""
        if not domain or not isinstance(domain, str):
            return False
        domain = domain.strip().lower()
        
        # Check length
        if len(domain) > 253:
            return False
        
        # Check for valid characters and structure
        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(pattern, domain):
            return False
        
        # Check for consecutive hyphens or starting/ending with hyphen
        if '--' in domain or domain.startswith('-') or domain.endswith('-'):
            return False
        
        return True
    
    @staticmethod
    def is_valid_port(port):
        """Validate port number"""
        try:
            if isinstance(port, str):
                port = port.strip()
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def is_valid_url(url):
        """Validate URL"""
        if not url or not isinstance(url, str):
            return False
        url = url.strip()
        pattern = r'^https?://[\w.-]+(?:\.[a-z]{2,})?(?::\d+)?(?:/.*)?$'
        return bool(re.match(pattern, url, re.IGNORECASE))
    
    @staticmethod
    def is_valid_filename(filename):
        """Validate filename for security"""
        if not filename or not isinstance(filename, str):
            return False
        filename = filename.strip()
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        if any(char in filename for char in dangerous_chars):
            return False
        
        # Check for path traversal
        if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
            return False
        
        # Check length
        if len(filename) > 255:
            return False
        
        return bool(filename)
    
    @staticmethod
    def sanitize_input(text, max_length=1000):
        """Sanitize text input"""
        if not text or not isinstance(text, str):
            return ""
        
        # Remove null bytes and other dangerous characters
        text = text.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def parse_port_list(port_str):
        """Parse comma-separated port list with validation"""
        if not port_str or not isinstance(port_str, str):
            return []
        
        ports = []
        parts = port_str.split(',')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            if '-' in part:
                # Handle ranges
                range_parts = part.split('-')
                if len(range_parts) != 2:
                    continue
                try:
                    start = int(range_parts[0].strip())
                    end = int(range_parts[1].strip())
                    if not (1 <= start <= 65535 and 1 <= end <= 65535):
                        continue
                    if start > end:
                        continue
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                # Handle single ports
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
                except ValueError:
                    continue
        
        return sorted(set(ports))
    
    @staticmethod
    def parse_hosts_from_file(filepath):
        """Parse hosts from file with validation"""
        if not filepath or not isinstance(filepath, str):
            return []
        
        filepath = filepath.strip()
        if not os.path.isfile(filepath):
            return []
        
        hosts = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Basic validation
                    line = line.lower()
                    if Validators.is_valid_ip(line) or Validators.is_valid_domain(line):
                        hosts.append(line)
                    elif Validators.is_valid_cidr(line):
                        # Expand CIDR to individual IPs (limit to reasonable size)
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            if network.num_addresses <= 1024:  # Limit to prevent huge expansions
                                hosts.extend(str(ip) for ip in network.hosts())
                        except:
                            pass
        except Exception:
            return []
        
        return list(set(hosts))  # Remove duplicates
