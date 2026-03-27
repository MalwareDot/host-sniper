"""
Main handler for CLI menu and operations
"""
from host_sniper.scanners import port_scanner, host_scanner
from host_sniper.utils import validators
from host_sniper.bugscanner import DirectScanner, ProxyScanner, SSLScanner, UdpScanner
import subprocess
import os
import socket
from pathlib import Path
import dns.resolver
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()


def run_port_scan():
    """Run port scanner"""
    target = input("Enter target hostname or IP: ").strip()
    
    if not target:
        console.print("[red]Error: Target required[/red]")
        return
    
    console.print("\n[bold cyan]Port Scan Options:[/bold cyan]")
    console.print("1. Common ports (22 most common)")
    console.print("2. All ports (1-65535)")
    
    choice = input("Select scan type [1/2]: ").strip()
    scan_type = "all" if choice == "2" else "common"
    
    console.print(f"\n[bold blue]Starting {scan_type} port scan on {target}...[/bold blue]")
    open_ports = port_scanner.scan_host_ports(target, scan_type)
    
    if open_ports:
        console.print(f"\n[bold green]Open ports found: {', '.join(map(str, open_ports))}[/bold green]")
    else:
        console.print("\n[yellow]No open ports found[/yellow]")


def run_host_scan():
    """Run host scanner using integrated BugScanner classes"""
    console.print("\n[bold cyan]Host Scanner - BugScanner[/bold cyan]")
    
    # Get input file
    filename = input("Enter filename with hosts: ").strip()
    if not filename or not os.path.isfile(filename):
        console.print("[red]File not found[/red]")
        return
    
    # Get scan mode
    console.print("\n[bold cyan]Scan Mode:[/bold cyan]")
    console.print("1. Direct (default)")
    console.print("2. Proxy")
    console.print("3. SSL")
    console.print("4. UDP")
    
    mode_choice = input("Select mode [1-4]: ").strip() or "1"
    mode_map = {"1": "direct", "2": "proxy", "3": "ssl", "4": "udp"}
    mode = mode_map.get(mode_choice, "direct")
    
    # Get HTTP methods (for direct mode)
    methods = "head"
    if mode == "direct":
        methods = input("Enter HTTP methods (comma-separated) [head]: ").strip() or "head"
    
    # Get ports
    ports = input("Enter ports (comma-separated) [80]: ").strip() or "80"
    
    # Read hosts
    try:
        with open(filename, 'r') as f:
            host_list = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Failed to read hosts: {e}[/red]")
        return
    
    # Prepare scanner
    if mode == "direct":
        scanner = DirectScanner()
        scanner.method_list = [m.strip() for m in methods.split(',')]
        scanner.host_list = host_list
        scanner.port_list = [p.strip() for p in ports.split(',')]
    elif mode == "proxy":
        scanner = ProxyScanner()
        scanner.method_list = ["GET"]  # Default for proxy
        scanner.host_list = host_list
        scanner.port_list = [p.strip() for p in ports.split(',')]
        proxy = input("Enter proxy (host:port) [required]: ").strip()
        if not proxy or ':' not in proxy:
            console.print("[red]Proxy must be in host:port format[/red]")
            return
        scanner.proxy = proxy.split(':')
    elif mode == "ssl":
        scanner = SSLScanner()
        scanner.host_list = host_list
    elif mode == "udp":
        scanner = UdpScanner()
        scanner.host_list = host_list
        scanner.udp_server_host = 'bugscanner.tppreborn.my.id'
        scanner.udp_server_port = '8853'
    else:
        console.print("[red]Invalid mode[/red]")
        return
    
    threads = input("Enter number of threads [default: 10]: ").strip()
    try:
        scanner.threads = int(threads) if threads else 10
    except Exception:
        scanner.threads = 10
    
    console.print(f"\n[bold blue]Starting scan with mode: {mode}[/bold blue]")
    try:
        scanner.init()
        for task in scanner.get_task_list():
            scanner.task(task)
        scanner.complete()
        console.print("\n[bold green][✓] Scan completed successfully[/bold green]")
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")


def run_subdomain_enum():
    """Run subdomain enumeration using subfinder"""
    domain = input("Enter domain to enumerate: ").strip()
    
    if not validators.Validators.is_valid_domain(domain):
        console.print("[red]Invalid domain format[/red]")
        return
    
    output_file = f"{domain}_subdomains.txt"
    
    console.print(f"[bold blue]Starting subdomain enumeration for {domain}...[/bold blue]")
    console.print(f"[cyan]Output file: {output_file}[/cyan]\n")
    
    # Build subfinder command
    cmd = [
        "subfinder",
        "-d", domain,
        "-o", output_file
    ]
    
    try:
        console.print(f"[cyan]Running: {' '.join(cmd)}[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            refresh_per_second=2
        ) as progress:
            task = progress.add_task("Enumerating subdomains...", total=None)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            progress.update(task, completed=True)
        
        if result.returncode == 0:
            console.print(f"[bold green][✓] Subdomain enumeration completed[/bold green]")
            console.print(f"[cyan]Results saved to: {output_file}[/cyan]\n")
            
            # Try to read and display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.read().strip().split('\n')
                    console.print(f"[bold cyan]Found {len(subdomains)} subdomains:[/bold cyan]")
                    for subdomain in subdomains[:20]:  # Show first 20
                        console.print(f"  • {subdomain}")
                    if len(subdomains) > 20:
                        console.print(f"  ... and {len(subdomains) - 20} more")
            except Exception as e:
                console.print(f"[yellow]Could not read results file: {e}[/yellow]")
        else:
            console.print(f"[bold red][!] Subfinder failed[/bold red]")
            if result.stderr:
                console.print(f"[red]Error: {result.stderr}[/red]")
            console.print(f"[yellow]Make sure subfinder is installed: go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder[/yellow]")
    
    except FileNotFoundError:
        console.print("[red]subfinder not found. Install it:[/red]")
        console.print("[cyan]go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder[/cyan]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


def run_ip_lookup():
    """Run IP lookup"""
    from host_sniper.scanners import ip_lookup
    
    target = input("Enter IP address or domain: ").strip()
    
    if ip_lookup.is_valid_ip(target):
        console.print(f"[green]IP: {target}[/green]")
        info = ip_lookup.get_ip_info(target)
        console.print(f"Hostname: {info['hostname']}")
    elif validators.Validators.is_valid_domain(target):
        console.print(f"[green]Domain: {target}[/green]")
        try:
            ip = socket.gethostbyname(target)
            console.print(f"IP Address: {ip}")
            info = ip_lookup.get_ip_info(ip)
            console.print(f"Hostname: {info['hostname']}")
        except socket.gaierror:
            console.print("[red]Unable to resolve domain[/red]")
    else:
        console.print("[red]Invalid IP address or domain[/red]")


def get_domains_from_hackertarget(ip):
    """Get domains from hackertarget API"""
    from host_sniper.utils.rate_limit import rate_limited
    return rate_limited(lambda: _get_domains_from_hackertarget(ip))()

def _get_domains_from_hackertarget(ip):
    """Internal function for hackertarget API call"""
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            domains = [line.strip() for line in response.text.split('\n') if line.strip() and not line.startswith('API count exceeded')]
            return domains
    except:
        pass
    return []


def get_domains_from_sonar(ip):
    """Get domains from sonar.omnisint.io API"""
    from host_sniper.utils.rate_limit import rate_limited
    return rate_limited(lambda: _get_domains_from_sonar(ip))()

def _get_domains_from_sonar(ip):
    """Internal function for sonar API call"""
    try:
        url = f"https://sonar.omnisint.io/reverse/{ip}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data if isinstance(data, list) else []
    except:
        pass
    return []


def run_reverse_ip_lookup():
    """Run reverse IP lookup for single IP or from file"""
    from host_sniper.scanners import ip_lookup
    from host_sniper.utils.rate_limit import api_limiter
    
    console.print("\n[bold cyan]Reverse IP Lookup[/bold cyan]")
    console.print("1. Single IP address")
    console.print("2. From text file (one IP per line)")
    
    choice = input("Select option [1/2]: ").strip()
    
    if choice == '1':
        target_ip = input("Enter IP address: ").strip()
        if not ip_lookup.is_valid_ip(target_ip):
            console.print("[red]Invalid IP address[/red]")
            return
        ips = [target_ip]
    elif choice == '2':
        filename = input("Enter filename with IPs: ").strip()
        if not filename or not os.path.isfile(filename):
            console.print("[red]File not found[/red]")
            return
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip() and ip_lookup.is_valid_ip(line.strip())]
            if not ips:
                console.print("[red]No valid IPs found in file[/red]")
                return
        except Exception as e:
            console.print(f"[red]Failed to read file: {e}[/red]")
            return
    else:
        console.print("[red]Invalid choice[/red]")
        return
    
    output_file = input("Enter output filename: ").strip()
    if not output_file:
        output_file = "reverse_lookup_results.txt"
    
    console.print(f"\n[bold blue]Performing reverse lookup for {len(ips)} IP(s)...[/bold blue]")
    
    all_domains = set()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=2
    ) as progress:
        
        main_task = progress.add_task("Processing IPs...", total=len(ips))
        
        for i, ip in enumerate(ips, 1):
            progress.update(main_task, description=f"Processing {ip} ({i}/{len(ips)})")
            
            domains = set()
            
            # Get hostname from socket
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                domains.add(hostname)
            except:
                pass
            
            # Get domains from hackertarget with rate limiting
            try:
                ht_domains = get_domains_from_hackertarget(ip)
                if ht_domains:
                    domains.update(ht_domains)
            except:
                pass
            
            # Get domains from sonar with rate limiting
            try:
                sonar_domains = get_domains_from_sonar(ip)
                if sonar_domains:
                    domains.update(sonar_domains)
            except:
                pass
            
            # Add to global set
            all_domains.update(domains)
            progress.update(main_task, advance=1)
    
    # Save to file
    try:
        with open(output_file, 'w') as f:
            f.write(f"Reverse IP Lookup Results - {len(ips)} IPs processed\n")
            f.write(f"Total unique domains found: {len(all_domains)}\n")
            f.write("=" * 50 + "\n")
            for domain in sorted(all_domains):
                f.write(domain + "\n")
        
        console.print(f"\n[bold green][✓] Results saved to {output_file}[/bold green]")
        console.print(f"[cyan]Total IPs: {len(ips)}, Unique domains: {len(all_domains)}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]Failed to save results: {e}[/red]")


def run_whois_lookup():
    """Run WHOIS lookup for domain or IP"""
    try:
        import whois
    except ImportError:
        console.print("[red]python-whois not installed. Installing...[/red]")
        try:
            import subprocess
            subprocess.check_call(["pip", "install", "python-whois"])
            import whois
        except:
            console.print("[red]Failed to install python-whois. Please install manually: pip install python-whois[/red]")
            return
    
    target = input("Enter domain or IP address: ").strip()
    
    if not validators.Validators.is_valid_domain(target) and not validators.Validators.is_valid_ip(target):
        console.print("[red]Invalid domain or IP address[/red]")
        return
    
    console.print(f"[bold blue]Performing WHOIS lookup for {target}...[/bold blue]")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            refresh_per_second=2
        ) as progress:
            task = progress.add_task("Querying WHOIS database...", total=None)
            
            w = whois.whois(target)
            
            progress.update(task, completed=True)
        
        console.print(f"\n[bold green]WHOIS Information for {target}:[/bold green]")
        console.print("=" * 50)
        
        # Display key information
        fields = [
            ('Domain Name', w.domain_name),
            ('Registrar', w.registrar),
            ('Creation Date', w.creation_date),
            ('Expiration Date', w.expiration_date),
            ('Updated Date', w.updated_date),
            ('Name Servers', w.name_servers),
            ('Status', w.status),
            ('Emails', w.emails),
            ('DNSSEC', w.dnssec),
            ('Organization', w.org),
            ('Country', w.country),
            ('State', w.state),
            ('City', w.city)
        ]
        
        for field_name, value in fields:
            if value:
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                console.print(f"[cyan]{field_name}:[/cyan] {value}")
        
        # Save to file option
        save_choice = input("\nSave results to file? [y/N]: ").strip().lower()
        if save_choice == 'y':
            filename = input("Enter filename: ").strip() or f"{target}_whois.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"WHOIS Information for {target}\n")
                    f.write("=" * 50 + "\n")
                    for field_name, value in fields:
                        if value:
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value)
                            f.write(f"{field_name}: {value}\n")
                console.print(f"[green]Results saved to {filename}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save file: {e}[/red]")
                
    except Exception as e:
        console.print(f"[red]WHOIS lookup failed: {e}[/red]")
        console.print("[yellow]Make sure python-whois is installed: pip install python-whois[/yellow]")


def run_ssl_analysis():
    """Run SSL certificate analysis using sslscan"""
    target = input("Enter domain or IP address: ").strip()

    if not validators.Validators.is_valid_domain(target) and not validators.Validators.is_valid_ip(target):
        console.print("[red]Invalid domain or IP address[/red]")
        return

    port = input("Enter port [443]: ").strip() or "443"
    try:
        port = int(port)
    except:
        console.print("[red]Invalid port number[/red]")
        return

    output_file = f"{target}_sslscan.txt"

    cmd = [
        "sslscan",
        "--no-failed",
        "--no-rejected",
        "--no-compression",
        "--no-heartbleed",
        "--no-renegotiation",
        "--no-resumption",
        f"{target}:{port}"
    ]

    console.print(f"[bold blue]Running sslscan on {target}:{port}...[/bold blue]")
    console.print(f"[cyan]Output file: {output_file}[/cyan]\n")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            refresh_per_second=2
        ) as progress:
            task = progress.add_task("Scanning SSL/TLS configuration...", total=None)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            progress.update(task, completed=True)

        if result.returncode != 0:
            console.print(f"[red]sslscan failed with exit code {result.returncode}[/red]")
            if result.stderr:
                console.print(f"[red]stderr: {result.stderr}[/red]")
            return

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"sslscan Results for {target}:{port}\n")
            f.write("=" * 50 + "\n")
            f.write(result.stdout)

        console.print(f"[green][✓] sslscan completed and output saved to {output_file}[/green]")

        cert_info = {}
        vulnerabilities = []
        cipher_info = []

        for line in result.stdout.splitlines():
            l = line.strip()
            if l.lower().startswith('subject:'):
                cert_info['Subject'] = l.split(':', 1)[1].strip()
            elif l.lower().startswith('issuer:'):
                cert_info['Issuer'] = l.split(':', 1)[1].strip()
            elif l.lower().startswith('not before:'):
                cert_info['Not Before'] = l.split(':', 1)[1].strip()
            elif l.lower().startswith('not after:'):
                cert_info['Not After'] = l.split(':', 1)[1].strip()
            elif l.lower().startswith('cipher'):
                cipher_info.append(l)
            elif 'vulnerable' in l.lower() or 'weak' in l.lower():
                vulnerabilities.append(l)

        console.print('\n[bold cyan]sslscan Summary:[/bold cyan]')
        for k, v in cert_info.items():
            console.print(f"[green]{k}:[/green] {v}")

        if cipher_info:
            console.print('\n[cyan]Supported cipher details:[/cyan]')
            for c in cipher_info[:10]:
                console.print(f"  • {c}")
            if len(cipher_info) > 10:
                console.print(f"  ... and {len(cipher_info) - 10} more")

        if vulnerabilities:
            console.print('\n[bold red]Potential issues found:[/bold red]')
            for v in vulnerabilities:
                console.print(f"[red]• {v}[/red]")
        else:
            console.print('\n[bold green]No immediate SSL vulnerabilities detected in sslscan output[/bold green]')

    except subprocess.TimeoutExpired:
        console.print('[red]sslscan timed out\n[/red]')
    except FileNotFoundError:
        console.print('[red]sslscan not found. Please install via apt/yum/brew or from https://github.com/rbsec/sslscan[/red]')
    except Exception as e:
        console.print(f"[red]SSL analysis failed: {e}[/red]")


def run_host_info():
    """Get host information for a specific domain"""
    domain = input("Enter domain: ").strip()
    
    if not validators.Validators.is_valid_domain(domain):
        console.print("[red]Invalid domain format[/red]")
        return
    
    console.print(f"\n[bold cyan]Host Information for {domain}:[/bold cyan]")
    
    try:
        # Get IP address
        ip = socket.gethostbyname(domain)
        console.print(f"IP Address: {ip}")
        
        # Get hostname
        hostname = socket.gethostbyaddr(ip)[0]
        console.print(f"Hostname: {hostname}")
        
        # Get aliases
        aliases = socket.gethostbyaddr(ip)[1]
        if aliases:
            console.print(f"Aliases: {', '.join(aliases)}")
        
    except socket.gaierror:
        console.print("[red]Unable to resolve domain[/red]")
    except socket.herror:
        console.print("[red]Unable to get hostname information[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def run_help():
    """Display help information"""
    help_text = """
[bold cyan]Host Sniper - Combined Security Scanner[/bold cyan]

[bold]Available Tools:[/bold]
  1. PORT SCANNER - Scan ports on target hosts
  2. SUBDOMAIN FINDER - Enumerate subdomains using subfinder
  3. IP LOOKUP - Lookup IP/domain information
  4. REVERSE IP LOOKUP - Reverse DNS lookup for IPs
  5. HOST SCANNER - Scan host networks using BugScanner
  6. DNS RECORDS - Lookup DNS records
  7. DOMAIN INFO - Get information for specific domains
  8. HELP - Display this help
  
[bold]Features:[/bold]
  • Multi-threaded scanning
  • CIDR range support
  • Batch processing from files
  • Multiple scan modes
  • Report generation
  • Subprocess integration for external tools

[bold]Usage:[/bold]
  Run the tool and select an option from the menu.
  
[bold]Required Tools:[/bold]
  • subfinder - for subdomain enumeration (go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder)
  • dnspython - for DNS lookups (pip install dnspython)
"""
    console.print(help_text)


def run_file_toolkit():
    """Run file toolkit"""
    print("\n[bold cyan]File Toolkit[/bold cyan]")
    print("[yellow]File analysis tools (work in progress)[/yellow]")
