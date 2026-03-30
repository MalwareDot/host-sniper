"""
Main handler for CLI menu and operations
"""
from host_sniper.scanners import port_scanner, host_scanner
from host_sniper.utils import validators
from host_sniper.bugscanner import DirectScanner, ProxyScanner, SSLScanner, UdpScanner
import subprocess
import os
import socket
import ssl
from pathlib import Path
from datetime import datetime
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
    from host_sniper.utils.dependencies import is_command_available, install_go_tool
    
    domain = input("Enter domain to enumerate: ").strip()
    
    if not validators.Validators.is_valid_domain(domain):
        console.print("[red]Invalid domain format[/red]")
        return
    
    # Check and install subfinder if not available
    if not is_command_available("subfinder"):
        console.print("[yellow][!] subfinder not found[/yellow]")
        choice = input("Install subfinder now? [y/N]: ").strip().lower()
        if choice == 'y':
            if not install_go_tool("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"):
                console.print("[red]Failed to install subfinder. Aborting.[/red]")
                return
        else:
            console.print("[red]subfinder is required for subdomain enumeration[/red]")
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
        console.print("[bold cyan]subfinder output:[/bold cyan]")
        
        # Run without capturing output - let user see the tool's output
        result = subprocess.run(cmd, text=True)
        
        if result.returncode == 0:
            console.print(f"\n[bold green][✓] Subdomain enumeration completed[/bold green]")
            console.print(f"[cyan]Results saved to: {output_file}[/cyan]\n")
            
            # Try to read and display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    if subdomains:
                        console.print(f"[bold cyan]Found {len(subdomains)} subdomains:[/bold cyan]")
                        for subdomain in subdomains[:20]:  # Show first 20
                            console.print(f"  • {subdomain}")
                        if len(subdomains) > 20:
                            console.print(f"  ... and {len(subdomains) - 20} more")
            except Exception as e:
                console.print(f"[yellow]Could not read results file: {e}[/yellow]")
        else:
            console.print(f"\n[bold red][!] Subfinder failed with exit code {result.returncode}[/bold red]")
    
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
    from host_sniper.utils.dependencies import install_pip_package
    
    # Try to import whois, install if needed
    try:
        import whois
    except ImportError:
        console.print("[yellow][*] python-whois not found. Installing...[/yellow]")
        if not install_pip_package("whois", "python-whois"):
            console.print("[red]Failed to install python-whois[/red]")
            return
        import whois
    
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




def run_ssl_analysis():
    """Run SSL certificate analysis using sslscan"""
    from host_sniper.utils.dependencies import is_command_available, install_apt_package
    
    target = input("Enter domain or IP address: ").strip()

    if not validators.Validators.is_valid_domain(target) and not validators.Validators.is_valid_ip(target):
        console.print("[red]Invalid domain or IP address[/red]")
        return

    port = input("Enter port [443]: ").strip() or "443"
    try:
        port = int(port)
    except ValueError:
        console.print("[red]Invalid port number[/red]")
        return

    # Check and install sslscan if not available
    if not is_command_available("sslscan"):
        console.print("[yellow][!] sslscan not found[/yellow]")
        choice = input("Install sslscan now? [y/N]: ").strip().lower()
        if choice == 'y':
            if not install_apt_package("sslscan", "sslscan"):
                console.print("[red]Failed to install sslscan. Please install manually from https://github.com/rbsec/sslscan[/red]")
                return
        else:
            console.print("[red]sslscan is required for SSL analysis[/red]")
            return

    output_file = f"{target}_{port}_sslscan.txt"
    cmd = ["sslscan", f"{target}:{port}"]

    console.print(f"[bold blue]Running sslscan on {target}:{port}...[/bold blue]")
    console.print(f"[cyan]Output file: {output_file}[/cyan]\n")

    try:
        console.print("[bold cyan]sslscan output:[/bold cyan]")
        
        # Run without capturing - let user see the tool output
        with open(output_file, 'w') as out_file:
            result = subprocess.run(cmd, text=True, stdout=out_file, stderr=subprocess.STDOUT)

        if result.returncode == 0:
            # Display the output that was saved
            console.print("\n")
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        console.print(f"[grey58]{line}[/grey58]")
            except:
                pass
            
            console.print(f"\n[green][✓] sslscan output saved to {output_file}[/green]")
        else:
            console.print(f"\n[bold red][!] sslscan failed with exit code {result.returncode}[/bold red]")

    except FileNotFoundError:
        console.print('[red]sslscan command not found. Please install sslscan from https://github.com/rbsec/sslscan and ensure it is in your PATH.[/red]')
    except subprocess.TimeoutExpired:
        console.print('[red]sslscan command timed out. Try increasing timeout or checking network connectivity.[/red]')
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


def run_dns_records():
    """Lookup DNS records for a domain"""
    domain = input("Enter domain to lookup: ").strip()
    
    if not validators.Validators.is_valid_domain(domain):
        console.print("[red]Invalid domain format[/red]")
        return
    
    console.print(f"\n[bold cyan]DNS Records for {domain}:[/bold cyan]")
    console.print("=" * 60)
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
    results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=2
    ) as progress:
        task = progress.add_task("Querying DNS records...", total=len(record_types))
        
        for record_type in record_types:
            progress.update(task, description=f"Querying {record_type} records...")
            try:
                answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                if answers:
                    results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                console.print(f"\n[red]Domain {domain} does not exist[/red]")
                return
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except Exception as e:
                results[record_type] = [f"Error: {e}"]
            progress.update(task, advance=1)
    
    # Display results
    console.print()
    for record_type in record_types:
        if record_type in results and results[record_type]:
            console.print(f"[bold cyan]{record_type} Records:[/bold cyan]")
            for record in results[record_type]:
                console.print(f"  • {record}")
        else:
            console.print(f"[yellow]{record_type} Records:[/yellow] [dim]None found[/dim]")
    
    # Save to file option
    save_choice = input("\nSave results to file? [y/N]: ").strip().lower()
    if save_choice == 'y':
        filename = input("Enter filename: ").strip() or f"{domain}_dns_records.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"DNS Records for {domain}\n")
                f.write("=" * 60 + "\n\n")
                for record_type in record_types:
                    if record_type in results and results[record_type]:
                        f.write(f"{record_type} Records:\n")
                        for record in results[record_type]:
                            f.write(f"  {record}\n")
                    else:
                        f.write(f"{record_type} Records: None found\n")
                    f.write("\n")
            console.print(f"[green][✓] Results saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save results: {e}[/red]")


def run_help():
    """Display help information"""
    help_text = """
[bold cyan]Host Sniper - Combined Security Scanner[/bold cyan]

[bold yellow]Available Menu Options:[/bold yellow]
  1. PORT SCANNER - Scan open ports on target hosts
  2. SUBDOMAIN FINDER - Enumerate subdomains using subfinder
  3. IP LOOKUP - Lookup IP/domain DNS information  
  4. REVERSE IP LOOKUP - Reverse lookup domains from IP addresses
  5. WHOIS LOOKUP - Get WHOIS information for domains/IPs
  6. SSL ANALYSIS - Analyze SSL/TLS certificates using sslscan
  7. HOST SCANNER - Scan networks using BugScanner with multiple modes
  8. DNS RECORDS - Query detailed DNS records (A, AAAA, MX, NS, etc.)
  9. HOST INFO - Get hostname and DNS information for a domain
  10. HELP - Show this help message
  0. EXIT - Quit the application
  
[bold yellow]Key Features:[/bold yellow]
  • Multi-threaded scanning for better performance
  • Batch processing from input files
  • Multiple scanning modes (Direct, Proxy, SSL, UDP)
  • Automatic dependency installation
  • Real-time 3rd-party tool output display
  • Results saved to output files
  • Rate limiting for API calls
  • DNS resolver with configurable servers

[bold yellow]Required External Tools:[/bold yellow]
  • subfinder - Go tool for subdomain enumeration
    Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  • sslscan - Command-line SSL/TLS analyzer
    Install: apt-get install sslscan (Linux) OR https://github.com/rbsec/sslscan

[bold yellow]Python Dependencies:[/bold yellow]
  All Python dependencies (requests, rich, dnspython, python-whois) will be
  installed automatically on first run if not already present.

[bold yellow]Usage Tips:[/bold yellow]
  • Most tools support batch operations from text files
  • Results are automatically saved with timestamps
  • Use rate limiting for bulk API operations
  • Enable proxy mode for anonymized scanning
  • Check tool logs for detailed error messages
"""
    console.print(help_text)


def run_file_toolkit():
    """Run file toolkit"""
    print("\n[bold cyan]File Toolkit[/bold cyan]")
    print("[yellow]File analysis tools (work in progress)[/yellow]")
