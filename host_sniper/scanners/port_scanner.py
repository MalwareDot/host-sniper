"""
Port scanning module
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)

console = Console()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888
]


def scan_port(ip, port):
    """Scan a single port on target IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            return port if sock.connect_ex((ip, port)) == 0 else None
    except:
        return None


def scan_host_ports(target, scan_type="common"):
    """
    Scan ports on a target host
    
    Args:
        target: Target hostname or IP
        scan_type: "common" for common ports, "all" for 1-65535
    
    Returns:
        List of open ports
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print(
            "\n[bold red] Failed to resolve hostname",
            "\n[bold red] Please check your target and try again.",
        )
        return []

    ports = COMMON_PORTS if scan_type == "common" else range(1, 65535)
    
    console.print(
        f"\n[bold green] Target Info:[/]\n"
        f" • Host: {target}\n"
        f" • IP: {ip}\n"
    )
    console.print(f"[bold blue] Starting scan...[/]\n")
    
    open_ports = []
    with Progress(
        TextColumn("[bold blue]│[/] {task.description}"),
        BarColumn(complete_style="green"),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(" Scanning ports", total=len(ports))
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, ip, port) for port in ports]
            for future in as_completed(futures):
                if result := future.result():
                    open_ports.append(result)
                    progress.console.print(f" [green]✓[/] Port {result} is open")
                progress.advance(task)

    if not open_ports:
        console.print("\n[yellow] No open ports found.[/]\n")

    return sorted(open_ports)
