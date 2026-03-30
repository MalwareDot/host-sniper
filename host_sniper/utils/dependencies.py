"""
Dependency manager for Host Sniper
Handles automatic installation of required external tools
"""
import subprocess
import sys
import shutil
import platform
from rich.console import Console

console = Console()


def is_command_available(command):
    """Check if a command is available in PATH"""
    return shutil.which(command) is not None


def install_go_tool(package_url, tool_name):
    """
    Install a Go-based tool
    
    Args:
        package_url: Full go install URL (e.g., "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        tool_name: Name of the tool (e.g., "subfinder")
    """
    if is_command_available(tool_name):
        console.print(f"[green][✓] {tool_name} is already installed[/green]")
        return True
    
    console.print(f"[yellow][*] {tool_name} not found. Attempting to install...[/yellow]")
    
    # Check if Go is installed
    if not is_command_available("go"):
        console.print(f"[red][!] Go is not installed. Please install Go from https://golang.org[/red]")
        console.print(f"[yellow]Then run: go install -v {package_url}[/yellow]")
        return False
    
    try:
        console.print(f"[cyan]Running: go install -v {package_url}[/cyan]")
        result = subprocess.run(
            ["go", "install", "-v", f"{package_url}"],
            check=True
        )
        
        if is_command_available(tool_name):
            console.print(f"[green][✓] {tool_name} installed successfully[/green]")
            return True
        else:
            console.print(f"[yellow][!] Go install completed but {tool_name} not found in PATH[/yellow]")
            console.print(f"[yellow]Make sure $GOPATH/bin is in your PATH environment variable[/yellow]")
            return False
            
    except subprocess.CalledProcessError as e:
        console.print(f"[red][!] Failed to install {tool_name}: {e}[/red]")
        console.print(f"[yellow]Try installing manually: go install -v {package_url}[/yellow]")
        return False
    except Exception as e:
        console.print(f"[red][!] Error installing {tool_name}: {e}[/red]")
        return False


def install_apt_package(package_name, apt_name=None):
    """
    Install a package using apt (Linux/Debian)
    
    Args:
        package_name: Package name to check with 'which'
        apt_name: Apt package name (default: same as package_name)
    """
    if apt_name is None:
        apt_name = package_name
    
    if is_command_available(package_name):
        console.print(f"[green][✓] {package_name} is already installed[/green]")
        return True
    
    if platform.system() != "Linux":
        console.print(f"[yellow][!] {package_name} not found[/yellow]")
        console.print(f"[yellow]Please install it manually for your OS[/yellow]")
        return False
    
    console.print(f"[yellow][*] {package_name} not found. Attempting to install via apt...[/yellow]")
    
    try:
        console.print(f"[cyan]Running: sudo apt-get install -y {apt_name}[/cyan]")
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y", apt_name],
            check=True
        )
        
        if is_command_available(package_name):
            console.print(f"[green][✓] {package_name} installed successfully[/green]")
            return True
        else:
            console.print(f"[red][!] Installation completed but {package_name} not found in PATH[/red]")
            return False
            
    except subprocess.CalledProcessError as e:
        console.print(f"[red][!] Failed to install {package_name}: {e}[/red]")
        return False
    except Exception as e:
        console.print(f"[red][!] Error installing {package_name}: {e}[/red]")
        return False


def install_pip_package(package_name, pip_name=None):
    """
    Install a Python package using pip
    
    Args:
        package_name: Package import name
        pip_name: Pip package name (default: same as package_name)
    """
    if pip_name is None:
        pip_name = package_name
    
    try:
        __import__(package_name)
        console.print(f"[green][✓] {package_name} is already installed[/green]")
        return True
    except ImportError:
        pass
    
    console.print(f"[yellow][*] {package_name} not found. Installing via pip...[/yellow]")
    
    try:
        console.print(f"[cyan]Running: pip install {pip_name}[/cyan]")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
        
        try:
            __import__(package_name)
            console.print(f"[green][✓] {package_name} installed successfully[/green]")
            return True
        except ImportError:
            console.print(f"[red][!] Installation completed but import failed[/red]")
            return False
            
    except subprocess.CalledProcessError as e:
        console.print(f"[red][!] Failed to install {package_name}: {e}[/red]")
        return False
    except Exception as e:
        console.print(f"[red][!] Error installing {package_name}: {e}[/red]")
        return False


def check_and_install_dependencies():
    """Check and install all required dependencies"""
    console.print("\n[bold cyan]Checking dependencies...[/bold cyan]")
    
    all_ok = True
    
    # Check Go-based tools
    console.print("\n[bold yellow]Go Tools:[/bold yellow]")
    
    # Subfinder
    if not install_go_tool("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"):
        console.print("[yellow][!] Subfinder is optional - subdomain enumeration will not work without it[/yellow]")
        all_ok = False
    
    # Check CLI tools
    console.print("\n[bold yellow]CLI Tools:[/bold yellow]")
    
    # sslscan
    if not is_command_available("sslscan"):
        console.print(f"[yellow][!] sslscan not found - SSL analysis will not work[/yellow]")
        if platform.system() == "Linux":
            install_apt_package("sslscan", "sslscan")
        else:
            console.print(f"[yellow]Please install sslscan from https://github.com/rbsec/sslscan[/yellow]")
        all_ok = False
    else:
        console.print(f"[green][✓] sslscan is installed[/green]")
    
    # Check Python packages
    console.print("\n[bold yellow]Python Packages:[/bold yellow]")
    
    install_pip_package("whois", "python-whois")
    install_pip_package("dns", "dnspython")
    install_pip_package("requests")
    install_pip_package("rich")
    
    if all_ok:
        console.print("\n[bold green][✓] All critical dependencies are installed[/bold green]")
    else:
        console.print("\n[bold yellow][!] Some optional dependencies are missing[/bold yellow]")
        console.print("[yellow]Some features may not work properly[/yellow]")
    
    return all_ok
