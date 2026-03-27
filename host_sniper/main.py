"""
Host Sniper - Main entry point
"""
import sys
import os
import ctypes
import colorama
from rich.console import Console
from rich.panel import Panel
from rich.align import Align

from host_sniper import handler

# Enable ANSI colors in Windows console
os.system('')

# Enable Virtual Terminal Processing for Windows
def enable_vt_mode():
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(handle, mode)
    except:
        pass

enable_vt_mode()
colorama.init()

console = Console()


def display_banner():
    """Display application banner"""
    banner = r"""
                __  __           __     _____       _                
               / / / /___  _____/ /_   / ___/____  (_)___  ___  _____
              / /_/ / __ \/ ___/ __/   \__ \/ __ \/ / __ \/ _ \/ ___/
             / __  / /_/ (__  ) /_    ___/ / / / / / /_/ /  __/ /    
            /_/ /_/\____/____/\__/   /____/_/ /_/_/ .___/\___/_/     
                                                 /_/                 

                v0.1.1 - BugHost Scanner & Reconnaissance Tool 
    Developed by @MalwareDot | Telegram: @MalwareDot | GitHub: @malwaredot
                    Telegram Group: @Hack_Institute_chat
            """
    panel = Panel(
        Align.center(banner),
        style="bold cyan",
        border_style="cyan"
    )
    console.print(panel)
def display_menu():
    """Display main menu"""
    menu_options = {
        '1': ("PORT SCANNER", "bold cyan"),
        '2': ("SUBDOMAIN FINDER", "bold cyan"),
        '3': ("IP LOOKUP", "bold cyan"),
        '4': ("REVERSE IP LOOKUP", "bold cyan"),
        '5': ("WHOIS LOOKUP", "bold cyan"),
        '6': ("SSL ANALYSIS", "bold cyan"),
        '7': ("HOST SCANNER", "bold cyan"),
        '8': ("DNS RECORDS", "bold cyan"),
        '9': ("DOMAIN INFO", "bold cyan"),
        '10': ("HELP", "bold cyan"),
        '0': ("EXIT", "bold cyan"),
    }
    
    menu_lines = []
    for k, (desc, color) in menu_options.items():
        menu_lines.append(f"[{color}] [{k}]{' ' if len(k)==1 else ''} {desc}")
    
    return '\n'.join(menu_lines), menu_options


def main():
    """Main application loop"""
    try:
        while True:
            display_banner()
            menu_text, menu_options = display_menu()
            console.print(menu_text)
            
            console.print("\n[cyan][-] Your Choice: [/cyan]", end="")
            choice = input().strip()
            
            if choice not in menu_options:
                console.print("[red][!] Invalid choice[/red]")
                continue
            
            if choice == '0':
                console.print("\n[bold green]Exiting Host Sniper... Goodbye![/bold green]")
                return
            
            try:
                if choice == '1':
                    handler.run_port_scan()
                elif choice == '2':
                    handler.run_subdomain_enum()
                elif choice == '3':
                    handler.run_ip_lookup()
                elif choice == '4':
                    handler.run_reverse_ip_lookup()
                elif choice == '5':
                    handler.run_whois_lookup()
                elif choice == '6':
                    handler.run_ssl_analysis()
                elif choice == '7':
                    handler.run_host_scan()
                elif choice == '8':
                    handler.run_dns_records()
                elif choice == '9':
                    handler.run_host_info()
                elif choice == '10':
                    handler.run_help()
                
                console.print("\n[yellow][*] Press Enter to continue...[/yellow]", end="")
                input()
                
            except KeyboardInterrupt:
                console.print("\n[yellow][!] Operation cancelled[/yellow]")
                continue
    
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold green]Exiting Host Sniper... Goodbye![/bold green]")
        sys.exit(0)


if __name__ == "__main__":
    main()
