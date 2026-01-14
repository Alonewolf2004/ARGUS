import asyncio
import socket
import sys

from .ui import ScannerUI
from .utils import parse_ports
from .scanner import PortScanner

def main():
    ui = ScannerUI()
    ui.display_welcome()
    
    # Get interactive input
    target = ui.get_target()
    try:
        target_ip = socket.gethostbyname(target)
        ui.console.print(f"[green]Resolved to {target_ip}[/green]")
    except socket.gaierror:
        ui.console.print("[bold red]Could not resolve hostname.[/bold red]")
        return

    port_input = ui.get_ports()
    ports = parse_ports(port_input)
    
    if not ports:
        ui.console.print("[bold red]No valid ports selected.[/bold red]")
        return
        
    concurrency = ui.get_speed()

    # Run Scanner
    scanner = PortScanner(target_ip, ports, concurrency=concurrency)
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        ui.console.print("\n[bold red]Scan interrupted by user.[/bold red]")

if __name__ == "__main__":
    main()
