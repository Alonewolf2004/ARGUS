import asyncio
import socket
import sys

from .ui import ScannerUI
from .scanner import PortScanner
from .utils import parse_ports
from .config import ScanConfig

def main():
    ui = ScannerUI()
    ui.display_welcome()
    
    try:
        # 1. Get Inputs
        target = ui.get_target()
        
        # Resolve hostname first (Validation requires valid IP/Host)
        try:
           target_ip = socket.gethostbyname(target)
        except socket.gaierror:
           ui.console.print(f"[bold red]Error:[/bold red] Could not resolve hostname {target}")
           return

        ports_str = ui.get_ports()
        raw_ports = parse_ports(ports_str)
        
        concurrency = ui.get_speed()
        
        # 2. Validate with Pydantic
        # This will raise ValidationError if constraints fail
        config = ScanConfig(
            target_ip=target_ip,
            ports=raw_ports,
            concurrency=concurrency
        )
        
        # 3. Initialize Scanner with Validated Config
        # **config.dict() unpacks keys: target_ip, ports, concurrency, timeout
        scanner = PortScanner(**config.dict())
        
        # 4. Run Async Loop
        asyncio.run(scanner.run())
        
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        ui.console.print(f"\n[bold red]Fatal Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
