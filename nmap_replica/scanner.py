import asyncio
import time
import json
from typing import List, Dict
from datetime import datetime
from rich.progress import Progress

from .analyzer import BannerAnalyzer
from .ui import ScannerUI

class PortScanner:
    def __init__(self, target_ip: str, ports: List[int], timeout: float = 1.5, concurrency: int = 100):
        self.target_ip = target_ip
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.results: List[Dict] = []
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.filtered_ports_count = 0
        self.ui = ScannerUI()

    async def scan_port(self, port: int, progress_task_id, progress_instance: Progress) -> None:
        """
        Scans a single port asynchronously with refined FTP reliability logic.
        """
        # CRITICAL SAFEGUARD: Never scan outside 1-65535
        if not (1 <= port <= 65535):
            return

        res = {"port": port, "status": "closed", "service": None, "banner": None, "os_guess": None}
        
        try:
            # Check if port needs SSL
            use_ssl = port in [443, 465, 993, 995, 8443]
            
            conn = asyncio.open_connection(self.target_ip, port, ssl=use_ssl if use_ssl else None)
            
            # 3-Way Handshake
            try:
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            except asyncio.TimeoutError:
                # Timeout = Packet dropped = FILTERED
                self.filtered_ports_count += 1
                progress_instance.advance(progress_task_id)
                return
            except ConnectionRefusedError:
                # RST received = Port alive but invalid = CLOSED
                self.closed_ports_count += 1
                progress_instance.advance(progress_task_id)
                return
            except OSError:
                # Other network reachability errors usually mean FILTERED
                self.filtered_ports_count += 1
                progress_instance.advance(progress_task_id)
                return
            except Exception:
                # Catch-all for other async/ssl weirdness
                self.closed_ports_count += 1
                progress_instance.advance(progress_task_id)
                return

            # If we are here, handshake completed = OPEN
            res["status"] = "open"
            self.open_ports_count += 1
            
            try:
                # 1. Passive Read
                # FTP Fix: Port 21 needs more time for the 220 Greeting.
                # If we read too fast, we get empty data.
                initial_read_timeout = 2.0 if port == 21 else 0.5
                
                initial_data = b""
                try:
                    initial_data = await asyncio.wait_for(reader.read(2048), timeout=initial_read_timeout)
                except asyncio.TimeoutError:
                    pass
                
                # FTP Retry: If port 21 and still empty, try one more time
                if port == 21 and not initial_data:
                    try:
                        # Small wait to see if laggy server sends greeting
                        await asyncio.sleep(0.5)
                        initial_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                    except asyncio.TimeoutError:
                        pass

                # 2. Active Probing (If no data or generic data)
                probe, is_binary_probe = BannerAnalyzer.get_probe(port, self.target_ip)
                
                # If we have no data, OR if it's HTTP (where we want to probe regardless of initial connection)
                if probe and (not initial_data or port in [80, 443, 8080]):
                     writer.write(probe)
                     await writer.drain()
                     
                     try:
                        probe_data = await asyncio.wait_for(reader.read(4096), timeout=1.5)
                        initial_data += probe_data
                     except asyncio.TimeoutError:
                        pass
                
                if initial_data:
                    # Specialized parser for HTTP
                    if port in [80, 443, 8080, 8000, 8443]:
                        banner_text, service_hint = BannerAnalyzer.parse_http_response(initial_data)
                        res["banner"] = banner_text
                        if service_hint: res["service"] = service_hint
                    else:
                        try:
                            banner_text = initial_data.decode('utf-8', errors='ignore').strip()
                        except:
                            banner_text = str(initial_data)
                        res["banner"] = banner_text
                    
                    # Heuristic Analysis
                    detected_service, detected_os = BannerAnalyzer.analyze_banner(res["banner"] or "", port)
                    
                    if not res["service"] or res["service"] == "Unknown":
                        res["service"] = detected_service
                    res["os_guess"] = detected_os
                
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                pass 
            except Exception as e:
                 res["error"] = str(e)

            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

        except Exception:
             pass
        
        # Fallback service identification
        if res["status"] == "open" and not res["service"]:
             res["service"] = BannerAnalyzer.get_common_service_name(port)

        if res["status"] == "open":
             self.results.append(res)
        
        progress_instance.advance(progress_task_id)

    async def run(self):
        """
        Orchestrates the asynchronous scan.
        """
        self.ui.display_start(self.target_ip, len(self.ports))
        
        start_time = time.time()
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def sem_scan(port, task_id, progress):
            async with semaphore:
                await self.scan_port(port, task_id, progress)

        with self.ui.create_progress() as progress:
            task_id = progress.add_task(f"[cyan]Scanning {len(self.ports)} ports...", total=len(self.ports))
            tasks = [sem_scan(port, task_id, progress) for port in self.ports]
            await asyncio.gather(*tasks)

        end_time = time.time()
        duration = end_time - start_time
        
        # OS Aggregation
        final_os = self._aggregate_os_detection()
        
        self.ui.display_results(
            self.target_ip, 
            duration, 
            self.results, 
            final_os, 
            self.closed_ports_count, 
            self.filtered_ports_count
        )
        self.save_results(final_os)

    def _aggregate_os_detection(self) -> str:
        """
        Aggregates OS guesses from all ports to find a high-confidence OS.
        """
        final_os = "Unknown"
        # 1. Look for high confidence hints
        for res in self.results:
            os_hint = res.get("os_guess")
            if os_hint and os_hint != "Unknown":
                if "Linux" in os_hint or "Windows" in os_hint or "FreeBSD" in os_hint:
                    final_os = os_hint
                    break 
        
        # 2. Backfill details
        for res in self.results:
            if res["os_guess"] == "Unknown":
                 res["os_guess"] = final_os
        return final_os

    def save_results(self, final_os: str):
        filename = f"scan_results_{self.target_ip.replace('.', '_')}.json"
        data = {
            "target": self.target_ip,
            "timestamp": datetime.now().isoformat(),
            "os_detected": final_os,
            "results": self.results
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        self.ui.show_saved(filename)
