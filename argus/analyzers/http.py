import re
from typing import Tuple
from .base import ServiceAnalyzer

class HTTPAnalyzer(ServiceAnalyzer):
    # Pre-compiled Regex
    RE_SERVER = re.compile(r'^Server: (.+)$', re.MULTILINE | re.IGNORECASE)
    RE_POWERED_BY = re.compile(r'^X-Powered-By: (.+)$', re.MULTILINE | re.IGNORECASE)
    RE_TITLE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
    
    # CMS/Server Regex
    RE_APACHE = re.compile(r'Apache/([\d\.]+)')
    RE_NGINX = re.compile(r'nginx/([\d\.]+)')
    RE_IIS = re.compile(r'Microsoft-IIS/([\d\.]+)')

    def can_analyze(self, port: int, banner: str, trie_tag: str = None) -> bool:
        return trie_tag == "HTTP" or "HTTP" in banner or "html" in banner

    def analyze(self, banner: str) -> Tuple[str, str]:
        service_name = "[HTTP] Web Server"
        os_info = "Unknown"
        
        # 1. Parse Info
        info_lines = []
        
        server_match = self.RE_SERVER.search(banner)
        if server_match:
            server = server_match.group(1).strip()
            info_lines.append(f"Server: {server}")
            
            # Detailed Tagging
            if "Apache" in server:
                 m = self.RE_APACHE.search(server)
                 service_name = f"[HTTP] Apache {m.group(1)}" if m else "[HTTP] Apache"
                 if "Ubuntu" in server: os_info = "Ubuntu Linux"
                 elif "CentOS" in server: os_info = "CentOS Linux"
                 elif "Win32" in server: os_info = "Windows"
            elif "nginx" in server:
                 m = self.RE_NGINX.search(server)
                 service_name = f"[HTTP] Nginx {m.group(1)}" if m else "[HTTP] Nginx"
            elif "Microsoft-IIS" in server:
                 m = self.RE_IIS.search(server)
                 service_name = f"[HTTP] IIS {m.group(1)}" if m else "[HTTP] IIS"
                 os_info = "Windows Server"
        
        x_powered = self.RE_POWERED_BY.search(banner)
        if x_powered:
             info_lines.append(f"Powered-By: {x_powered.group(1).strip()}")

        title_match = self.RE_TITLE.search(banner)
        if title_match:
             title = title_match.group(1).strip()[:60]
             info_lines.append(f"Title: {title}")
             
        if not info_lines:
             return service_name, os_info
             
        return f"{service_name} | " + " | ".join(info_lines), os_info
