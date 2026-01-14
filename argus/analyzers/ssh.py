import re
from typing import Tuple
from .base import ServiceAnalyzer

class SSHAnalyzer(ServiceAnalyzer):
    RE_OPENSSH = re.compile(r'OpenSSH[_-]?([\d\.]+)')

    def can_analyze(self, port: int, banner: str, trie_tag: str = None) -> bool:
        return trie_tag == "SSH" or "SSH-" in banner

    def analyze(self, banner: str) -> Tuple[str, str]:
        service = "[SSH] SSH Server"
        os_info = "Unknown"
        
        if "OpenSSH" in banner:
            m = self.RE_OPENSSH.search(banner)
            service = f"[SSH] OpenSSH {m.group(1)}" if m else "[SSH] OpenSSH"
            if "Ubuntu" in banner: os_info = "Ubuntu Linux"
            elif "Debian" in banner: os_info = "Debian Linux"
            elif "FreeBSD" in banner: os_info = "FreeBSD"
        else:
            # Fallback for weird banners like "SSH-2.0-Dropbear"
            parts = banner.split('-')
            if len(parts) > 2:
                service = f"[SSH] {parts[2].strip()}"
                
        return service, os_info
