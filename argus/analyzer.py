import re
from typing import Tuple, Optional
from .analyzers.registry import AnalyzerRegistry

class BannerAnalyzer:
    """
    Encapsulates logic for Protocol Probes, HTTP Parsing, and Banner Analysis.
    Delegates analysis to the Plugin Registry (Strategy Pattern).
    """
    
    # Trie Root for Protocol Prefixes (Optimization: O(k) lookup)
    _TRIE_ROOT = {}
    _REGISTRY = AnalyzerRegistry()

    @classmethod
    def _build_trie(cls):
        """
        Builds the prefix trie for fast O(k) protocol identification.
        """
        signatures = [
            ("SSH-", "SSH"),
            ("HTTP", "HTTP"),
            ("220 ", "FTP"),
            ("mysql", "MySQL"),
            ("MariaDB", "MySQL"),
            ("5.", "MySQL"), 
            ("+OK", "POP3"),
            ("RTSP", "RTSP"),
            ("PONG", "Redis"),
            ("RFB", "VNC")
        ]
        
        for pattern, tag in signatures:
            node = cls._TRIE_ROOT
            for char in pattern:
                node = node.setdefault(char, {})
            node['_tag'] = tag

    @classmethod
    def _trie_lookup(cls, text: str) -> Optional[str]:
        """
        Walks the Trie to find a matching protocol signature.
        """
        if not cls._TRIE_ROOT:
            cls._build_trie()
            
        node = cls._TRIE_ROOT
        for char in text[:20]:
            if char not in node:
                return None
            node = node[char]
            if '_tag' in node:
                return node['_tag']
        return None

    @staticmethod
    def get_probe(port: int, target_ip: str) -> Tuple[Optional[bytes], bool]:
        """
        Returns (Probe Data, IsBinary) based on port.
        """
        # HTTP Probes
        if port in [80, 8080, 8000, 443, 8443]:
            return f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Argus/1.0\r\n\r\n".encode(), False
        
        # RTSP
        if port == 554:
            return b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", False
            
        # PPTP
        if port == 1723:
            return (b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + b"\x00" * 148), True

        # FTP
        if port == 21: return b"HELP\r\n", False
        
        # SMTP
        if port in [25, 587]: return b"EHLO scan\r\n", False
        
        # Redis
        if port == 6379: return b"PING\r\n", False
        
        # Generic
        return b"\r\n\r\n", False

    @staticmethod
    def parse_http_response(data: bytes) -> Tuple[str, Optional[str]]:
        """
        Legacy helper kept for backward compatibility if needed, 
        but logic is now primarily in HTTPAnalyzer.
        """
        # Logic moved to analyzers/http.py
        pass

    @classmethod
    def analyze_banner(cls, banner: str, port: int) -> Tuple[str, str]:
        """
        Refactored: Uses Trie for Tagging -> Delegates to Registry Strategies.
        """
        # 1. Fast Path: Trie Lookup (Optimization)
        trie_tag = cls._trie_lookup(banner)
        
        # 2. Strategy Analysis (Architecture)
        return cls._REGISTRY.analyze(port, banner, trie_tag)

    # Trie Root for Protocol Prefixes
    _TRIE_ROOT = {}

    @classmethod
    def _build_trie(cls):
        """
        Builds the prefix trie for fast O(k) protocol identification.
        """
        signatures = [
            ("SSH-", "SSH"),
            ("HTTP", "HTTP"),
            ("220 ", "FTP"),
            ("mysql", "MySQL"),
            ("MariaDB", "MySQL"),
            ("5.", "MySQL"), # MySQL binary stats often start with version
            ("+OK", "POP3"),
            ("RTSP", "RTSP"),
            ("PONG", "Redis"),
            ("RFB", "VNC")
        ]
        
        for pattern, tag in signatures:
            node = cls._TRIE_ROOT
            for char in pattern:
                node = node.setdefault(char, {})
            node['_tag'] = tag

    @classmethod
    def _trie_lookup(cls, text: str) -> Optional[str]:
        """
        Walks the Trie to find a matching protocol signature.
        O(k) where k is the length of the signature.
        """
        if not cls._TRIE_ROOT:
            cls._build_trie()
            
        node = cls._TRIE_ROOT
        # Inspect first 20 chars max
        for char in text[:20]:
            if char not in node:
                return None
            node = node[char]
            if '_tag' in node:
                return node['_tag']
        return None

    @staticmethod
    def get_probe(port: int, target_ip: str) -> Tuple[Optional[bytes], bool]:
        """
        Returns (Probe Data, IsBinary) based on port.
        """
        # HTTP Probes
        if port in [80, 8080, 8000, 443, 8443]:
            # Simple GET usually works best
            return f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Argus/1.0\r\n\r\n".encode(), False
        
        # RTSP
        if port == 554:
            return b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", False
            
        # PPTP
        if port == 1723:
            return (b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + b"\x00" * 148), True

        # FTP: Usually speaks first, but if silent, HELP is safe.
        if port == 21: return b"HELP\r\n", False
        
        # SMTP
        if port in [25, 587]: return b"EHLO scan\r\n", False
        
        # Redis
        if port == 6379: return b"PING\r\n", False
        
        # Generic
        return b"\r\n\r\n", False

    @classmethod
    def parse_http_response(cls, data: bytes) -> Tuple[str, Optional[str]]:
        """
        Parses raw HTTP response to capture Title, Server, and Key Headers.
        Returns: (Formatted Banner String, potential_service_name)
        """
        try:
            text = data.decode('utf-8', errors='ignore')
            headers, _, body = text.partition('\r\n\r\n')
            
            info_lines = []
            service_hint = "HTTP"
            
            # Extract Server Header
            server_match = cls.RE_SERVER.search(headers)
            if server_match:
                server = server_match.group(1).strip()
                info_lines.append(f"Server: {server}")
                service_hint = f"HTTP ({server})"
                
            # Extract X-Powered-By
            x_powered = cls.RE_POWERED_BY.search(headers)
            if x_powered:
                info_lines.append(f"Powered-By: {x_powered.group(1).strip()}")

            # Extract Title
            title_match = cls.RE_TITLE.search(body)
            if title_match:
                title = title_match.group(1).strip()[:60] # Truncate title
                info_lines.append(f"Title: {title}")
            
            if not info_lines:
                # Fallback to first line of status if nothing else
                first_line = headers.splitlines()[0] if headers else ""
                if first_line: info_lines.append(first_line)

            return " | ".join(info_lines), service_hint
            
        except Exception:
            return "HTTP Response (Parse Error)", "HTTP"

    @classmethod
    def analyze_banner(cls, banner: str, port: int) -> Tuple[str, str]:
        """
        Sophisticated regex analysis of banner text with Protocol Tagging.
        Uses Trie for fast path detection + Regex for detailed versioning.
        """
        service = "Unknown"
        os_info = "Unknown"
        is_unknown = True
        
        def set_service(tag, name):
            nonlocal service, is_unknown
            service = f"[{tag}] {name}"
            is_unknown = False

        # --- Fast Path: Trie Lookup ---
        detected_tag = cls._trie_lookup(banner)
        
        # --- Detailed Analysis ---
        
        # HTTP
        if detected_tag == "HTTP" or "HTTP" in banner or "html" in banner or "Server:" in banner:
            tag = "HTTP"
            if "Apache" in banner:
                m = cls.RE_APACHE.search(banner)
                set_service(tag, f"Apache {m.group(1)}" if m else "Apache httpd")
                if "Ubuntu" in banner: os_info = "Ubuntu Linux"
                elif "CentOS" in banner: os_info = "CentOS Linux"
                elif "Windows" in banner or "Win32" in banner: os_info = "Windows"
            elif "nginx" in banner:
                m = cls.RE_NGINX.search(banner)
                set_service(tag, f"Nginx {m.group(1)}" if m else "Nginx")
            elif "Microsoft-IIS" in banner:
                m = cls.RE_IIS.search(banner)
                set_service(tag, f"Microsoft-IIS {m.group(1)}" if m else "Microsoft-IIS")
                os_info = "Windows Server"
            elif "LiteSpeed" in banner:
                set_service(tag, "LiteSpeed")
            elif "Jetty" in banner:
                 set_service(tag, "Jetty")
            elif "Node.js" in banner:
                set_service(tag, "Node.js")
            else:
                m = cls.RE_GENERIC_SERVER.search(banner)
                if m: set_service(tag, m.group(1).strip())
                else: set_service(tag, "Web Server")

        # SSH
        elif detected_tag == "SSH" or "SSH" in banner:
            tag = "SSH"
            if "OpenSSH" in banner:
                m = cls.RE_OPENSSH.search(banner)
                set_service(tag, f"OpenSSH {m.group(1)}" if m else "OpenSSH")
                if "Ubuntu" in banner: os_info = "Ubuntu Linux"
                elif "Debian" in banner: os_info = "Debian Linux"
                elif "FreeBSD" in banner: os_info = "FreeBSD"
            else:
                 set_service(tag, banner.split()[0].strip())

        # SMTP / POP3 / IMAP
        elif any(k in banner for k in ["SMTP", "ESMTP", "Postfix", "Exim", "OK", "+OK"]):
             tls_flag = " [STARTTLS]" if "STARTTLS" in banner else ""
             
             if port in [25, 587, 465]:
                 tag = "SMTP"
                 if "Postfix" in banner: set_service(tag, "Postfix" + tls_flag)
                 elif "Exim" in banner: set_service(tag, "Exim" + tls_flag)
                 elif "Microsoft ESMTP" in banner: 
                    set_service(tag, "Exchange/IIS" + tls_flag)
                    os_info = "Windows"
                 else: set_service(tag, "Mail Server" + tls_flag)
             elif port == 110 or detected_tag == "POP3":
                 set_service("POP3", "POP3 Server" + tls_flag)
             elif port == 143:
                 set_service("IMAP", "IMAP Server" + tls_flag)

        # FTP
        elif detected_tag == "FTP" or "FTP" in banner or "220" in banner:
            tag = "FTP"
            if "vsFTPd" in banner: set_service(tag, "vsFTPd")
            elif "FileZilla" in banner:
                set_service(tag, "FileZilla")
                os_info = "Windows"
            elif "Pure-FTPd" in banner: set_service(tag, "Pure-FTPd")
            else: set_service(tag, "Generic FTP")
            
        # RTSP
        elif detected_tag == "RTSP" or "RTSP" in banner:
            set_service("RTSP", "Media Server")
            
        # Redis
        elif detected_tag == "Redis" or "PONG" in banner or "redis" in banner:
             set_service("Redis", "Key-Value Store")
             
        # MySQL
        elif detected_tag == "MySQL" or "mysql" in banner.lower() or "mariadb" in banner.lower():
            m = cls.RE_MYSQL_VER.search(banner)
            if m:
                ver = m.group(1)
                db_type = "MariaDB" if "MariaDB" in banner else "MySQL"
                set_service("DB", f"{db_type} {ver}")
            elif "mysql" in banner.lower():
                set_service("DB", "MySQL")
                
        # VNC
        elif detected_tag == "VNC":
            set_service("VNC", "VNC Server")

        # Universal Fallback
        if is_unknown and len(banner) > 3:
            hint = banner.split('|')[0].strip()
            if len(hint) > 40: hint = hint[:37] + "..."
            service = f"[Unknown] {hint}"

        # OS Heuristics
        if os_info == "Unknown":
            if "Ubuntu" in banner: os_info = "Ubuntu Linux"
            elif "Debian" in banner: os_info = "Debian Linux"
            elif "Kali" in banner: os_info = "Kali Linux"
            elif "Alpine" in banner: os_info = "Alpine Linux"
            elif "Windows" in banner: os_info = "Windows"
            elif "FreeBSD" in banner: os_info = "FreeBSD"
            
        return service, os_info

    @staticmethod
    def get_common_service_name(port: int) -> str:
        common_ports = {
            21: "[FTP]", 22: "[SSH]", 23: "[Telnet]", 25: "[SMTP]", 
            53: "[DNS]", 80: "[HTTP]", 443: "[HTTPS]", 445: "[SMB]", 
            587: "[SMTP] Submission", 3306: "[DB] MySQL", 3389: "[RDP]", 
            5432: "[DB] PostgreSQL", 6379: "[Redis]", 8080: "[HTTP-Proxy]"
        }
        return common_ports.get(port, "Unknown")
