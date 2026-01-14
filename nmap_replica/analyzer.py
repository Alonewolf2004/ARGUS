import re
from typing import Tuple, Optional

class BannerAnalyzer:
    """
    Encapsulates logic for Protocol Probes, HTTP Parsing, and Banner Analysis.
    """

    @staticmethod
    def get_probe(port: int, target_ip: str) -> Tuple[Optional[bytes], bool]:
        """
        Returns (Probe Data, IsBinary) based on port.
        """
        # HTTP Probes
        if port in [80, 8080, 8000, 443, 8443]:
            # Simple GET usually works best
            return f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Nmap-Replica/1.0\r\n\r\n".encode(), False
        
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

    @staticmethod
    def parse_http_response(data: bytes) -> Tuple[str, Optional[str]]:
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
            server_match = re.search(r'^Server: (.+)$', headers, re.MULTILINE | re.IGNORECASE)
            if server_match:
                server = server_match.group(1).strip()
                info_lines.append(f"Server: {server}")
                service_hint = f"HTTP ({server})"
                
            # Extract X-Powered-By
            x_powered = re.search(r'^X-Powered-By: (.+)$', headers, re.MULTILINE | re.IGNORECASE)
            if x_powered:
                info_lines.append(f"Powered-By: {x_powered.group(1).strip()}")

            # Extract Title
            title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
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

    @staticmethod
    def analyze_banner(banner: str, port: int) -> Tuple[str, str]:
        """
        Sophisticated regex analysis of banner text with Protocol Tagging.
        """
        service = "Unknown"
        os_info = "Unknown"
        is_unknown = True
        
        def set_service(tag, name):
            nonlocal service, is_unknown
            service = f"[{tag}] {name}"
            is_unknown = False

        # --- Protocol Specific Detection ---
        
        # HTTP
        if "HTTP" in banner or "html" in banner or "Server:" in banner:
            tag = "HTTP"
            if "Apache" in banner:
                m = re.search(r'Apache/([\d\.]+)', banner)
                set_service(tag, f"Apache {m.group(1)}" if m else "Apache httpd")
                if "Ubuntu" in banner: os_info = "Ubuntu Linux"
                elif "CentOS" in banner: os_info = "CentOS Linux"
                elif "Win32" in banner or "Windows" in banner: os_info = "Windows"
            elif "nginx" in banner:
                m = re.search(r'nginx/([\d\.]+)', banner)
                set_service(tag, f"Nginx {m.group(1)}" if m else "Nginx")
            elif "Microsoft-IIS" in banner:
                m = re.search(r'Microsoft-IIS/([\d\.]+)', banner)
                set_service(tag, f"Microsoft-IIS {m.group(1)}" if m else "Microsoft-IIS")
                os_info = "Windows Server"
            elif "LiteSpeed" in banner:
                set_service(tag, "LiteSpeed")
            elif "Jetty" in banner:
                 set_service(tag, "Jetty")
            elif "Node.js" in banner:
                set_service(tag, "Node.js")
            else:
                m = re.search(r'Server: (.*?)(?:\||$)', banner)
                if m: set_service(tag, m.group(1).strip())
                else: set_service(tag, "Web Server")

        # SSH
        elif "SSH" in banner:
            tag = "SSH"
            if "OpenSSH" in banner:
                m = re.search(r'OpenSSH[_-]?([\d\.]+)', banner)
                set_service(tag, f"OpenSSH {m.group(1)}" if m else "OpenSSH")
                if "Ubuntu" in banner: os_info = "Ubuntu Linux"
                elif "Debian" in banner: os_info = "Debian Linux"
                elif "FreeBSD" in banner: os_info = "FreeBSD"
            else:
                 set_service(tag, banner.split()[0])

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
             elif port == 110:
                 set_service("POP3", "POP3 Server" + tls_flag)
             elif port == 143:
                 set_service("IMAP", "IMAP Server" + tls_flag)

        # FTP
        elif "FTP" in banner or "220" in banner:
            tag = "FTP"
            if "vsFTPd" in banner: set_service(tag, "vsFTPd")
            elif "FileZilla" in banner:
                set_service(tag, "FileZilla")
                os_info = "Windows"
            elif "Pure-FTPd" in banner: set_service(tag, "Pure-FTPd")
            else: set_service(tag, "Generic FTP")
            
        # RTSP
        elif "RTSP" in banner:
            set_service("RTSP", "Media Server")
            
        # Redis
        elif "PONG" in banner or "redis" in banner:
             set_service("Redis", "Key-Value Store")
             
        # MySQL
        elif "mysql" in banner.lower() or "mariadb" in banner.lower() or (len(banner) > 5 and banner[0:1] not in ["H", "S", "2", "+"]):
            m = re.search(r'((?:5|8|10)\.\d+\.\d+[\w\-]*)', banner)
            if m:
                ver = m.group(1)
                db_type = "MariaDB" if "MariaDB" in banner else "MySQL"
                set_service("DB", f"{db_type} {ver}")
            elif "mysql" in banner.lower():
                set_service("DB", "MySQL")

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
