import re
from typing import Tuple
from .base import ServiceAnalyzer

class DatabaseAnalyzer(ServiceAnalyzer):
    RE_MYSQL_VER = re.compile(r'((?:5|8|10)\.\d+\.\d+[\w\-]*)')

    def can_analyze(self, port: int, banner: str, trie_tag: str = None) -> bool:
        return trie_tag in ["MySQL", "Redis"] or "mysql" in banner.lower() or "PONG" in banner

    def analyze(self, banner: str) -> Tuple[str, str]:
        # Redis
        if "PONG" in banner or "redis" in banner:
            return "[Redis] Key-Value Store", "Unknown"
            
        # MySQL
        m = self.RE_MYSQL_VER.search(banner)
        if m:
            ver = m.group(1)
            db_type = "MariaDB" if "MariaDB" in banner else "MySQL"
            return f"[DB] {db_type} {ver}", "Unknown"
            
        return "[DB] Database Server", "Unknown"
