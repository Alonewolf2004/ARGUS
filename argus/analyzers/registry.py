from typing import Tuple, List
from .base import ServiceAnalyzer
from .http import HTTPAnalyzer
from .ssh import SSHAnalyzer
from .database import DatabaseAnalyzer

class AnalyzerRegistry:
    def __init__(self):
        self.analyzers: List[ServiceAnalyzer] = [
            HTTPAnalyzer(),
            SSHAnalyzer(),
            DatabaseAnalyzer()
        ]
    
    def analyze(self, port: int, banner: str, trie_tag: str = None) -> Tuple[str, str]:
        """
        Dispatches to the correct analyzer using Strategy Pattern.
        """
        for analyzer in self.analyzers:
            if analyzer.can_analyze(port, banner, trie_tag):
                return analyzer.analyze(banner)
        
        # Fallback
        clean_banner = banner.split('|')[0].strip()[:40]
        return f"[Unknown] {clean_banner}", "Unknown"
