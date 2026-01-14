from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any

class ServiceAnalyzer(ABC):
    """
    Abstract Base Class for Protocol Analyzers (Strategy Pattern).
    """
    @abstractmethod
    def can_analyze(self, port: int, banner: str, trie_tag: str = None) -> bool:
        """
        Determines if this analyzer can handle the given banner/port.
        """
        pass
    
    @abstractmethod
    def analyze(self, banner: str) -> Tuple[str, str]:
        """
        Parses banner. Returns (Service Name, OS Info).
        """
        pass
