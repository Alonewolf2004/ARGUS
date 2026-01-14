from typing import List

def parse_ports(port_input: str) -> List[int]:
    """
    Parses a string of ports (spaces, commas, ranges) into a list of integers.
    Example: "80 443 1000-1005" -> [80, 443, 1000, 1001, 1002, 1003, 1004, 1005]
    """
    ports = set()
    # Replace commas with spaces to handle both formats
    port_input = port_input.replace(',', ' ')
    tokens = port_input.split()
    
    for token in tokens:
        if '-' in token:
            try:
                start, end = map(int, token.split('-'))
                if start <= end:
                     # Clamp to valid range 1-65535
                    start = max(1, start)
                    end = min(65535, end)
                    if start <= end:
                        ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(list(ports))
