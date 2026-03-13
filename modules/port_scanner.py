"""
Port Scanner Module - Scans common ports on target domain
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

def scan_port(host, port, timeout=0.5):
    """Scan a single port with shorter timeout"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(domain, ports=None, max_workers=50):
    """
    Scan multiple ports on a domain
    Returns dict with open ports and their services
    """
    if ports is None:
        ports = COMMON_PORTS.keys()
    
    try:
        host = socket.gethostbyname(domain)
    except socket.gaierror:
        return {'error': 'Unable to resolve domain', 'open_ports': [], 'total_open': 0}
    
    open_ports = []
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_port, host, port): port for port in ports}
            
            for future in as_completed(futures):
                try:
                    port, is_open = future.result()
                    if is_open:
                        service = COMMON_PORTS.get(port, 'Unknown')
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                except:
                    pass  # Skip failed ports
    except Exception as e:
        return {
            'error': f'Port scan error: {str(e)}',
            'open_ports': [],
            'total_open': 0
        }
    
    return {
        'host': host,
        'domain': domain,
        'open_ports': sorted(open_ports, key=lambda x: x['port']),
        'total_open': len(open_ports)
    }
