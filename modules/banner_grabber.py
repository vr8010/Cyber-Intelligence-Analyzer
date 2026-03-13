"""
Server Banner Grabber - Extract server information
"""
import socket
import requests
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def grab_banners(domain):
    """
    Grab server banners and version information
    """
    result = {
        'domain': domain,
        'http_banner': {},
        'service_banners': {},
        'server_info': {}
    }
    
    try:
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        
        # HTTP/HTTPS Banner
        try:
            url = f'https://{domain}'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            
            # Extract interesting headers
            interesting_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version',
                'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache',
                'X-Varnish', 'Via', 'X-Served-By', 'X-Backend-Server'
            ]
            
            for header in interesting_headers:
                if header in response.headers:
                    result['http_banner'][header] = response.headers[header]
            
            # Server info
            if 'Server' in response.headers:
                server = response.headers['Server']
                result['server_info']['name'] = server
                
                # Parse version if available
                if '/' in server:
                    parts = server.split('/')
                    result['server_info']['software'] = parts[0]
                    if len(parts) > 1:
                        result['server_info']['version'] = parts[1].split()[0]
        except:
            pass
        
        # Common service ports banner grabbing
        common_services = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        for port, service_name in common_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                if sock.connect_ex((ip, port)) == 0:
                    # Try to receive banner
                    try:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        
                        if banner:
                            result['service_banners'][f'{service_name} ({port})'] = banner[:200]  # Limit length
                    except:
                        result['service_banners'][f'{service_name} ({port})'] = 'Open (no banner)'
                
                sock.close()
            except:
                pass
        
        # SSH Banner (special handling)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            if sock.connect_ex((ip, 22)) == 0:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    result['service_banners']['SSH (22)'] = banner
            
            sock.close()
        except:
            pass
        
    except socket.gaierror:
        result['error'] = 'Unable to resolve domain'
    except Exception as e:
        result['error'] = f'Banner grabbing error: {str(e)}'
    
    return result
