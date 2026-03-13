import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    'valid': True,
                    'issuer': dict(x[0] for x in cert['issuer'])['organizationName'],
                    'expiry': cert['notAfter'],
                    'subject': dict(x[0] for x in cert['subject'])['commonName'],
                    'version': cert['version']
                }
    except Exception as e:
        return {'valid': False, 'error': str(e)}
