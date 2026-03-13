"""
Reverse IP Lookup - Find other domains on same IP
"""
import socket
import requests
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def reverse_ip_lookup(domain):
    """
    Find other domains hosted on the same IP
    """
    result = {
        'domain': domain,
        'ip': None,
        'domains_on_ip': [],
        'total_domains': 0
    }
    
    try:
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        
        # Try multiple reverse IP lookup services
        domains_found = set()
        
        # Method 1: HackerTarget API (free, no key required)
        try:
            api_url = f'https://api.hackertarget.com/reverseiplookup/?q={ip}'
            response = requests.get(api_url, timeout=5)
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                domains = response.text.strip().split('\n')
                for d in domains:
                    d = d.strip()
                    if d and '.' in d and not d.startswith('error'):
                        domains_found.add(d)
        except:
            pass
        
        # Method 2: ViewDNS.info API (backup)
        try:
            api_url = f'https://viewdns.info/reverseip/?host={ip}&t=1'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(api_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                # Simple parsing - look for domain patterns
                import re
                domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
                found = re.findall(domain_pattern, response.text.lower())
                for d in found:
                    if d != domain and d not in ['viewdns.info', 'google.com']:
                        domains_found.add(d)
        except:
            pass
        
        # Convert to list and sort
        result['domains_on_ip'] = sorted(list(domains_found))[:50]  # Limit to 50
        result['total_domains'] = len(result['domains_on_ip'])
        
        # If no domains found via API, note it
        if result['total_domains'] == 0:
            result['note'] = 'No other domains found or API limit reached'
        
    except socket.gaierror:
        result['error'] = 'Unable to resolve domain'
    except Exception as e:
        result['error'] = f'Lookup error: {str(e)}'
    
    return result
