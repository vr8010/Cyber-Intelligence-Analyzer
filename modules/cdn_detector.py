"""
CDN Detection Module - Detect if domain uses CDN services
"""
import socket
import requests
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

CDN_PROVIDERS = {
    'cloudflare': ['cloudflare'],
    'akamai': ['akamai'],
    'fastly': ['fastly'],
    'cloudfront': ['cloudfront', 'amazonaws'],
    'maxcdn': ['maxcdn'],
    'incapsula': ['incapsula'],
    'sucuri': ['sucuri'],
    'stackpath': ['stackpath'],
    'keycdn': ['keycdn'],
    'azure': ['azureedge'],
    'google': ['googleusercontent', 'gstatic']
}

def detect_cdn(domain):
    """
    Detect CDN provider for a domain
    """
    result = {
        'cdn_detected': False,
        'provider': None,
        'cname': None,
        'headers': {}
    }
    
    try:
        # Check CNAME records
        try:
            cname = socket.getfqdn(domain)
            result['cname'] = cname
            
            # Check CNAME against known CDN providers
            for provider, keywords in CDN_PROVIDERS.items():
                if any(keyword in cname.lower() for keyword in keywords):
                    result['cdn_detected'] = True
                    result['provider'] = provider
                    break
        except:
            pass
        
        # Check HTTP headers
        try:
            response = requests.get(f'https://{domain}', timeout=3, allow_redirects=True, verify=False)
            headers = response.headers
            
            # Store relevant headers
            cdn_headers = ['Server', 'X-CDN', 'X-Cache', 'CF-Ray', 'X-Akamai-Transformed']
            for header in cdn_headers:
                if header in headers:
                    result['headers'][header] = headers[header]
            
            # Check headers for CDN indicators
            if 'cloudflare' in str(headers).lower() or 'CF-Ray' in headers:
                result['cdn_detected'] = True
                result['provider'] = 'cloudflare'
            elif 'akamai' in str(headers).lower():
                result['cdn_detected'] = True
                result['provider'] = 'akamai'
            elif 'x-amz' in str(headers).lower():
                result['cdn_detected'] = True
                result['provider'] = 'cloudfront'
                
        except:
            pass
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
