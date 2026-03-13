import requests

def check_headers(domain):
    headers_to_check = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'X-Content-Type-Options'
    ]
    
    try:
        response = requests.get(f'https://{domain}', timeout=5, allow_redirects=True)
        result = {}
        
        for header in headers_to_check:
            result[header] = response.headers.get(header, 'Missing')
        
        result['server'] = response.headers.get('Server', 'Hidden')
        result['status_code'] = response.status_code
        
        return result
    except Exception as e:
        return {'error': str(e)}
