"""
HTTP Header Analyzer - Detailed HTTP header analysis
"""
import requests
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def analyze_http_headers(domain):
    """
    Perform detailed HTTP header analysis
    """
    result = {
        'domain': domain,
        'headers': {},
        'security_score': 0,
        'recommendations': [],
        'vulnerabilities': []
    }
    
    try:
        url = f'https://{domain}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        result['status_code'] = response.status_code
        result['headers'] = dict(response.headers)
        
        # Analyze security headers
        security_headers = {
            'Strict-Transport-Security': {
                'weight': 15,
                'description': 'HSTS - Forces HTTPS connections'
            },
            'Content-Security-Policy': {
                'weight': 20,
                'description': 'CSP - Prevents XSS and injection attacks'
            },
            'X-Frame-Options': {
                'weight': 15,
                'description': 'Prevents clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'weight': 10,
                'description': 'Prevents MIME-type sniffing'
            },
            'X-XSS-Protection': {
                'weight': 10,
                'description': 'XSS filter protection'
            },
            'Referrer-Policy': {
                'weight': 10,
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'weight': 10,
                'description': 'Controls browser features'
            },
            'Cross-Origin-Embedder-Policy': {
                'weight': 5,
                'description': 'Controls cross-origin embedding'
            },
            'Cross-Origin-Opener-Policy': {
                'weight': 5,
                'description': 'Controls cross-origin window access'
            }
        }
        
        score = 0
        for header, info in security_headers.items():
            if header in response.headers:
                score += info['weight']
            else:
                result['recommendations'].append(
                    f"Add {header}: {info['description']}"
                )
        
        result['security_score'] = score
        result['max_score'] = sum(h['weight'] for h in security_headers.values())
        result['security_percentage'] = round((score / result['max_score']) * 100, 1)
        
        # Check for information disclosure
        server = response.headers.get('Server', '')
        if server:
            result['server_disclosed'] = True
            result['vulnerabilities'].append(
                f"Server version disclosed: {server}"
            )
        
        x_powered_by = response.headers.get('X-Powered-By', '')
        if x_powered_by:
            result['technology_disclosed'] = True
            result['vulnerabilities'].append(
                f"Technology disclosed: {x_powered_by}"
            )
        
        # Check for insecure cookies
        set_cookie = response.headers.get('Set-Cookie', '')
        if set_cookie:
            if 'secure' not in set_cookie.lower():
                result['vulnerabilities'].append(
                    "Cookies without Secure flag detected"
                )
            if 'httponly' not in set_cookie.lower():
                result['vulnerabilities'].append(
                    "Cookies without HttpOnly flag detected"
                )
            if 'samesite' not in set_cookie.lower():
                result['vulnerabilities'].append(
                    "Cookies without SameSite attribute detected"
                )
        
        # Check HTTP methods
        try:
            options_response = requests.options(url, timeout=3, verify=False)
            allowed_methods = options_response.headers.get('Allow', '')
            if allowed_methods:
                result['allowed_methods'] = allowed_methods.split(', ')
                
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in allowed_methods]
                if found_dangerous:
                    result['vulnerabilities'].append(
                        f"Dangerous HTTP methods enabled: {', '.join(found_dangerous)}"
                    )
        except:
            pass
        
        # Check response time
        result['response_time_ms'] = round(response.elapsed.total_seconds() * 1000, 2)
        
        # Check compression
        content_encoding = response.headers.get('Content-Encoding', '')
        if content_encoding:
            result['compression'] = content_encoding
        else:
            result['recommendations'].append("Enable compression (gzip/brotli)")
        
        # Check caching
        cache_control = response.headers.get('Cache-Control', '')
        if cache_control:
            result['caching_enabled'] = True
        else:
            result['recommendations'].append("Configure cache headers")
        
        # Overall security rating
        if result['security_percentage'] >= 80:
            result['security_rating'] = 'Excellent'
        elif result['security_percentage'] >= 60:
            result['security_rating'] = 'Good'
        elif result['security_percentage'] >= 40:
            result['security_rating'] = 'Fair'
        else:
            result['security_rating'] = 'Poor'
        
    except requests.Timeout:
        result['error'] = 'Request timeout'
    except requests.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = f'Analysis error: {str(e)}'
    
    return result
