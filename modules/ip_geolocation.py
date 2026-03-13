"""
IP Geolocation Module - Get geographical information about IP/domain
"""
import socket
import requests

def get_ip_info(domain):
    """
    Get IP geolocation and network information
    """
    try:
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        
        # Use ip-api.com for geolocation (free, no key required)
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'zip': data.get('zip', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A'),
                        'asn': data.get('as', 'N/A').split()[0] if data.get('as') else 'N/A'
                    }
                else:
                    return {
                        'ip': ip,
                        'error': 'Geolocation data not available for this IP'
                    }
        except requests.Timeout:
            return {
                'ip': ip,
                'error': 'Geolocation service timeout'
            }
        except requests.RequestException:
            return {
                'ip': ip,
                'error': 'Unable to connect to geolocation service'
            }
        
        return {
            'ip': ip,
            'error': 'Unable to fetch geolocation data'
        }
        
    except socket.gaierror:
        return {'error': 'Unable to resolve domain'}
    except Exception as e:
        return {'error': f'Geolocation error: {str(e)}'}
