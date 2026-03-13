"""
Website Fingerprinting - Advanced website identification
"""
import requests
import hashlib
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def fingerprint_website(domain):
    """
    Advanced website fingerprinting
    """
    result = {
        'domain': domain,
        'fingerprints': {},
        'characteristics': {},
        'signatures': []
    }
    
    try:
        url = f'https://{domain}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Favicon Hash (Shodan-style)
        try:
            favicon_url = f'{url}/favicon.ico'
            fav_response = requests.get(favicon_url, timeout=3, verify=False)
            if fav_response.status_code == 200:
                favicon_hash = hashlib.md5(fav_response.content).hexdigest()
                result['fingerprints']['favicon_md5'] = favicon_hash
        except:
            pass
        
        # 2. HTML Structure Hash
        html_hash = hashlib.md5(html_content.encode()).hexdigest()
        result['fingerprints']['html_md5'] = html_hash
        
        # 3. Title and Meta Tags
        title = soup.find('title')
        if title:
            result['characteristics']['title'] = title.get_text().strip()
        
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name', meta.get('property', ''))
            content = meta.get('content', '')
            if name and content:
                meta_tags[name] = content
        
        if meta_tags:
            result['characteristics']['meta_tags'] = meta_tags
        
        # 4. JavaScript Libraries
        scripts = soup.find_all('script', src=True)
        js_libraries = []
        
        for script in scripts:
            src = script.get('src', '')
            if 'jquery' in src.lower():
                js_libraries.append('jQuery')
            elif 'react' in src.lower():
                js_libraries.append('React')
            elif 'angular' in src.lower():
                js_libraries.append('Angular')
            elif 'vue' in src.lower():
                js_libraries.append('Vue.js')
            elif 'bootstrap' in src.lower():
                js_libraries.append('Bootstrap')
        
        if js_libraries:
            result['characteristics']['js_libraries'] = list(set(js_libraries))
        
        # 5. CSS Frameworks
        css_links = soup.find_all('link', rel='stylesheet')
        css_frameworks = []
        
        for link in css_links:
            href = link.get('href', '')
            if 'bootstrap' in href.lower():
                css_frameworks.append('Bootstrap')
            elif 'tailwind' in href.lower():
                css_frameworks.append('Tailwind CSS')
            elif 'foundation' in href.lower():
                css_frameworks.append('Foundation')
            elif 'bulma' in href.lower():
                css_frameworks.append('Bulma')
        
        if css_frameworks:
            result['characteristics']['css_frameworks'] = list(set(css_frameworks))
        
        # 6. Unique Identifiers
        # WordPress
        if '/wp-content/' in html_content or '/wp-includes/' in html_content:
            result['signatures'].append('WordPress CMS')
        
        # Joomla
        if '/components/com_' in html_content or 'Joomla' in html_content:
            result['signatures'].append('Joomla CMS')
        
        # Drupal
        if 'Drupal' in html_content or '/sites/default/' in html_content:
            result['signatures'].append('Drupal CMS')
        
        # Shopify
        if 'cdn.shopify.com' in html_content or 'shopify' in html_content.lower():
            result['signatures'].append('Shopify E-commerce')
        
        # Wix
        if 'wix.com' in html_content:
            result['signatures'].append('Wix Website Builder')
        
        # 7. HTTP Headers Fingerprint
        header_fingerprint = {}
        interesting_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-Frame-Options']
        
        for header in interesting_headers:
            if header in response.headers:
                header_fingerprint[header] = response.headers[header]
        
        if header_fingerprint:
            result['fingerprints']['http_headers'] = header_fingerprint
        
        # 8. Response Characteristics
        result['characteristics']['response_size'] = len(html_content)
        result['characteristics']['status_code'] = response.status_code
        result['characteristics']['response_time_ms'] = round(response.elapsed.total_seconds() * 1000, 2)
        
        # 9. Forms Detection
        forms = soup.find_all('form')
        if forms:
            result['characteristics']['forms_count'] = len(forms)
            form_actions = [form.get('action', 'N/A') for form in forms[:5]]
            result['characteristics']['form_actions'] = form_actions
        
        # 10. External Resources
        external_domains = set()
        for tag in soup.find_all(['script', 'link', 'img'], src=True):
            src = tag.get('src', tag.get('href', ''))
            if src.startswith('http'):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(src)
                    if parsed.netloc and parsed.netloc != domain:
                        external_domains.add(parsed.netloc)
                except:
                    pass
        
        if external_domains:
            result['characteristics']['external_domains'] = list(external_domains)[:10]
        
    except requests.Timeout:
        result['error'] = 'Request timeout'
    except requests.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = f'Fingerprinting error: {str(e)}'
    
    return result
