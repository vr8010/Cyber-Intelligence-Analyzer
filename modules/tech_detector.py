"""
Website Technology Detector - Detect technologies used by website
"""
import requests
import re
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Technology signatures
TECH_SIGNATURES = {
    'cms': {
        'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
        'Joomla': ['/components/com_', '/modules/mod_', 'Joomla'],
        'Drupal': ['/sites/default/', '/misc/drupal.js', 'Drupal'],
        'Magento': ['/skin/frontend/', 'Mage.Cookies', 'Magento'],
        'Shopify': ['cdn.shopify.com', 'shopify'],
        'Wix': ['wix.com', 'parastorage'],
        'Squarespace': ['squarespace.com', 'squarespace'],
        'Ghost': ['/ghost/', 'ghost.org'],
        'PrestaShop': ['/modules/prestashop', 'prestashop']
    },
    'frameworks': {
        'React': ['react', '_react', 'react-dom'],
        'Angular': ['ng-', 'angular', 'ng-app'],
        'Vue.js': ['vue', 'v-if', 'v-for'],
        'jQuery': ['jquery', 'jQuery'],
        'Bootstrap': ['bootstrap', 'Bootstrap'],
        'Tailwind': ['tailwind'],
        'Next.js': ['_next/', '__next'],
        'Nuxt.js': ['_nuxt/', '__nuxt'],
        'Laravel': ['laravel', 'Laravel'],
        'Django': ['django', 'csrfmiddlewaretoken'],
        'Flask': ['flask'],
        'Express': ['express']
    },
    'servers': {
        'Apache': ['Apache'],
        'Nginx': ['nginx'],
        'IIS': ['Microsoft-IIS'],
        'LiteSpeed': ['LiteSpeed'],
        'Cloudflare': ['cloudflare'],
        'Varnish': ['varnish']
    },
    'analytics': {
        'Google Analytics': ['google-analytics.com', 'gtag', 'ga.js'],
        'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
        'Facebook Pixel': ['facebook.net/en_US/fbevents.js', 'fbq'],
        'Hotjar': ['hotjar.com'],
        'Mixpanel': ['mixpanel.com'],
        'Segment': ['segment.com/analytics.js']
    },
    'advertising': {
        'Google AdSense': ['googlesyndication.com', 'adsbygoogle'],
        'Google AdWords': ['googleadservices.com'],
        'Media.net': ['media.net'],
        'Amazon Associates': ['amazon-adsystem.com']
    },
    'cdn': {
        'Cloudflare': ['cloudflare'],
        'CloudFront': ['cloudfront.net'],
        'Akamai': ['akamai'],
        'Fastly': ['fastly'],
        'jsDelivr': ['jsdelivr.net'],
        'unpkg': ['unpkg.com'],
        'cdnjs': ['cdnjs.cloudflare.com']
    },
    'payment': {
        'Stripe': ['stripe.com', 'stripe.js'],
        'PayPal': ['paypal.com', 'paypal'],
        'Square': ['squareup.com'],
        'Razorpay': ['razorpay.com']
    },
    'security': {
        'reCAPTCHA': ['recaptcha', 'google.com/recaptcha'],
        'hCaptcha': ['hcaptcha.com'],
        'Cloudflare Turnstile': ['challenges.cloudflare.com']
    }
}

def detect_technologies(domain):
    """
    Detect technologies used by a website
    """
    result = {
        'domain': domain,
        'technologies': {},
        'total_detected': 0
    }
    
    try:
        # Fetch website
        url = f'https://{domain}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        html_content = response.text
        response_headers = response.headers
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Combine all text for searching
        page_text = html_content.lower()
        headers_text = str(response_headers).lower()
        
        # Check each technology category
        for category, technologies in TECH_SIGNATURES.items():
            detected = []
            
            for tech_name, signatures in technologies.items():
                for signature in signatures:
                    if signature.lower() in page_text or signature.lower() in headers_text:
                        if tech_name not in detected:
                            detected.append(tech_name)
                        break
            
            if detected:
                result['technologies'][category] = detected
                result['total_detected'] += len(detected)
        
        # Detect from meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            generator = meta_generator.get('content')
            if 'cms' not in result['technologies']:
                result['technologies']['cms'] = []
            if generator not in result['technologies']['cms']:
                result['technologies']['cms'].append(generator)
                result['total_detected'] += 1
        
        # Detect from server header
        server = response_headers.get('Server', '')
        if server:
            result['server'] = server
            # Add to servers if not already detected
            if 'servers' not in result['technologies']:
                result['technologies']['servers'] = []
            if server not in result['technologies']['servers']:
                result['technologies']['servers'].append(server)
        
        # Detect programming language hints
        result['technologies']['languages'] = []
        if '.php' in page_text or 'php' in headers_text:
            result['technologies']['languages'].append('PHP')
        if '.asp' in page_text or 'asp.net' in headers_text:
            result['technologies']['languages'].append('ASP.NET')
        if '.jsp' in page_text or 'java' in headers_text:
            result['technologies']['languages'].append('Java')
        if 'python' in headers_text:
            result['technologies']['languages'].append('Python')
        
        if result['technologies']['languages']:
            result['total_detected'] += len(result['technologies']['languages'])
        else:
            del result['technologies']['languages']
        
        # Get charset
        charset = soup.find('meta', attrs={'charset': True})
        if charset:
            result['charset'] = charset.get('charset', 'UTF-8')
        
        # Get viewport
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if viewport:
            result['responsive'] = True
        else:
            result['responsive'] = False
        
    except requests.Timeout:
        result['error'] = 'Request timeout'
    except requests.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = f'Detection error: {str(e)}'
    
    return result
