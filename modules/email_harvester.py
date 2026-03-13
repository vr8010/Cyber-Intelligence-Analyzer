"""
Email Harvester - Extract email addresses from website
"""
import requests
import re
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def harvest_emails(domain):
    """
    Harvest email addresses from website
    """
    result = {
        'domain': domain,
        'emails': [],
        'total_found': 0,
        'sources': {}
    }
    
    try:
        url = f'https://{domain}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Fetch main page
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        html_content = response.text
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Email regex pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Find emails in HTML content
        emails_in_html = set(re.findall(email_pattern, html_content))
        
        # Find emails in mailto links
        mailto_links = soup.find_all('a', href=re.compile(r'^mailto:', re.I))
        emails_in_mailto = set()
        for link in mailto_links:
            href = link.get('href', '')
            email_match = re.search(email_pattern, href)
            if email_match:
                emails_in_mailto.add(email_match.group())
        
        # Find emails in text content
        text_content = soup.get_text()
        emails_in_text = set(re.findall(email_pattern, text_content))
        
        # Combine all emails
        all_emails = emails_in_html | emails_in_mailto | emails_in_text
        
        # Filter out common false positives
        filtered_emails = []
        exclude_patterns = [
            'example.com', 'test.com', 'domain.com',
            'email.com', 'mail.com', 'yoursite.com',
            'wix.com', 'weebly.com', 'wordpress.com'
        ]
        
        for email in all_emails:
            if not any(pattern in email.lower() for pattern in exclude_patterns):
                filtered_emails.append(email)
                
                # Track source
                if email in emails_in_mailto:
                    result['sources'][email] = 'mailto link'
                elif email in emails_in_html:
                    result['sources'][email] = 'HTML source'
                else:
                    result['sources'][email] = 'page text'
        
        result['emails'] = sorted(list(set(filtered_emails)))
        result['total_found'] = len(result['emails'])
        
        # Check common pages for more emails
        common_pages = ['contact', 'about', 'team', 'contact-us', 'about-us']
        for page in common_pages:
            try:
                page_url = f'{url}/{page}'
                page_response = requests.get(page_url, headers=headers, timeout=3, verify=False)
                if page_response.status_code == 200:
                    page_emails = set(re.findall(email_pattern, page_response.text))
                    for email in page_emails:
                        if email not in result['emails'] and not any(p in email.lower() for p in exclude_patterns):
                            result['emails'].append(email)
                            result['sources'][email] = f'/{page} page'
            except:
                pass
        
        result['total_found'] = len(result['emails'])
        
    except requests.Timeout:
        result['error'] = 'Request timeout'
    except requests.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = f'Harvesting error: {str(e)}'
    
    return result
