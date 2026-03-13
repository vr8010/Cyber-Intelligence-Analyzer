import re

def detect_phishing(domain):
    score = 0
    indicators = []
    
    # Check URL length
    if len(domain) > 30:
        score += 20
        indicators.append('Long domain name')
    
    # Check for IP address
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 40
        indicators.append('IP address used instead of domain')
    
    # Check for suspicious keywords
    suspicious_words = ['login', 'verify', 'account', 'secure', 'update', 'confirm']
    for word in suspicious_words:
        if word in domain.lower():
            score += 10
            indicators.append(f'Suspicious keyword: {word}')
    
    # Check for excessive hyphens
    if domain.count('-') > 3:
        score += 15
        indicators.append('Excessive hyphens')
    
    # Check for subdomain depth
    if domain.count('.') > 3:
        score += 15
        indicators.append('Deep subdomain structure')
    
    return {
        'score': min(score, 100),
        'indicators': indicators,
        'risk_level': 'High' if score > 50 else 'Medium' if score > 25 else 'Low'
    }
