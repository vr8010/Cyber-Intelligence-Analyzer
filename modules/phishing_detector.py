"""
Phishing Detector - PhishTank + VirusTotal + heuristic scoring
"""
import re
import os
import hashlib
import requests


def _phishtank_check(domain):
    """Check domain against PhishTank API"""
    api_key = os.getenv('PHISHTANK_API_KEY', '')
    url = 'https://checkurl.phishtank.com/checkurl/'
    try:
        data = {'url': f'http://{domain}', 'format': 'json'}
        if api_key:
            data['app_key'] = api_key
        r = requests.post(url, data=data, timeout=8,
                          headers={'User-Agent': 'phishtank/CYBERSCAN.AI'})
        if r.status_code == 200:
            j = r.json()
            result = j.get('results', {})
            return {
                'checked': True,
                'in_database': result.get('in_database', False),
                'valid': result.get('valid', False),
                'verified': result.get('verified', False),
                'phish_id': result.get('phish_id', ''),
            }
    except Exception as e:
        return {'checked': False, 'error': str(e)}
    return {'checked': False}


def _virustotal_check(domain):
    """Check domain reputation via VirusTotal API v3"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return {'checked': False, 'error': 'VIRUSTOTAL_API_KEY not set'}
    try:
        headers = {'x-apikey': api_key}
        r = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            attrs = r.json().get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            votes = attrs.get('total_votes', {})
            cats  = attrs.get('categories', {})
            return {
                'checked': True,
                'malicious':   stats.get('malicious', 0),
                'suspicious':  stats.get('suspicious', 0),
                'harmless':    stats.get('harmless', 0),
                'undetected':  stats.get('undetected', 0),
                'reputation':  attrs.get('reputation', 0),
                'categories':  list(cats.values())[:5],
                'community_malicious': votes.get('malicious', 0),
                'community_harmless':  votes.get('harmless', 0),
            }
        elif r.status_code == 404:
            return {'checked': True, 'malicious': 0, 'suspicious': 0,
                    'harmless': 0, 'undetected': 0, 'reputation': 0,
                    'categories': [], 'note': 'Domain not in VirusTotal database'}
        else:
            return {'checked': False, 'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'checked': False, 'error': str(e)}


def detect_phishing(domain):
    # ── Heuristic scoring ────────────────────────────────────
    score = 0
    indicators = []

    if len(domain) > 30:
        score += 15
        indicators.append('Long domain name')

    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 40
        indicators.append('IP address used instead of domain')

    suspicious_words = ['login', 'verify', 'account', 'secure', 'update',
                        'confirm', 'banking', 'paypal', 'signin', 'password']
    for word in suspicious_words:
        if word in domain.lower():
            score += 10
            indicators.append(f'Suspicious keyword: {word}')

    if domain.count('-') > 3:
        score += 15
        indicators.append('Excessive hyphens in domain')

    if domain.count('.') > 3:
        score += 15
        indicators.append('Deep subdomain structure')

    suspicious_tlds = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.tk', '.ml']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 20
            indicators.append(f'Suspicious TLD: {tld}')

    # ── PhishTank ────────────────────────────────────────────
    pt = _phishtank_check(domain)
    if pt.get('in_database') and pt.get('valid'):
        score += 60
        indicators.append('⚠ Listed in PhishTank database as active phish')
    elif pt.get('in_database'):
        score += 30
        indicators.append('Found in PhishTank database (unverified)')

    # ── VirusTotal ───────────────────────────────────────────
    vt = _virustotal_check(domain)
    if vt.get('checked'):
        mal = vt.get('malicious', 0)
        sus = vt.get('suspicious', 0)
        if mal > 5:
            score += 50
            indicators.append(f'⚠ VirusTotal: {mal} engines flagged as malicious')
        elif mal > 0:
            score += 25
            indicators.append(f'VirusTotal: {mal} engine(s) flagged as malicious')
        if sus > 0:
            score += 10
            indicators.append(f'VirusTotal: {sus} engine(s) flagged as suspicious')
        if vt.get('reputation', 0) < -10:
            score += 15
            indicators.append(f'VirusTotal reputation score: {vt["reputation"]}')

    final_score = min(score, 100)
    risk = 'Critical' if final_score > 75 else \
           'High'     if final_score > 50 else \
           'Medium'   if final_score > 25 else 'Low'

    return {
        'score':       final_score,
        'indicators':  indicators,
        'risk_level':  risk,
        'phishtank':   pt,
        'virustotal':  vt,
    }
