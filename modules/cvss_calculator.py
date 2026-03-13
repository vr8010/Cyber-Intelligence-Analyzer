"""
CVSS Score Calculator - Calculate security risk score based on findings
"""

def calculate_cvss_score(scan_results):
    """
    Calculate CVSS-like score based on scan results
    Score range: 0.0 - 10.0
    - 0.0-3.9: Low
    - 4.0-6.9: Medium
    - 7.0-8.9: High
    - 9.0-10.0: Critical
    """
    score = 0.0
    findings = []
    
    # SSL/TLS Issues (up to 3.0 points)
    if scan_results.get('ssl'):
        ssl = scan_results['ssl']
        if not ssl.get('valid', True):
            score += 2.5
            findings.append('Invalid SSL certificate')
        if ssl.get('expired', False):
            score += 3.0
            findings.append('Expired SSL certificate')
        elif ssl.get('days_until_expiry', 365) < 30:
            score += 1.0
            findings.append('SSL certificate expiring soon')
    
    # Security Headers (up to 2.5 points)
    if scan_results.get('headers'):
        headers = scan_results['headers']
        missing_headers = []
        
        if not headers.get('strict-transport-security'):
            score += 0.5
            missing_headers.append('HSTS')
        if not headers.get('x-frame-options'):
            score += 0.5
            missing_headers.append('X-Frame-Options')
        if not headers.get('x-content-type-options'):
            score += 0.3
            missing_headers.append('X-Content-Type-Options')
        if not headers.get('content-security-policy'):
            score += 0.7
            missing_headers.append('CSP')
        if not headers.get('x-xss-protection'):
            score += 0.5
            missing_headers.append('XSS-Protection')
        
        if missing_headers:
            findings.append(f'Missing security headers: {", ".join(missing_headers)}')
    
    # Phishing Score (up to 2.0 points)
    if scan_results.get('phishing'):
        phishing_score = scan_results['phishing'].get('score', 0)
        if phishing_score > 70:
            score += 2.0
            findings.append('High phishing risk detected')
        elif phishing_score > 40:
            score += 1.0
            findings.append('Medium phishing risk detected')
    
    # Open Ports (up to 1.5 points)
    if scan_results.get('ports'):
        open_ports = scan_results['ports'].get('open_ports', [])
        risky_ports = [p for p in open_ports if p.get('port') in [21, 23, 3389, 5900]]
        
        if len(risky_ports) > 0:
            score += 1.5
            findings.append(f'Risky ports open: {", ".join([str(p["port"]) for p in risky_ports])}')
        elif len(open_ports) > 10:
            score += 0.5
            findings.append(f'Many open ports detected: {len(open_ports)}')
    
    # DNS Issues (up to 1.0 points)
    if scan_results.get('dns'):
        dns = scan_results['dns']
        if not dns.get('records'):
            score += 0.5
            findings.append('DNS configuration issues')
    
    # Cap score at 10.0
    score = min(score, 10.0)
    
    # Determine severity
    if score < 4.0:
        severity = 'Low'
        color = 'success'
    elif score < 7.0:
        severity = 'Medium'
        color = 'warning'
    elif score < 9.0:
        severity = 'High'
        color = 'danger'
    else:
        severity = 'Critical'
        color = 'critical'
    
    return {
        'score': round(score, 1),
        'severity': severity,
        'color': color,
        'findings': findings,
        'total_findings': len(findings)
    }
