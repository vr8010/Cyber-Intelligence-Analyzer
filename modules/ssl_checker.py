"""
SSL Checker - python ssl library + Qualys SSL Labs API for grade
"""
import ssl
import socket
import requests
import time
from datetime import datetime


def _ssl_labs_grade(domain):
    """Get SSL grade from Qualys SSL Labs API (free, no key needed)"""
    try:
        # Trigger analysis
        r = requests.get(
            'https://api.ssllabs.com/api/v3/analyze',
            params={'host': domain, 'startNew': 'on', 'all': 'done'},
            timeout=15
        )
        if r.status_code != 200:
            return None

        data = r.json()
        status = data.get('status', '')

        # Poll until ready (max 60s)
        attempts = 0
        while status not in ('READY', 'ERROR') and attempts < 6:
            time.sleep(10)
            attempts += 1
            r = requests.get(
                'https://api.ssllabs.com/api/v3/analyze',
                params={'host': domain, 'all': 'done'},
                timeout=15
            )
            if r.status_code != 200:
                break
            data = r.json()
            status = data.get('status', '')

        if status == 'READY':
            endpoints = data.get('endpoints', [])
            if endpoints:
                ep = endpoints[0]
                return {
                    'grade':          ep.get('grade', 'N/A'),
                    'grade_trust_ignored': ep.get('gradeTrustIgnored', 'N/A'),
                    'has_warnings':   ep.get('hasWarnings', False),
                    'is_exceptional': ep.get('isExceptional', False),
                    'ip_address':     ep.get('ipAddress', 'N/A'),
                    'status_message': ep.get('statusMessage', ''),
                }
    except Exception as e:
        return {'error': str(e)}
    return None


def check_ssl(domain):
    result = {
        'valid':    False,
        'issuer':   'N/A',
        'expiry':   'N/A',
        'subject':  'N/A',
        'version':  'N/A',
        'protocol': 'N/A',
        'cipher':   'N/A',
        'san':      [],
        'days_left': None,
        'grade':    None,
    }

    # ── Python ssl library ───────────────────────────────────
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()
                cipher  = ssock.cipher()
                version = ssock.version()

                issuer_dict  = dict(x[0] for x in cert.get('issuer', []))
                subject_dict = dict(x[0] for x in cert.get('subject', []))

                expiry_str = cert.get('notAfter', '')
                try:
                    expiry_dt  = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_left  = (expiry_dt - datetime.utcnow()).days
                except Exception:
                    expiry_dt = None
                    days_left = None

                # Subject Alternative Names
                san = []
                for stype, sval in cert.get('subjectAltName', []):
                    if stype == 'DNS':
                        san.append(sval)

                result.update({
                    'valid':     True,
                    'issuer':    issuer_dict.get('organizationName',
                                 issuer_dict.get('commonName', 'N/A')),
                    'expiry':    expiry_str,
                    'subject':   subject_dict.get('commonName', 'N/A'),
                    'version':   cert.get('version', 'N/A'),
                    'protocol':  version,
                    'cipher':    cipher[0] if cipher else 'N/A',
                    'san':       san[:10],
                    'days_left': days_left,
                    'not_before': cert.get('notBefore', 'N/A'),
                })

                # Warn if expiring soon
                if days_left is not None and days_left < 30:
                    result['warning'] = f'Certificate expires in {days_left} days!'

    except ssl.SSLCertVerificationError as e:
        result['error'] = f'Certificate verification failed: {e}'
    except ssl.SSLError as e:
        result['error'] = f'SSL error: {e}'
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except Exception as e:
        result['error'] = str(e)

    # ── SSL Labs grade (non-blocking best-effort) ────────────
    try:
        grade_info = _ssl_labs_grade(domain)
        if grade_info:
            result['grade'] = grade_info
    except Exception:
        pass

    return result
