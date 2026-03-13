import socket
import dns.resolver

def dns_lookup(domain):
    result = {}
    try:
        result['ip'] = socket.gethostbyname(domain)
        
        # DNS Records
        for record_type in ['A', 'MX', 'TXT', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = [str(rdata) for rdata in answers]
            except:
                result[record_type] = []
    except Exception as e:
        result['error'] = str(e)
    
    return result
