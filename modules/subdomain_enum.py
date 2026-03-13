import socket

def enumerate_subdomains(domain):
    common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog', 'shop']
    found = []
    
    for sub in common_subdomains:
        subdomain = f'{sub}.{domain}'
        try:
            socket.gethostbyname(subdomain)
            found.append(subdomain)
        except:
            pass
    
    return found
