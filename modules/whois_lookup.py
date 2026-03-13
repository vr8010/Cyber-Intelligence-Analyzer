import whois
from datetime import datetime

def whois_info(domain):
    try:
        w = whois.whois(domain)
        
        # Extract domain name
        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]
        
        # Extract dates
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        # Handle list or single date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        # Calculate domain age
        age_days = 0
        if creation_date:
            age_days = (datetime.now() - creation_date).days
        
        # Extract registrar
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        
        # Extract name servers
        name_servers = w.name_servers if w.name_servers else []
        
        # Extract emails
        emails = w.emails if hasattr(w, 'emails') and w.emails else []
        if isinstance(emails, str):
            emails = [emails]
        
        return {
            'domain_name': domain_name,
            'registrar': registrar if registrar else 'N/A',
            'creation_date': str(creation_date) if creation_date else 'N/A',
            'expiration_date': str(expiration_date) if expiration_date else 'N/A',
            'age_days': age_days,
            'name_servers': name_servers,
            'emails': emails
        }
    except Exception as e:
        return {'error': str(e)}
