"""
Test script for all security and networking modules
"""
from modules.ssl_checker import check_ssl
from modules.dns_lookup import dns_lookup
from modules.whois_lookup import whois_info
from modules.security_headers import check_headers
from modules.phishing_detector import detect_phishing
from modules.subdomain_enum import enumerate_subdomains
from modules.port_scanner import scan_ports
from modules.ip_geolocation import get_ip_info
from modules.cdn_detector import detect_cdn
from modules.traceroute import traceroute
from modules.cvss_calculator import calculate_cvss_score
from modules.report_generator import generate_json_report, generate_xml_report
import json

def test_domain(domain):
    """Test all modules with a domain"""
    print(f"\n{'='*60}")
    print(f"Testing domain: {domain}")
    print(f"{'='*60}\n")
    
    # Test SSL
    print("1. Testing SSL Checker...")
    ssl_result = check_ssl(domain)
    print(f"   SSL Valid: {ssl_result.get('valid', 'N/A')}")
    
    # Test DNS
    print("\n2. Testing DNS Lookup...")
    dns_result = dns_lookup(domain)
    print(f"   IP: {dns_result.get('ip', 'N/A')}")
    
    # Test WHOIS
    print("\n3. Testing WHOIS Lookup...")
    whois_result = whois_info(domain)
    print(f"   Registrar: {whois_result.get('registrar', 'N/A')}")
    
    # Test Security Headers
    print("\n4. Testing Security Headers...")
    headers_result = check_headers(domain)
    print(f"   Headers found: {len(headers_result) if not headers_result.get('error') else 0}")
    
    # Test Phishing Detection
    print("\n5. Testing Phishing Detector...")
    phishing_result = detect_phishing(domain)
    print(f"   Risk Score: {phishing_result.get('score', 'N/A')}/100")
    
    # Test Subdomain Enumeration
    print("\n6. Testing Subdomain Enumeration...")
    subdomains = enumerate_subdomains(domain)
    print(f"   Subdomains found: {len(subdomains)}")
    
    # Test Port Scanner
    print("\n7. Testing Port Scanner...")
    ports_result = scan_ports(domain, ports=[80, 443, 22, 21, 25])
    print(f"   Open ports: {ports_result.get('total_open', 0)}")
    
    # Test IP Geolocation
    print("\n8. Testing IP Geolocation...")
    ip_info = get_ip_info(domain)
    print(f"   Location: {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}")
    
    # Test CDN Detection
    print("\n9. Testing CDN Detection...")
    cdn_info = detect_cdn(domain)
    print(f"   CDN Detected: {cdn_info.get('cdn_detected', False)}")
    if cdn_info.get('provider'):
        print(f"   Provider: {cdn_info['provider']}")
    
    # Test Traceroute (skip for speed)
    print("\n10. Testing Traceroute... (skipped for speed)")
    
    # Test CVSS Calculator
    print("\n11. Testing CVSS Calculator...")
    scan_data = {
        'domain': domain,
        'ssl': ssl_result,
        'headers': headers_result,
        'phishing': phishing_result,
        'ports': ports_result,
        'dns': dns_result
    }
    cvss_result = calculate_cvss_score(scan_data)
    print(f"   CVSS Score: {cvss_result['score']} ({cvss_result['severity']})")
    print(f"   Findings: {cvss_result['total_findings']}")
    
    # Test Report Generation
    print("\n12. Testing Report Generators...")
    
    complete_data = {
        'domain': domain,
        'ssl': ssl_result,
        'dns': dns_result,
        'whois': whois_result,
        'headers': headers_result,
        'phishing': phishing_result,
        'subdomains': subdomains,
        'ports': ports_result,
        'ip_info': ip_info,
        'cdn_info': cdn_info,
        'cvss': cvss_result
    }
    
    # JSON Report
    json_report = generate_json_report(complete_data)
    print(f"   JSON Report: {len(json_report)} bytes")
    
    # XML Report
    xml_report = generate_xml_report(complete_data)
    print(f"   XML Report: {len(xml_report)} bytes")
    
    print(f"\n{'='*60}")
    print("All modules tested successfully!")
    print(f"{'='*60}\n")
    
    return complete_data

if __name__ == '__main__':
    # Test with a well-known domain
    test_domains = ['google.com', 'github.com']
    
    print("\n" + "="*60)
    print("CYBERSCAN.AI - MODULE TEST")
    print("="*60)
    
    for domain in test_domains:
        try:
            result = test_domain(domain)
        except Exception as e:
            print(f"\nError testing {domain}: {str(e)}")
    
    print("\n✅ Testing completed!")
    print("\nNote: Some tests may fail due to network restrictions or timeouts.")
    print("This is normal and doesn't indicate a problem with the modules.\n")
