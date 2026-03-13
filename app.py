from flask import Flask, render_template, request, jsonify, send_file, Response
import sqlite3
from datetime import datetime
from io import BytesIO
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
from modules.report_generator import generate_json_report, generate_xml_report, generate_pdf_report
from modules.http_analyzer import analyze_http_headers
from modules.tech_detector import detect_technologies
from modules.directory_enum import enumerate_directories
from modules.email_harvester import harvest_emails
from modules.fingerprinting import fingerprint_website
from modules.waf_detector import detect_waf
from modules.banner_grabber import grab_banners
from modules.reverse_ip import reverse_ip_lookup

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT,
                  scan_date TEXT,
                  ssl_status TEXT,
                  security_headers TEXT,
                  phishing_score INTEGER,
                  cvss_score REAL,
                  open_ports INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS domain_info
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT,
                  registrar TEXT,
                  creation_date TEXT,
                  expiration_date TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    # Remove protocol if present
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    # Perform all scans
    ssl_result = check_ssl(domain)
    dns_result = dns_lookup(domain)
    whois_result = whois_info(domain)
    headers_result = check_headers(domain)
    phishing_result = detect_phishing(domain)
    subdomains = enumerate_subdomains(domain)
    
    # New networking modules
    ports_result = scan_ports(domain)
    ip_info = get_ip_info(domain)
    cdn_info = detect_cdn(domain)
    
    # Traceroute (optional - may timeout)
    try:
        traceroute_result = traceroute(domain)
    except Exception as e:
        traceroute_result = {
            'error': f'Traceroute unavailable: {str(e)}',
            'domain': domain,
            'hops': [],
            'total_hops': 0
        }
    
    # New advanced modules
    http_analysis = analyze_http_headers(domain)
    tech_stack = detect_technologies(domain)
    directories = enumerate_directories(domain)
    emails = harvest_emails(domain)
    fingerprint = fingerprint_website(domain)
    waf_info = detect_waf(domain)
    banners = grab_banners(domain)
    reverse_ip = reverse_ip_lookup(domain)
    
    # Prepare data for CVSS calculation
    scan_data = {
        'domain': domain,
        'ssl': ssl_result,
        'headers': headers_result,
        'phishing': phishing_result,
        'ports': ports_result,
        'dns': dns_result
    }
    
    # Calculate CVSS score
    cvss_result = calculate_cvss_score(scan_data)
    
    # Store in database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''INSERT INTO scans (domain, scan_date, ssl_status, security_headers, phishing_score, cvss_score, open_ports)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (domain, datetime.now().isoformat(), str(ssl_result), str(headers_result), 
               phishing_result['score'], cvss_result['score'], ports_result.get('total_open', 0)))
    
    if whois_result:
        c.execute('''INSERT INTO domain_info (domain, registrar, creation_date, expiration_date)
                     VALUES (?, ?, ?, ?)''',
                  (domain, whois_result.get('registrar', 'N/A'),
                   whois_result.get('creation_date', 'N/A'),
                   whois_result.get('expiration_date', 'N/A')))
    conn.commit()
    conn.close()
    
    return render_template('result.html',
                         domain=domain,
                         ssl=ssl_result,
                         dns=dns_result,
                         whois=whois_result,
                         headers=headers_result,
                         phishing=phishing_result,
                         subdomains=subdomains,
                         ports=ports_result,
                         ip_info=ip_info,
                         cdn_info=cdn_info,
                         traceroute=traceroute_result,
                         cvss=cvss_result,
                         http_analysis=http_analysis,
                         tech_stack=tech_stack,
                         directories=directories,
                         emails=emails,
                         fingerprint=fingerprint,
                         waf_info=waf_info,
                         banners=banners,
                         reverse_ip=reverse_ip)

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY scan_date DESC LIMIT 20')
    scans = c.fetchall()
    
    # Get domain info for each scan
    scan_details = []
    for scan in scans:
        c.execute('SELECT * FROM domain_info WHERE domain = ? ORDER BY id DESC LIMIT 1', (scan[1],))
        domain_info = c.fetchone()
        scan_details.append({
            'id': scan[0],
            'domain': scan[1],
            'scan_date': scan[2],
            'ssl_status': scan[3],
            'security_headers': scan[4],
            'phishing_score': scan[5],
            'cvss_score': scan[6],
            'open_ports': scan[7],
            'domain_info': domain_info
        })
    
    conn.close()
    return render_template('dashboard.html', scans=scan_details)

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete a specific scan from history"""
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Scan deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear all scan history"""
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('DELETE FROM scans')
        c.execute('DELETE FROM domain_info')
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'All scan history cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_full_scan/<domain>')
def get_full_scan(domain):
    """Perform a fresh scan with all 20 modules and return complete data"""
    try:
        # Perform all 20 module scans
        ssl_result = check_ssl(domain)
        dns_result = dns_lookup(domain)
        whois_result = whois_info(domain)
        headers_result = check_headers(domain)
        phishing_result = detect_phishing(domain)
        subdomains = enumerate_subdomains(domain)
        ports_result = scan_ports(domain)
        ip_info = get_ip_info(domain)
        cdn_info = detect_cdn(domain)
        
        try:
            traceroute_result = traceroute(domain)
        except:
            traceroute_result = {'error': 'Traceroute unavailable', 'hops': [], 'total_hops': 0}
        
        http_analysis = analyze_http_headers(domain)
        tech_stack = detect_technologies(domain)
        directories = enumerate_directories(domain)
        emails = harvest_emails(domain)
        fingerprint = fingerprint_website(domain)
        waf_info = detect_waf(domain)
        banners = grab_banners(domain)
        reverse_ip_result = reverse_ip_lookup(domain)
        
        cvss_result = calculate_cvss_score({
            'domain': domain,
            'ssl': ssl_result,
            'headers': headers_result,
            'phishing': phishing_result,
            'ports': ports_result,
            'dns': dns_result
        })
        
        # Return all module data as JSON
        return jsonify({
            'success': True,
            'domain': domain,
            'modules': {
                'ssl': ssl_result,
                'dns': dns_result,
                'whois': whois_result,
                'headers': headers_result,
                'phishing': phishing_result,
                'subdomains': subdomains,
                'ports': ports_result,
                'ip_info': ip_info,
                'cdn_info': cdn_info,
                'traceroute': traceroute_result,
                'cvss': cvss_result,
                'http_analysis': http_analysis,
                'tech_stack': tech_stack,
                'directories': directories,
                'emails': emails,
                'fingerprint': fingerprint,
                'waf_info': waf_info,
                'banners': banners,
                'reverse_ip': reverse_ip_result
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/export/<format>/<domain>')
def export_report(format, domain):
    """Export comprehensive scan report in JSON, XML, or PDF format with all 20 modules"""
    # Perform fresh scan with all modules
    ssl_result = check_ssl(domain)
    dns_result = dns_lookup(domain)
    whois_result = whois_info(domain)
    headers_result = check_headers(domain)
    phishing_result = detect_phishing(domain)
    subdomains = enumerate_subdomains(domain)
    ports_result = scan_ports(domain)
    ip_info = get_ip_info(domain)
    cdn_info = detect_cdn(domain)
    
    # Traceroute (optional)
    try:
        traceroute_result = traceroute(domain)
    except:
        traceroute_result = {'error': 'Traceroute unavailable'}
    
    # Advanced modules
    http_analysis = analyze_http_headers(domain)
    tech_stack = detect_technologies(domain)
    directories = enumerate_directories(domain)
    emails = harvest_emails(domain)
    fingerprint = fingerprint_website(domain)
    waf_info = detect_waf(domain)
    banners = grab_banners(domain)
    reverse_ip_result = reverse_ip_lookup(domain)
    
    # Prepare complete scan data with all 20 modules
    scan_data = {
        'domain': domain,
        'scan_date': datetime.now().isoformat(),
        'ssl': ssl_result,
        'dns': dns_result,
        'whois': whois_result,
        'headers': headers_result,
        'phishing': phishing_result,
        'subdomains': subdomains,
        'ports': ports_result,
        'ip_info': ip_info,
        'cdn_info': cdn_info,
        'traceroute': traceroute_result,
        'http_analysis': http_analysis,
        'tech_stack': tech_stack,
        'directories': directories,
        'emails': emails,
        'fingerprint': fingerprint,
        'waf_info': waf_info,
        'banners': banners,
        'reverse_ip': reverse_ip_result,
        'cvss': calculate_cvss_score({
            'domain': domain,
            'ssl': ssl_result,
            'headers': headers_result,
            'phishing': phishing_result,
            'ports': ports_result,
            'dns': dns_result
        })
    }
    
    if format == 'json':
        report = generate_json_report(scan_data)
        return Response(
            report,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename={domain}_comprehensive_report.json'}
        )
    
    elif format == 'xml':
        report = generate_xml_report(scan_data)
        return Response(
            report,
            mimetype='application/xml',
            headers={'Content-Disposition': f'attachment;filename={domain}_comprehensive_report.xml'}
        )
    
    elif format == 'pdf':
        pdf_data = generate_pdf_report(scan_data)
        if pdf_data:
            return send_file(
                BytesIO(pdf_data),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'{domain}_comprehensive_report.pdf'
            )
        else:
            return jsonify({'error': 'PDF generation requires reportlab library. Install: pip install reportlab'}), 500
    
    return jsonify({'error': 'Invalid format. Use json, xml, or pdf'}), 400

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
