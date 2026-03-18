from flask import Flask, render_template, request, jsonify, send_file, Response, session
import sqlite3
from datetime import datetime
from io import BytesIO
import json
import time
import os
from groq import Groq
from dotenv import load_dotenv
load_dotenv()
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
app.secret_key = 'cyber_intel_secret_key'

# In-memory scan results cache
scan_cache = {}

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
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    return render_template('scanning.html', domain=domain)


@app.route('/scan_stream/<domain>')
def scan_stream(domain):
    """SSE endpoint - streams scan progress to client"""
    def generate():
        results = {}

        def send(step, label, data=None, progress=0):
            payload = json.dumps({'step': step, 'label': label, 'progress': progress, 'data': data})
            return f"data: {payload}\n\n"

        modules = [
            ('ssl',        'SSL Certificate',        lambda: check_ssl(domain)),
            ('dns',        'DNS Lookup',              lambda: dns_lookup(domain)),
            ('whois',      'WHOIS Info',              lambda: whois_info(domain)),
            ('headers',    'Security Headers',        lambda: check_headers(domain)),
            ('phishing',   'Phishing Detection',      lambda: detect_phishing(domain)),
            ('subdomains', 'Subdomain Enumeration',   lambda: enumerate_subdomains(domain)),
            ('ports',      'Port Scanner',            lambda: scan_ports(domain)),
            ('ip_info',    'IP Geolocation',          lambda: get_ip_info(domain)),
            ('cdn_info',   'CDN Detection',           lambda: detect_cdn(domain)),
            ('traceroute', 'Traceroute',              lambda: traceroute(domain)),
            ('http_analysis', 'HTTP Analysis',        lambda: analyze_http_headers(domain)),
            ('tech_stack', 'Tech Detection',          lambda: detect_technologies(domain)),
            ('directories','Directory Enumeration',   lambda: enumerate_directories(domain)),
            ('emails',     'Email Harvesting',        lambda: harvest_emails(domain)),
            ('fingerprint','Fingerprinting',          lambda: fingerprint_website(domain)),
            ('waf_info',   'WAF Detection',           lambda: detect_waf(domain)),
            ('banners',    'Banner Grabbing',         lambda: grab_banners(domain)),
            ('reverse_ip', 'Reverse IP Lookup',       lambda: reverse_ip_lookup(domain)),
        ]

        total = len(modules) + 2  # +2 for cvss + db save

        for i, (key, label, fn) in enumerate(modules):
            yield send(key, label, progress=int((i / total) * 100))
            try:
                results[key] = fn()
            except Exception as e:
                results[key] = {'error': str(e)}

        # CVSS
        yield send('cvss', 'Calculating CVSS Score', progress=int((len(modules) / total) * 100))
        cvss_result = calculate_cvss_score({
            'domain': domain,
            'ssl': results.get('ssl', {}),
            'headers': results.get('headers', {}),
            'phishing': results.get('phishing', {}),
            'ports': results.get('ports', {}),
            'dns': results.get('dns', {}),
        })
        results['cvss'] = cvss_result

        # Save to DB
        yield send('saving', 'Saving Results', progress=95)
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            phishing_score = results.get('phishing', {}).get('score', 0)
            ports_open = results.get('ports', {}).get('total_open', 0)
            c.execute('''INSERT INTO scans (domain, scan_date, ssl_status, security_headers, phishing_score, cvss_score, open_ports)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (domain, datetime.now().isoformat(), str(results.get('ssl', {})),
                       str(results.get('headers', {})), phishing_score, cvss_result['score'], ports_open))
            whois_result = results.get('whois', {})
            if whois_result and not whois_result.get('error'):
                c.execute('''INSERT INTO domain_info (domain, registrar, creation_date, expiration_date)
                             VALUES (?, ?, ?, ?)''',
                          (domain, whois_result.get('registrar', 'N/A'),
                           whois_result.get('creation_date', 'N/A'),
                           whois_result.get('expiration_date', 'N/A')))
            conn.commit()
            conn.close()
        except Exception:
            pass

        # Cache results and signal done
        scan_cache[domain] = results
        yield send('done', 'Scan Complete', progress=100)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/scan_result/<domain>')
def scan_result(domain):
    results = scan_cache.get(domain, {})
    return render_template('result.html',
                           domain=domain,
                           ssl=results.get('ssl', {}),
                           dns=results.get('dns', {}),
                           whois=results.get('whois', {}),
                           headers=results.get('headers', {}),
                           phishing=results.get('phishing', {}),
                           subdomains=results.get('subdomains', []),
                           ports=results.get('ports', {}),
                           ip_info=results.get('ip_info', {}),
                           cdn_info=results.get('cdn_info', {}),
                           traceroute=results.get('traceroute', {'hops': [], 'total_hops': 0}),
                           cvss=results.get('cvss', {}),
                           http_analysis=results.get('http_analysis', {}),
                           tech_stack=results.get('tech_stack', {}),
                           directories=results.get('directories', {}),
                           emails=results.get('emails', {}),
                           fingerprint=results.get('fingerprint', {}),
                           waf_info=results.get('waf_info', {}),
                           banners=results.get('banners', {}),
                           reverse_ip=results.get('reverse_ip', {}))

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

@app.route('/save_ai_solution', methods=['POST'])
def save_ai_solution():
    """Save AI solution text into scan cache for PDF inclusion"""
    data = request.get_json()
    domain = data.get('domain', '')
    ai_text = data.get('ai_text', '')
    if domain and ai_text:
        if domain not in scan_cache:
            scan_cache[domain] = {}
        scan_cache[domain]['ai_solution'] = ai_text
    return jsonify({'ok': True})


@app.route('/export/<format>/<domain>')
def export_report(format, domain):
    """Export using cached scan data if available, else fresh scan"""
    cached = scan_cache.get(domain)
    if cached and len(cached) > 2:
        # Use cached results from the scan
        scan_data = {
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'ssl':          cached.get('ssl', {}),
            'dns':          cached.get('dns', {}),
            'whois':        cached.get('whois', {}),
            'headers':      cached.get('headers', {}),
            'phishing':     cached.get('phishing', {}),
            'subdomains':   cached.get('subdomains', []),
            'ports':        cached.get('ports', {}),
            'ip_info':      cached.get('ip_info', {}),
            'cdn_info':     cached.get('cdn_info', {}),
            'traceroute':   cached.get('traceroute', {'hops': [], 'total_hops': 0}),
            'http_analysis':cached.get('http_analysis', {}),
            'tech_stack':   cached.get('tech_stack', {}),
            'directories':  cached.get('directories', {}),
            'emails':       cached.get('emails', {}),
            'fingerprint':  cached.get('fingerprint', {}),
            'waf_info':     cached.get('waf_info', {}),
            'banners':      cached.get('banners', {}),
            'reverse_ip':   cached.get('reverse_ip', {}),
            'cvss':         cached.get('cvss', {}),
            'ai_solution':  cached.get('ai_solution', ''),
        }
    else:
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
            traceroute_result = {'error': 'Traceroute unavailable'}
        http_analysis = analyze_http_headers(domain)
        tech_stack = detect_technologies(domain)
        directories = enumerate_directories(domain)
        emails = harvest_emails(domain)
        fingerprint = fingerprint_website(domain)
        waf_info = detect_waf(domain)
        banners = grab_banners(domain)
        reverse_ip_result = reverse_ip_lookup(domain)
        scan_data = {
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'ssl': ssl_result, 'dns': dns_result, 'whois': whois_result,
            'headers': headers_result, 'phishing': phishing_result,
            'subdomains': subdomains, 'ports': ports_result,
            'ip_info': ip_info, 'cdn_info': cdn_info,
            'traceroute': traceroute_result, 'http_analysis': http_analysis,
            'tech_stack': tech_stack, 'directories': directories,
            'emails': emails, 'fingerprint': fingerprint,
            'waf_info': waf_info, 'banners': banners,
            'reverse_ip': reverse_ip_result, 'ai_solution': '',
            'cvss': calculate_cvss_score({
                'domain': domain, 'ssl': ssl_result,
                'headers': headers_result, 'phishing': phishing_result,
                'ports': ports_result, 'dns': dns_result
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

@app.route('/ai_solutions', methods=['POST'])
def ai_solutions():
    """Stream AI-generated security solutions using Groq LLaMA 3"""
    data = request.get_json()
    domain = data.get('domain', '')
    scan_summary = data.get('scan_summary', {})

    api_key = os.getenv('GROQ_API_KEY', '')
    if not api_key or api_key == 'your_groq_api_key_here':
        return jsonify({'error': 'GROQ_API_KEY not configured in .env file'}), 400

    # Build a concise prompt from scan data
    findings = []
    if scan_summary.get('ssl_invalid'):       findings.append('SSL certificate is invalid or missing')
    if scan_summary.get('missing_headers'):   findings.extend([f'Missing security header: {h}' for h in scan_summary['missing_headers']])
    if scan_summary.get('open_ports'):        findings.extend([f'Open port: {p}' for p in scan_summary['open_ports']])
    if scan_summary.get('phishing_score', 0) > 40: findings.append(f"High phishing risk score: {scan_summary['phishing_score']}/100")
    if scan_summary.get('no_waf'):            findings.append('No Web Application Firewall detected')
    if scan_summary.get('vulnerabilities'):   findings.extend(scan_summary['vulnerabilities'])
    if scan_summary.get('cvss_score', 0) > 5: findings.append(f"CVSS risk score: {scan_summary['cvss_score']}/10 ({scan_summary.get('cvss_severity','')})")
    if scan_summary.get('exposed_paths'):     findings.extend([f'Exposed path: {p}' for p in scan_summary['exposed_paths'][:5]])

    if not findings:
        findings = ['No critical issues detected']

    prompt = f"""You are a senior cybersecurity expert. Analyze the following security scan results for domain: {domain}

FINDINGS:
{chr(10).join(f'- {f}' for f in findings)}

Provide a structured security remediation report with:
1. A brief overall risk summary (2-3 sentences)
2. For each finding, provide:
   - Issue title
   - Severity (Critical/High/Medium/Low)
   - Clear explanation of the risk
   - Step-by-step fix with specific commands where applicable
   - Prevention tip

Format your response in clean markdown. Be specific, technical, and actionable. Focus on practical fixes a developer or sysadmin can implement immediately."""

    def generate():
        try:
            import httpx
            http_client = httpx.Client()
            client = Groq(api_key=api_key, http_client=http_client)
            stream = client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[
                    {'role': 'system', 'content': 'You are a senior cybersecurity expert providing detailed, actionable security remediation advice. Always be specific and technical.'},
                    {'role': 'user', 'content': prompt}
                ],
                stream=True,
                max_tokens=2048,
                temperature=0.3,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield f"data: {json.dumps({'text': delta})}\n\n"
            yield "data: {\"done\": true}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
