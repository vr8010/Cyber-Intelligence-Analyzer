"""
Report Generator Module - Generate reports in XML, JSON, PDF formats
Includes all 20 modules data
"""
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from io import BytesIO

def generate_json_report(scan_data):
    """Generate comprehensive JSON report with all modules"""
    report = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'report_type': 'Comprehensive Security Scan Report',
            'version': '3.0',
            'total_modules': 20
        },
        'scan_data': scan_data
    }
    return json.dumps(report, indent=2, default=str)

def generate_xml_report(scan_data):
    """Generate comprehensive XML report with all modules"""
    root = ET.Element('ComprehensiveSecurityScanReport')
    
    # Metadata
    metadata = ET.SubElement(root, 'Metadata')
    ET.SubElement(metadata, 'GeneratedAt').text = datetime.now().isoformat()
    ET.SubElement(metadata, 'ReportType').text = 'Comprehensive Security Scan Report'
    ET.SubElement(metadata, 'Version').text = '3.0'
    ET.SubElement(metadata, 'TotalModules').text = '20'
    
    # Domain Info
    domain_elem = ET.SubElement(root, 'Domain')
    ET.SubElement(domain_elem, 'Name').text = scan_data.get('domain', 'N/A')
    
    # CVSS Score
    if scan_data.get('cvss'):
        cvss_elem = ET.SubElement(root, 'CVSSScore')
        cvss = scan_data['cvss']
        ET.SubElement(cvss_elem, 'Score').text = str(cvss.get('score', 0))
        ET.SubElement(cvss_elem, 'Severity').text = cvss.get('severity', 'N/A')
        
        findings_elem = ET.SubElement(cvss_elem, 'Findings')
        for finding in cvss.get('findings', []):
            ET.SubElement(findings_elem, 'Finding').text = str(finding)
    
    # SSL Info
    if scan_data.get('ssl'):
        ssl_elem = ET.SubElement(root, 'SSL')
        ssl = scan_data['ssl']
        ET.SubElement(ssl_elem, 'Valid').text = str(ssl.get('valid', False))
        ET.SubElement(ssl_elem, 'Issuer').text = str(ssl.get('issuer', 'N/A'))
        ET.SubElement(ssl_elem, 'ExpiryDate').text = str(ssl.get('expiry_date', 'N/A'))
    
    # DNS Records
    if scan_data.get('dns'):
        dns_elem = ET.SubElement(root, 'DNS')
        dns = scan_data['dns']
        if not dns.get('error'):
            ET.SubElement(dns_elem, 'IP').text = str(dns.get('ip', 'N/A'))
    
    # WHOIS
    if scan_data.get('whois'):
        whois_elem = ET.SubElement(root, 'WHOIS')
        whois = scan_data['whois']
        if not whois.get('error'):
            ET.SubElement(whois_elem, 'Registrar').text = str(whois.get('registrar', 'N/A'))
            ET.SubElement(whois_elem, 'CreationDate').text = str(whois.get('creation_date', 'N/A'))
    
    # Security Headers
    if scan_data.get('headers'):
        headers_elem = ET.SubElement(root, 'SecurityHeaders')
        for key, value in scan_data['headers'].items():
            if key != 'error':
                header = ET.SubElement(headers_elem, 'Header')
                ET.SubElement(header, 'Name').text = str(key)
                ET.SubElement(header, 'Value').text = str(value)
    
    # Phishing Detection
    if scan_data.get('phishing'):
        phishing_elem = ET.SubElement(root, 'PhishingDetection')
        phishing = scan_data['phishing']
        ET.SubElement(phishing_elem, 'Score').text = str(phishing.get('score', 0))
        ET.SubElement(phishing_elem, 'RiskLevel').text = str(phishing.get('risk_level', 'N/A'))
    
    # Subdomains
    if scan_data.get('subdomains'):
        subdomains_elem = ET.SubElement(root, 'Subdomains')
        ET.SubElement(subdomains_elem, 'Total').text = str(len(scan_data['subdomains']))
    
    # Open Ports
    if scan_data.get('ports'):
        ports_elem = ET.SubElement(root, 'OpenPorts')
        ports = scan_data['ports']
        ET.SubElement(ports_elem, 'Total').text = str(ports.get('total_open', 0))
        for port in ports.get('open_ports', [])[:10]:
            port_elem = ET.SubElement(ports_elem, 'Port')
            ET.SubElement(port_elem, 'Number').text = str(port.get('port'))
            ET.SubElement(port_elem, 'Service').text = str(port.get('service', 'Unknown'))
    
    # IP Geolocation
    if scan_data.get('ip_info'):
        ip_elem = ET.SubElement(root, 'IPGeolocation')
        ip_info = scan_data['ip_info']
        if not ip_info.get('error'):
            ET.SubElement(ip_elem, 'IP').text = str(ip_info.get('ip', 'N/A'))
            ET.SubElement(ip_elem, 'Country').text = str(ip_info.get('country', 'N/A'))
            ET.SubElement(ip_elem, 'City').text = str(ip_info.get('city', 'N/A'))
            ET.SubElement(ip_elem, 'ISP').text = str(ip_info.get('isp', 'N/A'))
    
    # CDN Detection
    if scan_data.get('cdn_info'):
        cdn_elem = ET.SubElement(root, 'CDN')
        cdn = scan_data['cdn_info']
        ET.SubElement(cdn_elem, 'Detected').text = str(cdn.get('cdn_detected', False))
        if cdn.get('provider'):
            ET.SubElement(cdn_elem, 'Provider').text = str(cdn['provider'])
    
    # HTTP Analysis
    if scan_data.get('http_analysis'):
        http_elem = ET.SubElement(root, 'HTTPAnalysis')
        http = scan_data['http_analysis']
        if not http.get('error'):
            ET.SubElement(http_elem, 'SecurityScore').text = str(http.get('security_percentage', 0))
            ET.SubElement(http_elem, 'Rating').text = str(http.get('security_rating', 'N/A'))
    
    # Technology Stack
    if scan_data.get('tech_stack'):
        tech_elem = ET.SubElement(root, 'TechnologyStack')
        tech = scan_data['tech_stack']
        ET.SubElement(tech_elem, 'TotalDetected').text = str(tech.get('total_detected', 0))
    
    # Directory Enumeration
    if scan_data.get('directories'):
        dir_elem = ET.SubElement(root, 'DirectoryEnumeration')
        dirs = scan_data['directories']
        ET.SubElement(dir_elem, 'TotalFound').text = str(dirs.get('total_found', 0))
    
    # Email Harvesting
    if scan_data.get('emails'):
        email_elem = ET.SubElement(root, 'EmailHarvesting')
        emails = scan_data['emails']
        ET.SubElement(email_elem, 'TotalFound').text = str(emails.get('total_found', 0))
    
    # WAF Detection
    if scan_data.get('waf_info'):
        waf_elem = ET.SubElement(root, 'WAF')
        waf = scan_data['waf_info']
        ET.SubElement(waf_elem, 'Detected').text = str(waf.get('waf_detected', False))
        if waf.get('waf_name'):
            ET.SubElement(waf_elem, 'Name').text = str(waf['waf_name'])
            ET.SubElement(waf_elem, 'Confidence').text = str(waf.get('confidence', 'N/A'))
    
    # Reverse IP
    if scan_data.get('reverse_ip'):
        rev_elem = ET.SubElement(root, 'ReverseIP')
        rev = scan_data['reverse_ip']
        ET.SubElement(rev_elem, 'TotalDomains').text = str(rev.get('total_domains', 0))
    
    # Pretty print XML
    xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent='  ')
    return xml_str

def generate_pdf_report(scan_data):
    """
    Generate comprehensive PDF report with all 20 modules
    Note: Requires reportlab library
    """
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=20,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph('Comprehensive Security Scan Report', title_style))
        story.append(Paragraph('20 Module Analysis', styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        story.append(Paragraph(f'<b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', styles['Normal']))
        story.append(Paragraph(f'<b>Domain:</b> {scan_data.get("domain", "N/A")}', styles['Normal']))
        story.append(Paragraph(f'<b>Report Version:</b> 3.0', styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph('Executive Summary', heading_style))
        
        # CVSS Score (Most Important)
        if scan_data.get('cvss'):
            cvss = scan_data['cvss']
            story.append(Paragraph('<b>Overall Risk Assessment</b>', styles['Heading3']))
            
            score_data = [
                ['CVSS Score', 'Severity', 'Total Findings'],
                [str(cvss['score']), cvss['severity'], str(cvss['total_findings'])]
            ]
            score_table = Table(score_data, colWidths=[2*inch, 2*inch, 2*inch])
            score_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(score_table)
            story.append(Spacer(1, 0.2*inch))
            
            if cvss.get('findings'):
                story.append(Paragraph('<b>Critical Findings:</b>', styles['Normal']))
                for finding in cvss['findings'][:5]:
                    story.append(Paragraph(f'• {finding}', styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
        
        # Module 1: SSL/TLS Certificate
        story.append(Paragraph('1. SSL/TLS Certificate Analysis', heading_style))
        if scan_data.get('ssl'):
            ssl = scan_data['ssl']
            if not ssl.get('error'):
                story.append(Paragraph(f'<b>Valid:</b> {"✓ Yes" if ssl.get("valid") else "✗ No"}', styles['Normal']))
                story.append(Paragraph(f'<b>Issuer:</b> {ssl.get("issuer", "N/A")}', styles['Normal']))
                story.append(Paragraph(f'<b>Expiry:</b> {ssl.get("expiry_date", "N/A")}', styles['Normal']))
            else:
                story.append(Paragraph(f'Error: {ssl.get("error")}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 2: DNS Records
        story.append(Paragraph('2. DNS Records', heading_style))
        if scan_data.get('dns'):
            dns = scan_data['dns']
            if not dns.get('error'):
                story.append(Paragraph(f'<b>IP Address:</b> {dns.get("ip", "N/A")}', styles['Normal']))
                if dns.get('A'):
                    story.append(Paragraph(f'<b>A Records:</b> {len(dns["A"])} found', styles['Normal']))
                if dns.get('MX'):
                    story.append(Paragraph(f'<b>MX Records:</b> {len(dns["MX"])} found', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 3: WHOIS Information
        story.append(Paragraph('3. WHOIS Information', heading_style))
        if scan_data.get('whois'):
            whois = scan_data['whois']
            if not whois.get('error'):
                story.append(Paragraph(f'<b>Registrar:</b> {whois.get("registrar", "N/A")}', styles['Normal']))
                story.append(Paragraph(f'<b>Creation Date:</b> {whois.get("creation_date", "N/A")}', styles['Normal']))
                story.append(Paragraph(f'<b>Domain Age:</b> {whois.get("age_days", "N/A")} days', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 4: Security Headers
        story.append(Paragraph('4. Security Headers', heading_style))
        if scan_data.get('headers'):
            headers = scan_data['headers']
            if not headers.get('error'):
                story.append(Paragraph(f'<b>Headers Found:</b> {len(headers)} security headers', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 5: Phishing Detection
        story.append(Paragraph('5. Phishing Detection', heading_style))
        if scan_data.get('phishing'):
            phishing = scan_data['phishing']
            story.append(Paragraph(f'<b>Risk Score:</b> {phishing.get("score", 0)}/100', styles['Normal']))
            story.append(Paragraph(f'<b>Risk Level:</b> {phishing.get("risk_level", "N/A")}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 6: Subdomains
        story.append(Paragraph('6. Subdomain Enumeration', heading_style))
        if scan_data.get('subdomains'):
            story.append(Paragraph(f'<b>Subdomains Found:</b> {len(scan_data["subdomains"])}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Page Break
        story.append(PageBreak())
        
        # Module 7: Port Scanner
        story.append(Paragraph('7. Open Ports', heading_style))
        if scan_data.get('ports') and scan_data['ports'].get('open_ports'):
            ports = scan_data['ports']
            story.append(Paragraph(f'<b>Total Open Ports:</b> {ports.get("total_open", 0)}', styles['Normal']))
            
            port_data = [['Port', 'Service', 'State']]
            for port in ports['open_ports'][:10]:
                port_data.append([
                    str(port.get('port')),
                    port.get('service', 'Unknown'),
                    'Open'
                ])
            
            if port_data:
                port_table = Table(port_data, colWidths=[1.5*inch, 2.5*inch, 1.5*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(port_table)
        story.append(Spacer(1, 0.1*inch))
        
        # Module 8: IP Geolocation
        story.append(Paragraph('8. IP Geolocation', heading_style))
        if scan_data.get('ip_info') and not scan_data['ip_info'].get('error'):
            ip_info = scan_data['ip_info']
            story.append(Paragraph(f'<b>IP:</b> {ip_info.get("ip", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>Location:</b> {ip_info.get("city", "N/A")}, {ip_info.get("country", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>ISP:</b> {ip_info.get("isp", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>ASN:</b> {ip_info.get("asn", "N/A")}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 9: CDN Detection
        story.append(Paragraph('9. CDN Detection', heading_style))
        if scan_data.get('cdn_info'):
            cdn = scan_data['cdn_info']
            story.append(Paragraph(f'<b>CDN Detected:</b> {"Yes" if cdn.get("cdn_detected") else "No"}', styles['Normal']))
            if cdn.get('provider'):
                story.append(Paragraph(f'<b>Provider:</b> {cdn["provider"].upper()}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 10: Network Traceroute
        story.append(Paragraph('10. Network Traceroute', heading_style))
        if scan_data.get('traceroute'):
            trace = scan_data['traceroute']
            if not trace.get('error'):
                story.append(Paragraph(f'<b>Total Hops:</b> {trace.get("total_hops", 0)}', styles['Normal']))
            else:
                story.append(Paragraph(f'Status: {trace.get("error")}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 11: HTTP Header Analysis
        story.append(Paragraph('11. HTTP Header Analysis', heading_style))
        if scan_data.get('http_analysis'):
            http = scan_data['http_analysis']
            if not http.get('error'):
                story.append(Paragraph(f'<b>Security Score:</b> {http.get("security_percentage", 0)}%', styles['Normal']))
                story.append(Paragraph(f'<b>Rating:</b> {http.get("security_rating", "N/A")}', styles['Normal']))
                if http.get('vulnerabilities'):
                    story.append(Paragraph(f'<b>Vulnerabilities:</b> {len(http["vulnerabilities"])} found', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 12: Technology Detection
        story.append(Paragraph('12. Technology Stack', heading_style))
        if scan_data.get('tech_stack'):
            tech = scan_data['tech_stack']
            story.append(Paragraph(f'<b>Technologies Detected:</b> {tech.get("total_detected", 0)}', styles['Normal']))
            if tech.get('technologies'):
                for category, techs in list(tech['technologies'].items())[:3]:
                    story.append(Paragraph(f'<b>{category.title()}:</b> {", ".join(techs[:5])}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 13: Directory Enumeration
        story.append(Paragraph('13. Directory Enumeration', heading_style))
        if scan_data.get('directories'):
            dirs = scan_data['directories']
            story.append(Paragraph(f'<b>Paths Found:</b> {dirs.get("total_found", 0)} / {dirs.get("total_checked", 0)}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 14: Email Harvesting
        story.append(Paragraph('14. Email Harvesting', heading_style))
        if scan_data.get('emails'):
            emails = scan_data['emails']
            story.append(Paragraph(f'<b>Emails Found:</b> {emails.get("total_found", 0)}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 15: Website Fingerprinting
        story.append(Paragraph('15. Website Fingerprinting', heading_style))
        if scan_data.get('fingerprint'):
            fp = scan_data['fingerprint']
            if fp.get('signatures'):
                story.append(Paragraph(f'<b>Signatures:</b> {", ".join(fp["signatures"])}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 16: WAF Detection
        story.append(Paragraph('16. WAF Detection', heading_style))
        if scan_data.get('waf_info'):
            waf = scan_data['waf_info']
            story.append(Paragraph(f'<b>WAF Detected:</b> {"Yes" if waf.get("waf_detected") else "No"}', styles['Normal']))
            if waf.get('waf_name'):
                story.append(Paragraph(f'<b>WAF Name:</b> {waf["waf_name"]}', styles['Normal']))
                story.append(Paragraph(f'<b>Confidence:</b> {waf.get("confidence", "N/A")}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 17: Server Banners
        story.append(Paragraph('17. Server Banners', heading_style))
        if scan_data.get('banners'):
            banners = scan_data['banners']
            if banners.get('server_info'):
                story.append(Paragraph(f'<b>Server:</b> {banners["server_info"].get("name", "N/A")}', styles['Normal']))
            if banners.get('service_banners'):
                story.append(Paragraph(f'<b>Services Found:</b> {len(banners["service_banners"])}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Module 18: Reverse IP Lookup
        story.append(Paragraph('18. Reverse IP Lookup', heading_style))
        if scan_data.get('reverse_ip'):
            rev = scan_data['reverse_ip']
            story.append(Paragraph(f'<b>Domains on Same IP:</b> {rev.get("total_domains", 0)}', styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Footer
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph('---', styles['Normal']))
        story.append(Paragraph('<b>Report Generated by Cyber Intelligence Analyzer v3.0</b>', styles['Normal']))
        story.append(Paragraph('20 Module Comprehensive Security Analysis', styles['Normal']))
        
        # Build PDF
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
        
    except ImportError:
        return None  # reportlab not installed
    """
    Generate PDF report
    Note: Requires reportlab library
    """
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
        )
        story.append(Paragraph('Security Scan Report', title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Metadata
        story.append(Paragraph(f'<b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', styles['Normal']))
        story.append(Paragraph(f'<b>Domain:</b> {scan_data.get("domain", "N/A")}', styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # CVSS Score
        if scan_data.get('cvss'):
            cvss = scan_data['cvss']
            story.append(Paragraph('CVSS Risk Score', styles['Heading2']))
            
            score_color = colors.green
            if cvss['score'] >= 7.0:
                score_color = colors.red
            elif cvss['score'] >= 4.0:
                score_color = colors.orange
            
            score_data = [
                ['Score', 'Severity', 'Findings'],
                [str(cvss['score']), cvss['severity'], str(cvss['total_findings'])]
            ]
            score_table = Table(score_data)
            score_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(score_table)
            story.append(Spacer(1, 0.2*inch))
            
            if cvss.get('findings'):
                story.append(Paragraph('<b>Security Findings:</b>', styles['Normal']))
                for finding in cvss['findings']:
                    story.append(Paragraph(f'• {finding}', styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
        
        # SSL Information
        if scan_data.get('ssl'):
            story.append(Paragraph('SSL/TLS Certificate', styles['Heading2']))
            ssl = scan_data['ssl']
            story.append(Paragraph(f'<b>Valid:</b> {ssl.get("valid", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>Issuer:</b> {ssl.get("issuer", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>Expiry:</b> {ssl.get("expiry_date", "N/A")}', styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Open Ports
        if scan_data.get('ports') and scan_data['ports'].get('open_ports'):
            story.append(Paragraph('Open Ports', styles['Heading2']))
            port_data = [['Port', 'Service', 'State']]
            for port in scan_data['ports']['open_ports'][:10]:  # Limit to 10
                port_data.append([
                    str(port.get('port')),
                    port.get('service', 'Unknown'),
                    port.get('state', 'open')
                ])
            
            port_table = Table(port_data)
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
            story.append(Spacer(1, 0.2*inch))
        
        # IP Geolocation
        if scan_data.get('ip_info') and not scan_data['ip_info'].get('error'):
            story.append(Paragraph('IP Geolocation', styles['Heading2']))
            ip_info = scan_data['ip_info']
            story.append(Paragraph(f'<b>IP:</b> {ip_info.get("ip", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>Location:</b> {ip_info.get("city", "N/A")}, {ip_info.get("country", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>ISP:</b> {ip_info.get("isp", "N/A")}', styles['Normal']))
            story.append(Paragraph(f'<b>ASN:</b> {ip_info.get("asn", "N/A")}', styles['Normal']))
        
        # Build PDF
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
        
    except ImportError:
        return None  # reportlab not installed
