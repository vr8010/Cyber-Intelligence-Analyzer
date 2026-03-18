"""
Report Generator - CYBERSCAN.AI
Clean professional PDF - teal/navy theme
"""
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from io import BytesIO
import math
import re


def generate_json_report(scan_data):
    report = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'tool': 'CYBERSCAN.AI',
            'version': '1.0',
            'total_modules': 20
        },
        'scan_data': scan_data
    }
    return json.dumps(report, indent=2, default=str)


def generate_xml_report(scan_data):
    root = ET.Element('CyberScanReport')
    meta = ET.SubElement(root, 'Metadata')
    ET.SubElement(meta, 'GeneratedAt').text = datetime.now().isoformat()
    ET.SubElement(meta, 'Tool').text = 'CYBERSCAN.AI'
    ET.SubElement(meta, 'Domain').text = scan_data.get('domain', 'N/A')

    for section, data in scan_data.items():
        if isinstance(data, dict):
            sec = ET.SubElement(root, section.upper())
            for k, v in data.items():
                el = ET.SubElement(sec, str(k).replace(' ', '_'))
                el.text = str(v)

    return minidom.parseString(ET.tostring(root)).toprettyxml(indent='  ')


def generate_pdf_report(scan_data):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak,
                                        HRFlowable, KeepTogether)
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus.flowables import Flowable

        # ── Palette ──────────────────────────────────────────────
        TEAL      = colors.HexColor('#00B4CC')
        TEAL_DARK = colors.HexColor('#007A8C')
        TEAL_LITE = colors.HexColor('#E8F8FA')
        NAVY      = colors.HexColor('#0A1628')
        WHITE     = colors.white
        GREY_BG   = colors.HexColor('#F5F8FA')
        GREY_TXT  = colors.HexColor('#444444')
        ORANGE    = colors.HexColor('#FF6B35')
        RED       = colors.HexColor('#E53935')
        GREEN     = colors.HexColor('#00897B')
        AMBER     = colors.HexColor('#FFB300')
        LIGHT_LINE= colors.HexColor('#DDDDDD')

        PW = A4[0] - 2 * inch   # usable page width

        # ── Custom Flowables ─────────────────────────────────────
        class HexStrip(Flowable):
            """Row of small decorative hexagons"""
            def __init__(self, width=PW, n=20, col=TEAL, alpha=0.15, h=16):
                super().__init__()
                self.width = width
                self.n = n
                self.col = col
                self.alpha = alpha
                self.height = h

            def draw(self):
                c = self.canv
                s = self.width / (self.n * 1.85)
                x = s
                for _ in range(self.n):
                    c.setFillColor(self.col, alpha=self.alpha)
                    c.setStrokeColor(self.col, alpha=self.alpha * 1.4)
                    c.setLineWidth(0.4)
                    p = c.beginPath()
                    for i in range(6):
                        a = math.radians(60 * i - 30)
                        px, py = x + s * math.cos(a), self.height / 2 + s * math.sin(a)
                        if i == 0:
                            p.moveTo(px, py)
                        else:
                            p.lineTo(px, py)
                    p.close()
                    c.drawPath(p, fill=1, stroke=1)
                    x += s * 1.9

        class SectionHeader(Flowable):
            """Teal left-bar section title"""
            def __init__(self, text, width=PW):
                super().__init__()
                self.text = text
                self.width = width
                self.height = 24

            def draw(self):
                c = self.canv
                c.setFillColor(TEAL)
                c.rect(0, 2, 4, self.height - 2, fill=1, stroke=0)
                c.setFillColor(NAVY)
                c.setFont('Helvetica-Bold', 10)
                c.drawString(12, 7, self.text.upper())

        # ── Styles ───────────────────────────────────────────────
        styles = getSampleStyleSheet()

        def PS(name, **kw):
            return ParagraphStyle(name, parent=styles['Normal'], **kw)

        body   = PS('body',  fontSize=8,  textColor=GREY_TXT, leading=13)
        bold   = PS('bold',  fontSize=8,  textColor=NAVY, fontName='Helvetica-Bold', leading=13)
        small  = PS('small', fontSize=7,  textColor=colors.HexColor('#888888'), leading=11)
        red_p  = PS('redp',  fontSize=8,  textColor=RED, leading=13)
        center = PS('ctr',   fontSize=8,  textColor=GREY_TXT, alignment=TA_CENTER)
        h_ctr  = PS('hctr',  fontSize=9,  textColor=WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)
        footer = PS('ftr',   fontSize=7,  textColor=colors.HexColor('#AAAAAA'), alignment=TA_CENTER)

        # ── Table helpers ─────────────────────────────────────────
        def kv(rows, w1=1.7*inch, w2=PW-1.7*inch):
            data = [[Paragraph(f'<b>{k}</b>', bold), Paragraph(str(v)[:120], body)]
                    for k, v in rows]
            t = Table(data, colWidths=[w1, w2])
            t.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (0, -1), TEAL_LITE),
                ('ROWBACKGROUNDS',(0, 0), (-1,-1), [WHITE, GREY_BG]),
                ('GRID',          (0, 0), (-1,-1), 0.3, LIGHT_LINE),
                ('LEFTPADDING',   (0, 0), (-1,-1), 7),
                ('RIGHTPADDING',  (0, 0), (-1,-1), 7),
                ('TOPPADDING',    (0, 0), (-1,-1), 4),
                ('BOTTOMPADDING', (0, 0), (-1,-1), 4),
            ]))
            return t

        def tbl(cols, rows, widths=None):
            header = [Paragraph(f'<b>{c}</b>', h_ctr) for c in cols]
            data   = [header] + [[Paragraph(str(cell)[:80], body) for cell in r] for r in rows]
            t = Table(data, colWidths=widths)
            t.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, 0), TEAL),
                ('ROWBACKGROUNDS',(0, 1), (-1,-1), [WHITE, GREY_BG]),
                ('GRID',          (0, 0), (-1,-1), 0.3, LIGHT_LINE),
                ('LEFTPADDING',   (0, 0), (-1,-1), 7),
                ('TOPPADDING',    (0, 0), (-1,-1), 4),
                ('BOTTOMPADDING', (0, 0), (-1,-1), 4),
                ('FONTSIZE',      (0, 0), (-1,-1), 8),
            ]))
            return t

        def sp(n=0.12): return Spacer(1, n * inch)
        def hr(): return HRFlowable(width=PW, thickness=0.3, color=LIGHT_LINE)

        def badge_color(score):
            if score >= 9: return RED
            if score >= 7: return ORANGE
            if score >= 4: return AMBER
            return GREEN

        # ── Data ─────────────────────────────────────────────────
        domain    = scan_data.get('domain', 'N/A')
        now       = datetime.now().strftime('%Y-%m-%d  %H:%M UTC')
        cvss      = scan_data.get('cvss', {})
        score     = cvss.get('score', 0)
        severity  = cvss.get('severity', 'N/A')
        findings  = cvss.get('findings', [])
        bcol      = badge_color(score)

        # ── Document ─────────────────────────────────────────────
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=inch, rightMargin=inch,
                                topMargin=0.7*inch, bottomMargin=0.7*inch)
        S = []   # story

        # ════════════════════════════════════════════════════════
        # COVER PAGE
        # ════════════════════════════════════════════════════════
        # Teal accent line at top
        S.append(HRFlowable(width=PW, thickness=4, color=TEAL, spaceAfter=14))

        # Brand + title
        S.append(Paragraph('<b>CYBERSCAN.AI</b>',
                           PS('br', fontSize=28, textColor=TEAL,
                              fontName='Helvetica-Bold', leading=32)))
        S.append(Paragraph('Security Intelligence Report',
                           PS('st', fontSize=14, textColor=NAVY, leading=18)))
        S.append(sp(0.2))
        S.append(HexStrip(n=24, alpha=0.2))
        S.append(sp(0.25))

        # Cover info table
        cover_data = [
            [Paragraph('<b>TARGET DOMAIN</b>', bold),  Paragraph(domain, body)],
            [Paragraph('<b>SCAN DATE</b>',     bold),  Paragraph(now, body)],
            [Paragraph('<b>REPORT VERSION</b>',bold),  Paragraph('1.0', body)],
            [Paragraph('<b>MODULES RUN</b>',   bold),  Paragraph('20', body)],
        ]
        ct = Table(cover_data, colWidths=[1.8*inch, PW-1.8*inch])
        ct.setStyle(TableStyle([
            ('BACKGROUND',   (0,0),(0,-1), TEAL_LITE),
            ('GRID',         (0,0),(-1,-1), 0.3, LIGHT_LINE),
            ('LEFTPADDING',  (0,0),(-1,-1), 8),
            ('TOPPADDING',   (0,0),(-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 6),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[WHITE, GREY_BG]),
        ]))
        S.append(ct)
        S.append(sp(0.3))

        # CVSS badge
        badge = Table(
            [[Paragraph(f'<b>CVSS SCORE</b>', PS('bl', fontSize=9, textColor=WHITE,
                        fontName='Helvetica-Bold', alignment=TA_CENTER)),
              Paragraph(f'<b>{score}</b>', PS('bs', fontSize=26, textColor=WHITE,
                        fontName='Helvetica-Bold', alignment=TA_CENTER)),
              Paragraph(f'<b>{severity.upper()}</b>', PS('bsv', fontSize=13, textColor=WHITE,
                        fontName='Helvetica-Bold', alignment=TA_CENTER))]],
            colWidths=[1.8*inch, 1.2*inch, 3.5*inch], rowHeights=[55]
        )
        badge.setStyle(TableStyle([
            ('BACKGROUND',   (0,0),(-1,-1), bcol),
            ('VALIGN',       (0,0),(-1,-1), 'MIDDLE'),
            ('LEFTPADDING',  (0,0),(-1,-1), 10),
            ('RIGHTPADDING', (0,0),(-1,-1), 10),
        ]))
        S.append(badge)
        S.append(sp(0.3))
        S.append(HexStrip(n=24, alpha=0.15))
        S.append(sp(0.3))

        # Findings on cover
        if findings:
            S.append(Paragraph('<b>Key Findings</b>',
                               PS('kf', fontSize=10, textColor=NAVY,
                                  fontName='Helvetica-Bold')))
            S.append(sp(0.08))
            for f in findings[:6]:
                S.append(Paragraph(f'▸  {f}', red_p))
        S.append(PageBreak())

        # ════════════════════════════════════════════════════════
        # HELPER: section block
        # ════════════════════════════════════════════════════════
        def section(title, content_items):
            block = [SectionHeader(title), sp(0.1)] + content_items + [sp(0.18)]
            S.extend(block)

        # ════════════════════════════════════════════════════════
        # PAGE 2 — SECURITY
        # ════════════════════════════════════════════════════════
        ssl = scan_data.get('ssl', {})
        section('1. SSL / TLS Certificate', [
            kv([
                ('Status',  '✓ Valid' if ssl.get('valid') else '✗ Invalid'),
                ('Issuer',  ssl.get('issuer', 'N/A')),
                ('Expiry',  str(ssl.get('expiry', 'N/A'))),
                ('Subject', ssl.get('subject', 'N/A')),
                ('Error',   ssl.get('error', '—')),
            ])
        ])

        hdrs = scan_data.get('headers', {})
        hdr_rows = [(k, str(v)[:100]) for k, v in hdrs.items() if k != 'error']
        section('2. Security Headers', [kv(hdr_rows)] if hdr_rows else
                [Paragraph('No header data available.', body)])

        ph = scan_data.get('phishing', {})
        section('3. Phishing Detection', [
            kv([
                ('Risk Score', f'{ph.get("score", 0)} / 100'),
                ('Risk Level', ph.get('risk_level', 'N/A')),
                ('Indicators', ', '.join(ph.get('indicators', [])) or 'None'),
            ])
        ])

        waf = scan_data.get('waf_info', {})
        section('4. WAF Detection', [
            kv([
                ('WAF Detected', 'Yes ✓' if waf.get('waf_detected') else 'No ✗'),
                ('WAF Name',     waf.get('waf_name', 'N/A')),
                ('Confidence',   waf.get('confidence', 'N/A')),
            ])
        ])

        http = scan_data.get('http_analysis', {})
        http_items = [kv([
            ('Security Score',  f'{http.get("security_percentage", 0)}%'),
            ('Rating',          http.get('security_rating', 'N/A')),
            ('Response Time',   f'{http.get("response_time_ms", "N/A")} ms'),
            ('Vulnerabilities', str(len(http.get('vulnerabilities', [])))),
        ])]
        for v in http.get('vulnerabilities', [])[:5]:
            http_items.append(Paragraph(f'▸  {v}', red_p))
        section('5. HTTP Header Analysis', http_items)

        S.append(PageBreak())

        # ════════════════════════════════════════════════════════
        # PAGE 3 — NETWORK
        # ════════════════════════════════════════════════════════
        dns = scan_data.get('dns', {})
        dns_rows = [('IP Address', dns.get('ip', 'N/A'))]
        for rt in ['A', 'MX', 'TXT', 'NS']:
            if dns.get(rt):
                dns_rows.append((f'{rt} Records', ', '.join(str(r) for r in dns[rt][:4])))
        section('6. DNS Information', [kv(dns_rows)])

        ports = scan_data.get('ports', {})
        port_items = [Paragraph(f'Total Open Ports: <b>{ports.get("total_open", 0)}</b>', body), sp(0.08)]
        if ports.get('open_ports'):
            port_items.append(tbl(
                ['Port', 'Service', 'State'],
                [(p['port'], p.get('service', '?'), p.get('state', 'open'))
                 for p in ports['open_ports'][:15]],
                widths=[0.8*inch, 4*inch, 1.7*inch]
            ))
        section('7. Open Ports', port_items)

        ip = scan_data.get('ip_info', {})
        section('8. IP Geolocation', [
            kv([
                ('IP',          ip.get('ip', 'N/A')),
                ('Location',    f'{ip.get("city","?")} · {ip.get("region","?")} · {ip.get("country","?")}'),
                ('Coordinates', f'{ip.get("lat","?")} , {ip.get("lon","?")}'),
                ('ISP',         ip.get('isp', 'N/A')),
                ('ASN',         ip.get('asn', 'N/A')),
                ('Timezone',    ip.get('timezone', 'N/A')),
            ])
        ])

        cdn = scan_data.get('cdn_info', {})
        section('9. CDN Detection', [
            kv([
                ('CDN Detected', 'Yes ✓' if cdn.get('cdn_detected') else 'No ✗'),
                ('Provider',     str(cdn.get('provider', 'N/A')).upper()),
                ('CNAME',        cdn.get('cname', 'N/A')),
            ])
        ])

        trace = scan_data.get('traceroute', {})
        trace_items = []
        if trace.get('hops'):
            trace_items.append(kv([
                ('Total Hops', str(trace.get('total_hops', 0))),
                ('Target IP',  trace.get('ip', 'N/A')),
            ]))
            trace_items.append(sp(0.08))
            trace_items.append(tbl(
                ['Hop', 'IP Address'],
                [(h['hop'], h['ip']) for h in trace['hops'][:12]],
                widths=[0.8*inch, PW-0.8*inch]
            ))
        else:
            trace_items.append(Paragraph(str(trace.get('error', 'No data')), small))
        section('10. Network Traceroute', trace_items)

        S.append(PageBreak())

        # ════════════════════════════════════════════════════════
        # PAGE 4 — RECON & TECH
        # ════════════════════════════════════════════════════════
        whois = scan_data.get('whois', {})
        section('11. WHOIS Information', [
            kv([
                ('Domain',      whois.get('domain_name', 'N/A')),
                ('Registrar',   whois.get('registrar', 'N/A')),
                ('Created',     str(whois.get('creation_date', 'N/A'))),
                ('Expires',     str(whois.get('expiration_date', 'N/A'))),
                ('Domain Age',  f'{whois.get("age_days", "N/A")} days'),
            ])
        ])

        tech = scan_data.get('tech_stack', {})
        tech_items = [Paragraph(f'Total Detected: <b>{tech.get("total_detected", 0)}</b>', body), sp(0.08)]
        if tech.get('technologies'):
            tech_items.append(kv(
                [(cat.title(), ', '.join(items[:6]))
                 for cat, items in list(tech['technologies'].items())[:8]]
            ))
        section('12. Technology Stack', tech_items)

        subs = scan_data.get('subdomains', [])
        section('13. Subdomain Enumeration', [
            Paragraph(f'Found: <b>{len(subs)}</b> subdomains', body),
            sp(0.06),
            Paragraph(', '.join(subs[:20]) or 'None found', small),
        ])

        dirs = scan_data.get('directories', {})
        dir_items = [kv([
            ('Paths Checked', str(dirs.get('total_checked', 0))),
            ('Paths Found',   str(dirs.get('total_found', 0))),
        ])]
        acc = (dirs.get('categories') or {}).get('accessible', [])
        if acc:
            dir_items.append(sp(0.06))
            dir_items.append(Paragraph('<b>Accessible Paths:</b>', bold))
            for p in acc[:8]:
                dir_items.append(Paragraph(f'  {p.get("path","")}  [{p.get("status","")}]', small))
        section('14. Directory Enumeration', dir_items)

        emails = scan_data.get('emails', {})
        email_items = [Paragraph(f'Total Found: <b>{emails.get("total_found", 0)}</b>', body)]
        for e in (emails.get('emails') or [])[:10]:
            email_items.append(Paragraph(f'  {e}', small))
        section('15. Email Harvesting', email_items)

        S.append(PageBreak())

        # ════════════════════════════════════════════════════════
        # PAGE 5 — FINGERPRINT + BANNERS + REVERSE IP
        # ════════════════════════════════════════════════════════
        fp = scan_data.get('fingerprint', {})
        fp_items = []
        if fp.get('signatures'):
            fp_items.append(Paragraph('Signatures: ' + ', '.join(fp['signatures']), body))
            fp_items.append(sp(0.06))
        if fp.get('fingerprints'):
            fp_items.append(kv([(k, str(v)[:80]) for k, v in list(fp['fingerprints'].items())[:6]]))
        if not fp_items:
            fp_items.append(Paragraph('No fingerprint data.', small))
        section('16. Website Fingerprinting', fp_items)

        banners = scan_data.get('banners', {})
        ban_items = []
        if banners.get('ip'):
            ban_items.append(Paragraph(f'IP: <b>{banners["ip"]}</b>', body))
            ban_items.append(sp(0.06))
        if banners.get('server_info'):
            ban_items.append(kv([(k.title(), str(v)[:80]) for k, v in list(banners['server_info'].items())[:5]]))
        if banners.get('http_banner'):
            ban_items.append(sp(0.06))
            ban_items.append(Paragraph('<b>HTTP Headers:</b>', bold))
            for k, v in list(banners['http_banner'].items())[:6]:
                ban_items.append(Paragraph(f'  {k}: {str(v)[:80]}', small))
        if not ban_items:
            ban_items.append(Paragraph('No banner data.', small))
        section('17. Server Banners', ban_items)

        rev = scan_data.get('reverse_ip', {})
        rev_items = [kv([
            ('IP',               rev.get('ip', 'N/A')),
            ('Co-hosted Domains', str(rev.get('total_domains', 0))),
        ])]
        if rev.get('domains_on_ip'):
            rev_items.append(sp(0.06))
            rev_items.append(Paragraph(', '.join(rev['domains_on_ip'][:15]), small))
        section('18. Reverse IP Lookup', rev_items)

        # ════════════════════════════════════════════════════════
        # AI SOLUTIONS PAGE
        # ════════════════════════════════════════════════════════
        ai_text = scan_data.get('ai_solution', '').strip()
        if ai_text:
            S.append(PageBreak())
            S.append(HRFlowable(width=PW, thickness=3, color=TEAL, spaceAfter=10))
            S.append(Paragraph('<b>AI-Powered Security Remediation</b>',
                               PS('ait', fontSize=16, textColor=TEAL,
                                  fontName='Helvetica-Bold', leading=20)))
            S.append(Paragraph('Generated by CYBERSCAN.AI · Groq LLaMA 3',
                               PS('ais', fontSize=8, textColor=colors.HexColor('#888888'),
                                  leading=12)))
            S.append(sp(0.2))

            # Parse markdown-like text into paragraphs
            ai_style     = PS('ai_body', fontSize=8, textColor=GREY_TXT, leading=13)
            ai_h2        = PS('ai_h2',   fontSize=11, textColor=NAVY,
                              fontName='Helvetica-Bold', leading=16, spaceBefore=10)
            ai_h3        = PS('ai_h3',   fontSize=9,  textColor=TEAL_DARK,
                              fontName='Helvetica-Bold', leading=14, spaceBefore=6)
            ai_bullet    = PS('ai_bul',  fontSize=8,  textColor=GREY_TXT,
                              leading=13, leftIndent=12)
            ai_code      = PS('ai_code', fontSize=7,  textColor=colors.HexColor('#CC4400'),
                              fontName='Courier', leading=11,
                              backColor=colors.HexColor('#FFF8F5'), leftIndent=10)
            ai_sev_crit  = PS('sc', fontSize=8, textColor=RED,  fontName='Helvetica-Bold', leading=13)
            ai_sev_high  = PS('sh', fontSize=8, textColor=ORANGE, fontName='Helvetica-Bold', leading=13)
            ai_sev_med   = PS('sm', fontSize=8, textColor=AMBER,  fontName='Helvetica-Bold', leading=13)

            for line in ai_text.split('\n'):
                stripped = line.strip()
                if not stripped:
                    S.append(sp(0.04))
                    continue
                # Strip markdown symbols cleanly
                if stripped.startswith('### '):
                    S.append(Paragraph(stripped[4:], ai_h3))
                elif stripped.startswith('## '):
                    S.append(SectionHeader(stripped[3:]))
                    S.append(sp(0.06))
                elif stripped.startswith('# '):
                    S.append(Paragraph(stripped[2:], ai_h2))
                elif stripped.startswith('- ') or stripped.startswith('* '):
                    clean = re.sub(r'\*\*(.+?)\*\*', r'\1', stripped[2:])
                    clean = re.sub(r'\*(.+?)\*', r'\1', clean)
                    S.append(Paragraph('▸  ' + clean, ai_bullet))
                elif stripped.startswith('```') or stripped.startswith('`'):
                    clean = stripped.strip('`').strip()
                    if clean:
                        S.append(Paragraph(clean, ai_code))
                elif stripped.startswith('---') or stripped.startswith('==='):
                    S.append(HRFlowable(width=PW, thickness=0.3, color=LIGHT_LINE))
                else:
                    # Remove **bold**, *italic*, `code` markers
                    clean = re.sub(r'\*\*(.+?)\*\*', r'\1', stripped)
                    clean = re.sub(r'\*(.+?)\*',     r'\1', clean)
                    clean = re.sub(r'`(.+?)`',        r'\1', clean)
                    clean = re.sub(r'^#+\s*',          '',   clean)
                    if not clean:
                        continue
                    # Pick style by content
                    low = clean.lower()
                    if any(w in low for w in ['critical', 'severity: critical']):
                        S.append(Paragraph(clean, ai_sev_crit))
                    elif any(w in low for w in ['high', 'severity: high']):
                        S.append(Paragraph(clean, ai_sev_high))
                    elif any(w in low for w in ['medium', 'severity: medium']):
                        S.append(Paragraph(clean, ai_sev_med))
                    else:
                        S.append(Paragraph(clean, ai_style))

        # ════════════════════════════════════════════════════════
        # FOOTER
        # ════════════════════════════════════════════════════════
        S.append(HexStrip(n=24, alpha=0.18))
        S.append(sp(0.1))
        foot = Table([[
            Paragraph('<b>CYBERSCAN.AI  v1.0</b>',
                      PS('fl', fontSize=8, textColor=TEAL, fontName='Helvetica-Bold')),
            Paragraph(f'Generated {now}',
                      PS('fr', fontSize=7, textColor=colors.HexColor('#AAAAAA'),
                         alignment=TA_RIGHT)),
        ]], colWidths=[PW/2, PW/2])
        foot.setStyle(TableStyle([
            ('LINEABOVE',    (0,0),(-1,0), 0.5, TEAL),
            ('TOPPADDING',   (0,0),(-1,-1), 5),
            ('LEFTPADDING',  (0,0),(-1,-1), 0),
            ('RIGHTPADDING', (0,0),(-1,-1), 0),
        ]))
        S.append(foot)
        S.append(Paragraph('🤖 Report Generated By VS 🤖', footer))

        doc.build(S)
        pdf = buf.getvalue()
        buf.close()
        return pdf

    except Exception as e:
        print(f'PDF generation error: {e}')
        import traceback; traceback.print_exc()
        return None
