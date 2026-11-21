"""
report_generator.py — PDF Report Generator v2.0
NEW: AI narrative section, behavioral analysis summary,
     attacker profile breakdown, evidence-based recommendations.
"""

import os, json, logging
from datetime import datetime, timedelta
from config import REPORT_DIR, ORGANIZATION_NAME, PDF_LOGO_TEXT

logger = logging.getLogger("honeypot.report")


# ─── Color palette ────────────────────────────────────────────────────────────
C_BG       = (6,  11,  24)       # dark navy
C_SURF     = (13, 21,  38)
C_BLUE     = (59, 130, 246)
C_CYAN     = (6,  182, 212)
C_RED      = (239, 68, 68)
C_ORANGE   = (249,115, 22)
C_GREEN    = (34, 197, 94)
C_PURPLE   = (168, 85,247)
C_TEXT     = (226,232,240)
C_MUTED    = (100,116,139)
C_WHITE    = (255,255,255)

def _rgb(t): return (t[0]/255, t[1]/255, t[2]/255)


def generate_daily_report(date_str=None):
    try:
        from reportlab.lib.pagesizes  import A4
        from reportlab.lib.units      import mm
        from reportlab.pdfgen         import canvas as rl_canvas
        from reportlab.lib.colors     import Color
        from reportlab.platypus       import Table, TableStyle
        from reportlab.lib            import colors as rl_colors
    except ImportError:
        raise RuntimeError("reportlab not installed. Run: pip install reportlab")

    import database as db

    date = datetime.strptime(date_str, "%Y-%m-%d") if date_str else datetime.utcnow()
    date_label  = date.strftime("%Y-%m-%d")
    fname       = f"honeypot_report_{date_label}.pdf"
    fpath       = os.path.join(REPORT_DIR, fname)

    W, H = A4
    c    = rl_canvas.Canvas(fpath, pagesize=A4)

    def bg_page():
        c.setFillColorRGB(*_rgb(C_BG))
        c.rect(0, 0, W, H, fill=1, stroke=0)

    def text(x, y, s, size=10, color=C_TEXT, bold=False):
        c.setFillColorRGB(*_rgb(color))
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x*mm, y*mm, str(s))

    def rtext(x, y, s, size=10, color=C_TEXT):
        c.setFillColorRGB(*_rgb(color))
        c.setFont("Helvetica", size)
        c.drawRightString(x*mm, y*mm, str(s))

    def hline(y, col=C_SURF, w=0.5):
        c.setStrokeColorRGB(*_rgb(col))
        c.setLineWidth(w)
        c.line(14*mm, y*mm, (W/mm-14)*mm, y*mm)

    def pill(x, y, label, bg, fg=C_WHITE, w=32, h=6):
        c.setFillColorRGB(*_rgb(bg))
        c.roundRect(x*mm, y*mm, w*mm, h*mm, 2*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(fg))
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString((x+w/2)*mm, (y+1.5)*mm, label)

    def section_header(y, title):
        c.setFillColorRGB(*_rgb(C_SURF))
        c.rect(14*mm, y*mm, (W/mm-28)*mm, 8*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(C_BLUE))
        c.rect(14*mm, y*mm, 2*mm, 8*mm, fill=1, stroke=0)
        text(18, y+2, title, size=11, color=C_CYAN, bold=True)
        return y - 12

    def kpi_box(x, y, w, h, label, value, color):
        c.setFillColorRGB(*_rgb(C_SURF))
        c.roundRect(x*mm, y*mm, w*mm, h*mm, 2*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(color))
        c.rect(x*mm, (y+h-1.5)*mm, w*mm, 1.5*mm, fill=1, stroke=0)
        text(x+3, y+h-5, label, size=7, color=C_MUTED)
        text(x+3, y+3,   value, size=16, color=C_WHITE, bold=True)

    # ── Load data ─────────────────────────────────────────────────────────────
    stats     = db.get_dashboard_stats()
    sessions  = db.get_recent_sessions(50)
    countries = db.get_country_distribution()
    atypes    = db.get_attack_type_distribution()
    profiles  = db.get_attacker_type_distribution()
    phases    = db.get_attack_phase_distribution()
    alerts    = db.get_recent_alerts(10)
    top_atk   = db.get_top_attackers(8)

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 1: Cover + KPIs + Architecture
    # ─────────────────────────────────────────────────────────────────────────
    bg_page()

    # Header gradient bar
    c.setFillColorRGB(*_rgb(C_BLUE))
    c.rect(0, H-22*mm, W, 22*mm, fill=1, stroke=0)
    c.setFillColorRGB(*_rgb(C_CYAN))
    c.rect(0, H-24*mm, W, 2*mm, fill=1, stroke=0)

    c.setFillColorRGB(*_rgb(C_WHITE))
    c.setFont("Helvetica-Bold", 18)
    c.drawString(14*mm, H-14*mm, f"🍯  {PDF_LOGO_TEXT}")
    c.setFont("Helvetica", 9)
    c.setFillColorRGB(*_rgb((180,210,255)))
    c.drawRightString(W-14*mm, H-14*mm, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    c.drawRightString(W-14*mm, H-9*mm,  ORGANIZATION_NAME)

    # KPI row
    ky = H/mm - 42
    kw, kh, kgap = 37, 20, 4
    kx = 14
    kpis = [
        ("Total Sessions",  str(stats.get('total_sessions',0)),  C_BLUE),
        ("Unique IPs",      str(stats.get('unique_ips',0)),       C_CYAN),
        ("Countries",       str(stats.get('countries',0)),        C_GREEN),
        ("High Risk",       str(stats.get('high_risk',0)),        C_RED),
        ("Bots Detected",   str(stats.get('bots_detected',0)),    C_ORANGE),
    ]
    for label,val,col in kpis:
        kpi_box(kx, ky, kw, kh, label, val, col)
        kx += kw+kgap

    y = ky - 12

    # Architecture section
    y = section_header(y, "📐 System Architecture — 3-Layer Hybrid AI Model")
    layers = [
        ("Layer 3 — Presentation",  "Flask REST API + SSE + Dashboard (app.py, dashboard.html)",           C_CYAN),
        ("Layer 2 — Intelligence",  "Hybrid AI: Rule-based + Behavioral + LLM (ai_analyzer, behavior_analyzer, llm_client)", C_BLUE),
        ("Layer 1 — Collection",    "SSH Honeypot + SQLite + Geo (honeypot_server, database, geo)",         C_GREEN),
    ]
    for lname, ldesc, lcol in layers:
        c.setFillColorRGB(*_rgb(C_SURF))
        c.roundRect(14*mm, y*mm, (W/mm-28)*mm, 9*mm, 2*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(lcol))
        c.roundRect(14*mm, y*mm, 3*mm, 9*mm, 1.5*mm, fill=1, stroke=0)
        text(20, y+5.5, lname, size=9, color=C_WHITE, bold=True)
        text(60, y+5.5, ldesc, size=7.5, color=C_MUTED)
        y -= 11

    y -= 4

    # Attack type breakdown
    y = section_header(y, "⚔️ Attack Type Distribution")
    max_cnt = atypes[0]['cnt'] if atypes else 1
    for at in atypes[:8]:
        bar_w = max(2, int(80 * at['cnt']/max_cnt))
        c.setFillColorRGB(*_rgb(C_SURF))
        c.roundRect(14*mm, y*mm, (W/mm-28)*mm, 7*mm, 1.5*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(C_BLUE))
        c.roundRect(55*mm, (y+1.5)*mm, bar_w*mm, 4*mm, 1*mm, fill=1, stroke=0)
        text(16, y+2.5, at['primary_type'].replace('_',' ').title(), size=8, color=C_TEXT)
        rtext(53, y+2.5, str(at['cnt']), size=8, color=C_MUTED)
        text(57+bar_w, y+2.5, f"{at['cnt']} sessions", size=7, color=C_MUTED)
        y -= 9

    c.showPage()

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 2: Behavioral Intelligence + Attacker Profiles
    # ─────────────────────────────────────────────────────────────────────────
    bg_page()
    c.setFillColorRGB(*_rgb(C_BLUE))
    c.rect(0, H-10*mm, W, 10*mm, fill=1, stroke=0)
    text(14, H/mm-6, "Behavioral Intelligence Report", size=12, color=C_WHITE, bold=True)
    rtext(W/mm-14, H/mm-6, date_label, size=9, color=(180,210,255))

    y = H/mm - 18

    # Attacker profiles
    y = section_header(y, "🤖 Attacker Profile Breakdown")
    profile_colors = {
        "automated_bot":     C_RED,
        "script_kiddie":     C_ORANGE,
        "experienced_human": C_PURPLE,
        "unknown":           C_MUTED,
    }
    for p in profiles:
        col = profile_colors.get(p['attacker_type'], C_MUTED)
        pill(14, y, p['attacker_type'].replace('_',' ').upper(), col, w=46, h=7)
        text(64, y+1.5, f"{p['cnt']} sessions", size=9, color=C_TEXT)
        y -= 10

    y -= 4

    # Attack phases
    y = section_header(y, "🎯 Attack Phase Detection")
    phase_colors = {"reconnaissance":C_CYAN, "exploitation":C_ORANGE, "post_compromise":C_RED}
    for p in phases:
        col = phase_colors.get(p['attack_phase'], C_MUTED)
        pill(14, y, p['attack_phase'].replace('_',' ').upper(), col, w=44, h=7)
        text(62, y+1.5, f"{p['cnt']} sessions classified in this phase", size=9, color=C_TEXT)
        y -= 10

    y -= 4

    # AI Narrative Samples
    y = section_header(y, "🤖 AI-Generated Session Narratives (Sample)")
    high_sessions = [s for s in sessions if s.get('risk_level')=='High'][:3]
    for s in high_sessions:
        narrative = (s.get('ai_narrative') or 'Analysis pending.')[:320]
        ip = s.get('ip_address','unknown')
        country = s.get('country','Unknown')
        risk = s.get('risk_level','Low')
        profile = (s.get('attacker_type') or s.get('ai_attacker_type') or 'unknown').replace('_',' ')

        c.setFillColorRGB(*_rgb(C_SURF))
        c.roundRect(14*mm, (y-18)*mm, (W/mm-28)*mm, 22*mm, 2*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(C_RED if risk=='High' else C_ORANGE))
        c.roundRect(14*mm, (y-18)*mm, 2.5*mm, 22*mm, 1.5*mm, fill=1, stroke=0)

        text(19, y+1,  f"{ip} ({country})", size=9, color=C_WHITE, bold=True)
        text(19, y-3,  f"Profile: {profile}  |  Risk: {risk}", size=7.5, color=C_MUTED)

        # Word-wrap narrative
        words  = narrative.split()
        lines  = []
        cur    = ""
        for w in words:
            if len(cur)+len(w)+1 <= 90:
                cur = (cur+" "+w).strip()
            else:
                lines.append(cur); cur=w
        if cur: lines.append(cur)

        ly = y-7
        for line in lines[:3]:
            text(19, ly, line, size=7, color=C_TEXT)
            ly -= 4.5

        y -= 26

    c.showPage()

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 3: Sessions + Top Attackers + Countries
    # ─────────────────────────────────────────────────────────────────────────
    bg_page()
    c.setFillColorRGB(*_rgb(C_BLUE))
    c.rect(0, H-10*mm, W, 10*mm, fill=1, stroke=0)
    text(14, H/mm-6, "Session & Threat Intelligence", size=12, color=C_WHITE, bold=True)
    rtext(W/mm-14, H/mm-6, date_label, size=9, color=(180,210,255))

    y = H/mm - 18

    # Top attackers table
    y = section_header(y, "🎯 Top Attackers")
    headers = ["IP Address", "Country", "Profile", "Sessions", "Cmds", "Max Risk"]
    col_w   = [38, 30, 38, 18, 14, 18]
    cx = 14
    # Header row
    c.setFillColorRGB(*_rgb(C_SURF))
    c.rect(14*mm, y*mm, (W/mm-28)*mm, 7*mm, fill=1, stroke=0)
    for h_txt, w in zip(headers, col_w):
        text(cx+1, y+2, h_txt, size=7.5, color=C_MUTED, bold=True)
        cx += w
    y -= 7
    risk_cols = {'High':C_RED,'Medium':C_ORANGE,'Low':C_GREEN}
    for i,atk in enumerate(top_atk):
        cx = 14
        row_bg = C_SURF if i%2==0 else C_BG
        c.setFillColorRGB(*_rgb(row_bg))
        c.rect(14*mm, y*mm, (W/mm-28)*mm, 6*mm, fill=1, stroke=0)
        vals = [atk.get('ip_address',''),atk.get('country',''),
                (atk.get('attacker_type') or '—').replace('_',' '),
                str(atk.get('sessions',0)),str(atk.get('total_cmds',0)),atk.get('max_risk','')]
        for j,(v,w) in enumerate(zip(vals,col_w)):
            col = risk_cols.get(v,C_TEXT) if j==5 else C_TEXT
            text(cx+1, y+1.5, v[:22], size=7.5, color=col)
            cx += w
        y -= 7

    y -= 8

    # Countries table
    y = section_header(y, "🌍 Top Origin Countries")
    for i,cn in enumerate(countries[:10]):
        cx = 14
        c.setFillColorRGB(*_rgb(C_SURF if i%2==0 else C_BG))
        c.rect(14*mm, y*mm, (W/mm-28)*mm, 6*mm, fill=1, stroke=0)
        bar_w = max(2, int(40*cn['cnt']/(countries[0]['cnt'] or 1)))
        text(cx+1, y+1.5, f"{cn['country']}", size=8, color=C_TEXT)
        c.setFillColorRGB(*_rgb(C_BLUE))
        c.roundRect((cx+48)*mm, (y+1)*mm, bar_w*mm, 4*mm, 1*mm, fill=1, stroke=0)
        rtext(W/mm-16, y+1.5, str(cn['cnt']), size=8, color=C_MUTED)
        y -= 7

    y -= 8

    # Alerts summary
    y = section_header(y, "🚨 Recent Alerts")
    for alert in alerts[:6]:
        risk_col = risk_cols.get(alert.get('risk_level','Low'), C_TEXT)
        pill(14, y, (alert.get('risk_level','?')).upper(), risk_col, w=16, h=6)
        if alert.get('is_live'):
            pill(33, y, "LIVE", C_CYAN, w=12, h=6)
            text(48, y+1.5, f"{alert.get('ip_address','')} ({alert.get('country','')})", size=8, color=C_TEXT)
        else:
            text(33, y+1.5, f"{alert.get('ip_address','')} ({alert.get('country','')})", size=8, color=C_TEXT)
        ts_raw = alert.get('sent_at','')
        ts_str = ts_raw[:16].replace('T',' ') if ts_raw else ''
        rtext(W/mm-14, y+1.5, ts_str, size=7, color=C_MUTED)
        y -= 9

    c.showPage()

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 4: Evidence-Based Recommendations
    # ─────────────────────────────────────────────────────────────────────────
    bg_page()
    c.setFillColorRGB(*_rgb(C_BLUE))
    c.rect(0, H-10*mm, W, 10*mm, fill=1, stroke=0)
    text(14, H/mm-6, "Evidence-Based Security Recommendations", size=12, color=C_WHITE, bold=True)
    rtext(W/mm-14, H/mm-6, date_label, size=9, color=(180,210,255))

    y = H/mm - 20

    high_sessions_recs = [s for s in sessions if s.get('risk_level')=='High'][:5]
    for s in high_sessions_recs:
        ip   = s.get('ip_address','')
        risk = s.get('risk_level','Low')
        atk_type = s.get('primary_type','unknown').replace('_',' ').title()

        # Session header box
        c.setFillColorRGB(*_rgb(C_SURF))
        c.roundRect(14*mm, y*mm, (W/mm-28)*mm, 8*mm, 2*mm, fill=1, stroke=0)
        c.setFillColorRGB(*_rgb(C_RED if risk=='High' else C_ORANGE))
        c.roundRect(14*mm, y*mm, 3*mm, 8*mm, 1.5*mm, fill=1, stroke=0)
        text(19, y+5, f"Session: {ip}  ·  {atk_type}  ·  {risk} Risk", size=9, color=C_WHITE, bold=True)
        text(19, y+1.5, f"Profile: {(s.get('attacker_type') or 'unknown').replace('_',' ')}  ·  Phase: {(s.get('attack_phase') or '—').replace('_',' ')}", size=7.5, color=C_MUTED)
        y -= 10

        # Recommendations
        detail = db.get_attack_for_session(s.get('id'))
        recs_raw = detail.get('recommendations','') if detail else ''
        recs = [r for r in recs_raw.split('\n') if r.strip()][:3]
        for rec in recs:
            c.setFillColorRGB(*_rgb(C_SURF))
            c.roundRect(16*mm, y*mm, (W/mm-30)*mm, 7*mm, 1.5*mm, fill=1, stroke=0)
            c.setFillColorRGB(*_rgb(C_GREEN))
            c.circle(18.5*mm, (y+3.5)*mm, 1*mm, fill=1, stroke=0)
            rec_clean = rec.lstrip('•– ').strip()[:110]
            text(20.5, y+2.5, rec_clean, size=7, color=C_TEXT)
            y -= 9

        y -= 6
        if y < 30:
            c.showPage(); bg_page(); y = H/mm - 20

    # Footer
    c.setFillColorRGB(*_rgb(C_CYAN))
    c.rect(0, 0, W, 8*mm, fill=1, stroke=0)
    c.setFillColorRGB(*_rgb(C_BG))
    c.setFont("Helvetica", 8)
    c.drawCentredString(W/2, 3*mm, f"AI-Powered Honeypot System v2.0  ·  {ORGANIZATION_NAME}  ·  Confidential")

    c.save()
    logger.info("PDF report saved: %s", fpath)
    return fpath
