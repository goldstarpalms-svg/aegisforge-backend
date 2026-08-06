"""P11: Export as PDF, JSON, CSV with branding."""
import json, csv, io
from fpdf import FPDF
from datetime import datetime

class ScanPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(0, 180, 160)
        self.cell(0, 8, "AegisForge AI — Security Scan Report", new_x="LMARGIN", new_y="NEXT", align="L")
        self.ln(2)
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"AegisForge AI | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | Page {self.page_no()}", align="C")

def export_pdf(data: dict) -> bytes:
    pdf = ScanPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    rs = data.get("risk_score", {})
    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 12, f"Score: {rs.get('score',0)}/100  Grade: {rs.get('grade','F').upper()}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"URL: {data.get('url','')} | Domain: {data.get('domain','')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Scanned: {data.get('scanned_at','')} | Duration: {data.get('scan_duration_seconds','?')}s", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    # Checks
    checks = data.get("checks", {})
    for name, check in checks.items():
        score = check.get("score", check.get("security_score"))
        if score is None:
            continue
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 180, 160)
        pdf.cell(0, 7, f"{name.replace('_',' ').title()} — {score}/100  (Confidence: {check.get('confidence','N/A')})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        for k, v in check.items():
            if k in ("score", "security_score", "confidence"):
                continue
            val = str(v)
            if len(val) > 100:
                val = val[:100] + "..."
            pdf.cell(0, 5, f"  {k}: {val}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
    # Recommendations
    recs = data.get("recommendations", [])
    if recs:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "Recommendations", new_x="LMARGIN", new_y="NEXT")
        for r in recs:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(200, 50, 50) if r.get("priority") == "critical" else pdf.set_text_color(0, 100, 100)
            pdf.cell(0, 6, f"[{r.get('priority','low').upper()}] {r.get('issue','')}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 5, f"  Fix: {r.get('fix','')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 5, f"  Difficulty: {r.get('difficulty','N/A')} | Time: {r.get('estimated_time','N/A')}", new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())

def export_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)

def export_csv(data: dict) -> str:
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Category", "Score", "Confidence", "Key", "Value"])
    for name, check in data.get("checks", {}).items():
        score = check.get("score", check.get("security_score", ""))
        conf = check.get("confidence", "")
        for k, v in check.items():
            if k in ("score", "security_score", "confidence"):
                continue
            w.writerow([name.replace("_", " ").title(), score, conf, k, str(v)[:200]])
    return output.getvalue()
