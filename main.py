"""AegisForge AI Backend v2.1 — Enterprise scanner + waitlist + preview."""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import httpx, asyncio, time, re, os, io, csv, json, hashlib, resend
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.client import get_client, safe_get, normalize_scan_target
from scanner.checks import (
    check_https_redirect, check_cdn, check_headers, check_ssl,
    check_dns_security, check_dns, detect_tech_stack, analyze_cookies,
    check_reachability, check_performance, check_security_txt, check_robots_txt,
)
from scanner.scoring import calculate_weighted_score, generate_detailed_recommendations
from scanner.exports import export_pdf, export_json, export_csv

# ═══════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "AegisForge AI <onboarding@resend.dev>")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
WAITLIST_TABLE = os.getenv("WAITLIST_TABLE", "waitlist")
PREVIEW_REQUESTS_TABLE = os.getenv("PREVIEW_REQUESTS_TABLE", "preview_requests")
REPORTS_TABLE = os.getenv("REPORTS_TABLE", "scan_reports")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "3600"))
WAITLIST_RATE_LIMIT = int(os.getenv("WAITLIST_RATE_LIMIT", "5"))
SCAN_RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "10"))
RATE_LIMIT_STORE: dict = {}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

app = FastAPI(title="AegisForge AI Backend", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    url: str
class WaitlistRequest(BaseModel):
    email: str
class PreviewRequest(BaseModel):
    idea: str
    project_type: Optional[str] = "auto"

# ═══════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════
def get_client_ip(request: Request) -> str:
    xfwd = request.headers.get("x-forwarded-for", "")
    if xfwd: return xfwd.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip: return rip.strip()
    return request.client.host if request.client else "unknown"

def enforce_rate_limit(request: Request, bucket: str, limit: int):
    now = time.time(); ip = get_client_ip(request); key = f"{bucket}:{ip}"
    window_start = now - RATE_LIMIT_WINDOW
    ts = [t for t in RATE_LIMIT_STORE.get(key, []) if t > window_start]
    if len(ts) >= limit:
        raise HTTPException(429, detail=f"Rate limited. Retry in {max(1,int(RATE_LIMIT_WINDOW-(now-ts[0])))}s.")
    ts.append(now); RATE_LIMIT_STORE[key] = ts

def require_admin(request: Request):
    if not ADMIN_API_KEY: raise HTTPException(500, "Admin not configured")
    if (request.headers.get("x-admin-key") or request.query_params.get("admin_key")) != ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin key")

def sb_headers(extra=None):
    h = {"apikey": SUPABASE_SERVICE_ROLE_KEY, "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}", "Content-Type": "application/json"}
    if extra: h.update(extra)
    return h
def sb_ok(): return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)

# ═══════════════════════════════════════════
# BASIC ENDPOINTS
# ═══════════════════════════════════════════
@app.get("/")
async def root():
    return {"name": "AegisForge AI Backend", "status": "operational", "version": "2.1.0",
            "endpoints": {"scan": "/scan", "quick_scan": "/quick-scan", "waitlist": "/waitlist",
                          "preview": "/preview/generate", "docs": "/docs"}}

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "2.1.0", "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_configured": bool(RESEND_API_KEY), "supabase_configured": sb_ok()}

# ═══════════════════════════════════════════
# FULL SCAN (v2.1)
# ═══════════════════════════════════════════
@app.post("/scan")
async def scan_website(payload: ScanRequest, request: Request):
    enforce_rate_limit(request, "scan", SCAN_RATE_LIMIT)
    url, domain = normalize_scan_target(payload.url)
    try:
        start = time.time()
        # Run independent checks concurrently
        ssl_task = asyncio.to_thread(check_ssl, domain)
        dns_task = asyncio.to_thread(check_dns, domain)
        dns_sec_task = asyncio.to_thread(check_dns_security, domain)
        headers_coro = check_headers(url)
        reach_coro = check_reachability(url)
        tech_coro = detect_tech_stack(url)
        cookies_coro = analyze_cookies(url)
        cdn_coro = check_cdn(url, domain)
        https_coro = check_https_redirect(domain)
        perf_coro = check_performance(url)
        sectxt_coro = check_security_txt(url)
        robots_coro = check_robots_txt(url)
        results = await asyncio.gather(
            ssl_task, headers_coro, reach_coro, tech_coro, cookies_coro,
            cdn_coro, https_coro, perf_coro, dns_task, dns_sec_task,
            sectxt_coro, robots_coro,
        )
        checks = {
            "ssl": results[0], "headers": results[1], "reachability": results[2],
            "tech_stack": results[3], "cookies": results[4], "cdn": results[5],
            "https_enforcement": results[6], "performance": results[7],
            "dns": results[8], "dns_security": results[9],
            "security_txt": results[10], "robots_txt": results[11],
        }
        duration = round(time.time() - start, 2)
        risk_score = calculate_weighted_score(checks)
        recommendations = generate_detailed_recommendations(checks)
        report_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:12]
        result = {
            "url": url, "domain": domain, "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": duration, "report_id": report_id,
            "checks": checks, "risk_score": risk_score, "recommendations": recommendations,
        }
        # Store report in Supabase (best-effort)
        if sb_ok():
            try:
                import httpx as sync_httpx
                sync_httpx.post(f"{SUPABASE_URL}/rest/v1/{REPORTS_TABLE}",
                    headers=sb_headers({"Prefer": "return=minimal"}),
                    json={"report_id": report_id, "url": url, "domain": domain,
                          "score": risk_score["score"], "grade": risk_score["grade"],
                          "checks_summary": {k: v.get("score", v.get("security_score")) for k, v in checks.items() if v.get("score") is not None or v.get("security_score") is not None}},
                    timeout=5)
            except Exception:
                pass
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Scan failed: {str(e)}")

@app.post("/quick-scan")
async def quick_scan(payload: ScanRequest, request: Request):
    enforce_rate_limit(request, "quick_scan", 20)
    url, domain = normalize_scan_target(payload.url)
    try:
        ssl_r = await asyncio.to_thread(check_ssl, domain)
        hdr_r = await check_headers(url)
        reach_r = await check_reachability(url)
        dns_r = await asyncio.to_thread(check_dns, domain)
        checks = {"ssl": ssl_r, "headers": hdr_r, "reachability": reach_r, "dns": dns_r}
        return {"url": url, "domain": domain, "scanned_at": datetime.now(timezone.utc).isoformat(),
                "checks": checks, "risk_score": calculate_weighted_score(checks)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Scan failed: {str(e)}")

# ═══════════════════════════════════════════
# P11: EXPORT (PDF, JSON, CSV)
# ═══════════════════════════════════════════
@app.get("/scan/{report_id}/export/pdf")
async def export_scan_pdf(report_id: str, request: Request):
    data = await _get_report(report_id, request)
    pdf_bytes = export_pdf(data)
    return StreamingResponse(iter([pdf_bytes]), media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename=aegisforge-scan-{report_id}.pdf"})

@app.get("/scan/{report_id}/export/json")
async def export_scan_json(report_id: str, request: Request):
    data = await _get_report(report_id, request)
    return JSONResponse(content=data)

@app.get("/scan/{report_id}/export/csv")
async def export_scan_csv(report_id: str, request: Request):
    data = await _get_report(report_id, request)
    csv_str = export_csv(data)
    return StreamingResponse(iter([csv_str]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=aegisforge-scan-{report_id}.csv"})

async def _get_report(report_id: str, request: Request) -> dict:
    """Fetch stored report from Supabase, or return error."""
    if not sb_ok():
        raise HTTPException(501, "Report storage not configured")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{SUPABASE_URL}/rest/v1/{REPORTS_TABLE}",
                headers=sb_headers(), params={"report_id": f"eq.{report_id}", "limit": "1"})
            r.raise_for_status()
            rows = r.json()
            if not rows:
                raise HTTPException(404, "Report not found")
            return rows[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Could not fetch report: {str(e)}")

# ═══════════════════════════════════════════
# P12: SHAREABLE REPORT LINKS
# ═══════════════════════════════════════════
@app.get("/report/{report_id}")
async def get_shared_report(report_id: str):
    data = await _get_report(report_id, None)
    return data

# ═══════════════════════════════════════════
# WAITLIST (preserved from v2.0)
# ═══════════════════════════════════════════
def _sb_waitlist_url(): return f"{SUPABASE_URL}/rest/v1/{WAITLIST_TABLE}"

async def _get_waitlist_entry(email: str):
    if not sb_ok(): return None
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(_sb_waitlist_url(), headers=sb_headers(),
                        params={"select": "id,email,created_at", "email": f"eq.{email}", "limit": "1"})
        r.raise_for_status(); rows = r.json()
        return rows[0] if rows else None

async def _create_waitlist_entry(email: str):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(_sb_waitlist_url(), headers=sb_headers({"Prefer": "return=representation"}),
                         json={"email": email, "source": "landing"})
        if r.status_code == 409:
            existing = await _get_waitlist_entry(email)
            if existing: return existing
        r.raise_for_status(); rows = r.json()
        if not rows: raise RuntimeError("Supabase did not return row")
        return rows[0]

async def _get_waitlist_position(created_at: str):
    if not sb_ok() or not created_at: return None
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(_sb_waitlist_url(), headers=sb_headers({"Prefer": "count=exact"}),
                        params={"select": "id", "created_at": f"lte.{created_at}"})
        r.raise_for_status()
        cr = r.headers.get("content-range", "")
        if "/" in cr:
            total = cr.rsplit("/", 1)[-1]
            if total.isdigit(): return int(total)
    return None

def _send_waitlist_email(email: str, position=None, already_joined=False):
    if not RESEND_API_KEY: raise RuntimeError("RESEND_API_KEY not configured")
    resend.api_key = RESEND_API_KEY
    pos_line = f"Your waitlist position is #{position}." if position else "You are on the early access list."
    greeting = "You're already on the waitlist!" if already_joined else "You're officially on the waitlist!"
    status_html = f"Position: <strong>#{position}</strong>" if position else "Confirmed on the early access waitlist."
    resend.Emails.send({"from": FROM_EMAIL, "to": [email], "subject": "🎉 Welcome to AegisForge AI Waitlist",
        "html": f'<div style="font-family:Arial;max-width:620px;margin:auto;padding:40px;background:#0f0f0f;color:white;border-radius:16px;border:1px solid rgba(0,255,200,0.25)"><div style="font-size:34px;margin-bottom:12px">⚡ AegisForge AI</div><h2 style="color:#00ffcc;margin:0 0 18px">{greeting}</h2><p style="font-size:16px;color:#e5e7eb">{pos_line}</p><div style="margin:28px 0;padding:18px;background:rgba(0,255,200,0.08);border-left:4px solid #00ffcc;border-radius:10px"><strong style="color:#00ffcc">Status:</strong> {status_html}</div><p style="color:#94a3b8;font-size:13px">AegisForge AI — Build. Secure. Deploy.</p></div>',
        "text": f"Welcome to AegisForge AI!\n\n{pos_line}\n\nAegisForge AI\nBuild. Secure. Deploy."})

@app.post("/waitlist")
async def join_waitlist(payload: WaitlistRequest, request: Request):
    enforce_rate_limit(request, "waitlist", WAITLIST_RATE_LIMIT)
    email = payload.email.strip().lower()
    if not EMAIL_RE.match(email): raise HTTPException(400, "Valid email required")
    if not RESEND_API_KEY: raise HTTPException(500, "Email service not configured")
    try:
        existing = await _get_waitlist_entry(email)
        already_joined = existing is not None
        entry = existing or await _create_waitlist_entry(email)
        position = await _get_waitlist_position(entry.get("created_at"))
    except Exception as e:
        raise HTTPException(500, f"Could not save position: {str(e)}")
    try:
        _send_waitlist_email(email, position=position, already_joined=already_joined)
        return {"success": True, "email": email, "position": position, "already_joined": already_joined}
    except Exception as e:
        raise HTTPException(500, f"Saved but could not send email: {str(e)}")

@app.get("/waitlist/stats")
async def waitlist_stats():
    if not sb_ok(): return {"total": 0, "storage_configured": False}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(_sb_waitlist_url(), headers=sb_headers({"Prefer": "count=exact"}),
                            params={"select": "id", "limit": "1"})
            r.raise_for_status()
            cr = r.headers.get("content-range", "")
            total = int(cr.rsplit("/",1)[-1]) if "/" in cr and cr.rsplit("/",1)[-1].isdigit() else 0
            return {"total": total, "storage_configured": True}
    except Exception:
        return {"total": 0, "storage_configured": True}

# ═══════════════════════════════════════════
# PREVIEW ENGINE (preserved)
# ═══════════════════════════════════════════
PREVIEW_KEYWORDS = {
    "marketplace": ["marketplace","delivery","vendor","rider","booking platform"],
    "ecommerce": ["store","shop","ecommerce","fashion","products"],
    "dashboard": ["dashboard","admin","analytics","school","crm"],
    "booking": ["booking","appointment","salon","fitness","clinic"],
    "mobile": ["mobile","ios","android","app","tracking"],
    "website": ["website","landing","portfolio","agency","real estate"],
}
CATEGORY_PRESETS = {
    "marketplace": {"name":"MarketFlow","tagline":"Connect customers, vendors, and operators.","roles":["Customer","Vendor","Admin"],"features":["Vendor onboarding","Listings","Payments","Order tracking"],"pages":["Home","Vendor listing","Checkout","Admin panel"],"database":["users","vendors","listings","orders","payments"],"security":["RBAC","Webhook verification","Rate limiting"],"monetization":["Commission","Vendor subscription"],"layout":"marketplace"},
    "ecommerce": {"name":"StorePilot","tagline":"A polished online store.","roles":["Customer","Store Admin"],"features":["Product catalog","Cart","Checkout","Inventory"],"pages":["Home","Shop","Cart","Checkout","Admin"],"database":["users","products","orders","payments"],"security":["Secure checkout","Fraud checks"],"monetization":["Product sales","Subscriptions"],"layout":"store"},
    "dashboard": {"name":"CommandDesk","tagline":"A secure dashboard for operations.","roles":["Admin","Manager","Member"],"features":["Analytics","User management","Reports","Tasks"],"pages":["Overview","Users","Reports","Settings"],"database":["users","teams","tasks","reports"],"security":["RBAC","Audit logging"],"monetization":["Monthly subscription","Team seats"],"layout":"dashboard"},
    "booking": {"name":"BooklyPro","tagline":"Book and pay for services with confidence.","roles":["Client","Provider","Admin"],"features":["Service catalog","Availability","Booking","Payments"],"pages":["Home","Services","Booking","Admin"],"database":["users","services","bookings","payments"],"security":["Spam protection","Payment verification"],"monetization":["Booking fees","Subscription"],"layout":"booking"},
    "mobile": {"name":"AppPulse","tagline":"A mobile-first experience.","roles":["User","Admin"],"features":["Onboarding","Profiles","Push notifications","Tracking"],"pages":["Splash","Home","Details","Profile"],"database":["users","profiles","sessions","activities"],"security":["Secure sessions","Rate limits"],"monetization":["Freemium","In-app subscriptions"],"layout":"mobile"},
    "website": {"name":"LaunchSite","tagline":"A conversion-focused website.","roles":["Visitor","Lead","Admin"],"features":["Hero CTA","Services","Pricing","FAQ"],"pages":["Home","About","Services","Pricing","Contact"],"database":["leads","messages","subscribers"],"security":["Spam protection","Form validation"],"monetization":["Lead generation","Service packages"],"layout":"website"},
}

@app.post("/preview/generate")
async def generate_preview(payload: PreviewRequest, request: Request):
    enforce_rate_limit(request, "preview", 20)
    idea = payload.idea.strip()
    if len(idea) < 8: raise HTTPException(400, "Describe your idea in more detail")
    if len(idea) > 600: raise HTTPException(400, "Idea too long (max 600 chars)")
    # Detect category
    cat = (payload.project_type or "auto").strip().lower().replace(" ","_")
    if cat not in CATEGORY_PRESETS:
        text = idea.lower()
        scores = {c: sum(1 for kw in kws if kw in text) for c, kws in PREVIEW_KEYWORDS.items()}
        cat = max(scores, key=scores.get)
        if scores[cat] == 0: cat = "website"
    preset = CATEGORY_PRESETS[cat]
    # Personalize name
    name = preset["name"]
    words = re.findall(r"[a-zA-Z0-9]+", idea)
    meaningful = [w for w in words if len(w)>3 and w.lower() not in {"build","want","need","create","with","that","app","website"}]
    if meaningful: name = re.sub(r"[^A-Za-z0-9]","", meaningful[0].title())[:12] + "AI"
    return {"success": True, "category": cat, "layout": preset["layout"], "name": name,
            "tagline": preset["tagline"], "summary": f"{name} is a {cat.replace('_',' ')} concept from your idea: {idea}",
            "roles": preset["roles"], "features": preset["features"], "pages": preset["pages"],
            "database": preset["database"], "security": preset["security"],
            "monetization": preset["monetization"],
            "launch_plan": ["Validate with a landing page","Build core flow first","Add payments after validation","Security check before launch","Launch to beta group"],
            "disclaimer": "Smart preview from guided templates. Full AI modules coming soon."}

# ═══════════════════════════════════════════
# ADMIN
# ═══════════════════════════════════════════
@app.get("/admin/waitlist/stats")
async def admin_waitlist_stats(request: Request):
    require_admin(request)
    stats = await waitlist_stats()
    return stats

@app.get("/admin/waitlist/export.csv")
async def export_waitlist_csv(request: Request):
    require_admin(request)
    if not sb_ok(): return StreamingResponse(iter([""]), media_type="text/csv")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(_sb_waitlist_url(), headers=sb_headers(),
                        params={"select": "id,email,source,created_at", "order": "created_at.asc", "limit": "10000"})
        r.raise_for_status(); rows = r.json()
    output = io.StringIO(); w = csv.writer(output)
    w.writerow(["position","id","email","source","created_at"])
    for i, row in enumerate(rows, 1):
        w.writerow([i, row.get("id",""), row.get("email",""), row.get("source",""), row.get("created_at","")])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=aegisforge-waitlist.csv"})

# ═══════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
