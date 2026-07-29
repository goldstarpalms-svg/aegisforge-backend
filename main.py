from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
import requests
import ssl
import socket
from urllib.parse import urlparse, urlunparse, urljoin
from datetime import datetime
import re
import time
import ipaddress
import os
import csv
import io
import resend

# Email Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "AegisForge AI <onboarding@resend.dev>")

# Optional Supabase waitlist storage. Use a service-role key on the backend only.
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
WAITLIST_TABLE = os.getenv("WAITLIST_TABLE", "waitlist")
PREVIEW_REQUESTS_TABLE = os.getenv("PREVIEW_REQUESTS_TABLE", "preview_requests")

# Admin and abuse-protection configuration
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "3600"))
WAITLIST_RATE_LIMIT = int(os.getenv("WAITLIST_RATE_LIMIT", "5"))
SCAN_RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "10"))
QUICK_SCAN_RATE_LIMIT = int(os.getenv("QUICK_SCAN_RATE_LIMIT", "20"))
RATE_LIMIT_STORE = {}

REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 2_000_000
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# Create FastAPI app
app = FastAPI(
    title="AegisForge AI Backend",
    description="Autonomous cybersecurity scanner API - Enterprise-grade security analysis",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class ScanRequest(BaseModel):
    url: str

class WaitlistRequest(BaseModel):
    email: str

class PreviewRequest(BaseModel):
    idea: str
    project_type: Optional[str] = "auto"

# ============================================
# VALIDATION HELPERS
# ============================================

def normalize_scan_target(raw_url: str) -> tuple[str, str]:
    """Normalize and validate user-submitted URLs before scanning.

    Blocks localhost/private network targets to prevent SSRF against internal
    infrastructure from the public scanner API.
    """
    url = (raw_url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP and HTTPS URLs are supported")

    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Valid hostname is required")

    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URLs with embedded credentials are not allowed")

    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid port")

    hostname = parsed.hostname.strip().rstrip(".").lower()
    if not hostname or hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        raise HTTPException(status_code=400, detail="Localhost targets are not allowed")

    try:
        hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(status_code=400, detail="Invalid hostname")

    # Reject direct IPs and DNS names resolving to private/internal ranges.
    try:
        ip_obj = ipaddress.ip_address(hostname)
        resolved_ips = [ip_obj]
    except ValueError:
        try:
            addr_info = socket.getaddrinfo(hostname, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            resolved_ips = []
            for item in addr_info:
                ip_text = item[4][0]
                try:
                    resolved_ips.append(ipaddress.ip_address(ip_text))
                except ValueError:
                    continue
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="Hostname could not be resolved")

    if not resolved_ips:
        raise HTTPException(status_code=400, detail="Hostname could not be resolved")

    for ip_obj in resolved_ips:
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise HTTPException(status_code=400, detail="Private or internal network targets are not allowed")

    # Drop fragments; they are never sent to servers and only add noise.
    normalized = urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "", parsed.params, parsed.query, ""))
    return normalized, hostname

def trim_response_body(response: requests.Response) -> requests.Response:
    """Avoid retaining unexpectedly huge response bodies for simple analysis."""
    if len(response.content) > MAX_RESPONSE_BYTES:
        response._content = response.content[:MAX_RESPONSE_BYTES]
    return response

def fetch_url(url: str, *, allow_redirects: bool = True) -> requests.Response:
    """Shared outbound fetch settings with SSRF-safe redirect handling."""
    headers = {"User-Agent": "AegisForgeAI-Scanner/2.0 (+https://aegisforge.ai)"}
    current_url = url
    history = []

    for _ in range(6):
        response = requests.get(current_url, timeout=REQUEST_TIMEOUT, allow_redirects=False, headers=headers)
        trim_response_body(response)

        if not allow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
            response.history = history
            return response

        location = response.headers.get("Location")
        if not location:
            response.history = history
            return response

        history.append(response)
        next_url = urljoin(current_url, location)
        current_url, _ = normalize_scan_target(next_url)

    raise requests.TooManyRedirects("Too many redirects")

def get_client_ip(request: Request) -> str:
    """Get the best-effort client IP behind Render/proxies."""
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"

def enforce_rate_limit(request: Request, bucket: str, limit: int) -> None:
    """Simple in-memory per-IP rate limiter.

    This protects Resend/Supabase/scanner from casual abuse. It resets on server
    restart and should eventually be replaced with Redis for multi-instance use.
    """
    now = time.time()
    client_ip = get_client_ip(request)
    key = f"{bucket}:{client_ip}"
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    timestamps = [ts for ts in RATE_LIMIT_STORE.get(key, []) if ts > window_start]
    if len(timestamps) >= limit:
        retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0])))
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please try again in {retry_after} seconds."
        )

    timestamps.append(now)
    RATE_LIMIT_STORE[key] = timestamps

def require_admin(request: Request) -> None:
    """Require ADMIN_API_KEY via x-admin-key header or ?admin_key= query."""
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="Admin API is not configured")

    provided_key = request.headers.get("x-admin-key") or request.query_params.get("admin_key")
    if provided_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")

# ============================================
# BASIC ENDPOINTS
# ============================================

@app.get("/")
async def root():
    """Welcome endpoint"""
    return {
        "name": "AegisForge AI Backend",
        "status": "operational",
        "version": "2.0.0",
        "message": "Welcome to the future of autonomous cybersecurity",
        "features": [
            "SSL/TLS Analysis",
            "Security Headers Scanner",
            "Tech Stack Detection",
            "Cookie Analysis",
            "CDN Detection",
            "Redirect Chain Analyzer",
            "Performance Metrics",
            "DNS Analysis",
            "Security.txt and Robots.txt Checks",
            "HTTPS Enforcement Check",
            "Risk Scoring with AI Grading"
        ],
        "endpoints": {
            "health": "/health",
            "scan": "/scan (POST)",
            "quick_scan": "/quick-scan (POST)",
            "waitlist": "/waitlist (POST)",
            "waitlist_stats": "/waitlist/stats (GET)",
            "preview_generator": "/preview/generate (POST)",
            "admin_waitlist_stats": "/admin/waitlist/stats (GET)",
            "admin_waitlist_export": "/admin/waitlist/export.csv (GET)",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "AegisForge AI Scanner",
        "version": "2.0.0",
        "email_configured": bool(RESEND_API_KEY),
        "waitlist_storage_configured": bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY),
        "admin_configured": bool(ADMIN_API_KEY),
        "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS
    }

# ============================================
# WAITLIST ENDPOINT
# ============================================

def supabase_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)

def supabase_headers(extra: Optional[dict] = None) -> dict:
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers

def supabase_table_url() -> str:
    return f"{SUPABASE_URL}/rest/v1/{WAITLIST_TABLE}"

def supabase_preview_table_url() -> str:
    return f"{SUPABASE_URL}/rest/v1/{PREVIEW_REQUESTS_TABLE}"

def get_waitlist_entry(email: str) -> Optional[dict]:
    if not supabase_configured():
        return None

    response = requests.get(
        supabase_table_url(),
        headers=supabase_headers(),
        params={
            "select": "id,email,created_at",
            "email": f"eq.{email}",
            "limit": "1",
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    rows = response.json()
    return rows[0] if rows else None

def create_waitlist_entry(email: str) -> dict:
    response = requests.post(
        supabase_table_url(),
        headers=supabase_headers({"Prefer": "return=representation"}),
        json={"email": email, "source": "landing"},
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 409:
        existing = get_waitlist_entry(email)
        if existing:
            return existing

    response.raise_for_status()
    rows = response.json()
    if not rows:
        raise RuntimeError("Supabase did not return inserted waitlist row")
    return rows[0]

def get_waitlist_position(created_at: str) -> Optional[int]:
    if not supabase_configured() or not created_at:
        return None

    response = requests.get(
        supabase_table_url(),
        headers=supabase_headers({"Prefer": "count=exact"}),
        params={
            "select": "id",
            "created_at": f"lte.{created_at}",
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    content_range = response.headers.get("content-range", "")
    if "/" in content_range:
        total = content_range.rsplit("/", 1)[-1]
        if total.isdigit():
            return int(total)
    return None

def get_waitlist_total() -> int:
    if not supabase_configured():
        return 0

    response = requests.get(
        supabase_table_url(),
        headers=supabase_headers({"Prefer": "count=exact"}),
        params={"select": "id", "limit": "1"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    content_range = response.headers.get("content-range", "")
    if "/" in content_range:
        total = content_range.rsplit("/", 1)[-1]
        if total.isdigit():
            return int(total)
    return 0

def fetch_waitlist_rows(limit: int = 10000) -> list[dict]:
    if not supabase_configured():
        return []

    response = requests.get(
        supabase_table_url(),
        headers=supabase_headers(),
        params={
            "select": "id,email,source,created_at",
            "order": "created_at.asc",
            "limit": str(limit),
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()

def register_waitlist_email(email: str) -> tuple[Optional[int], bool]:
    """Store waitlist email and return (position, already_joined)."""
    if not supabase_configured():
        print("⚠️ Supabase waitlist storage not configured; sending email without storing position.")
        return None, False

    existing = get_waitlist_entry(email)
    already_joined = existing is not None
    entry = existing or create_waitlist_entry(email)
    position = get_waitlist_position(entry.get("created_at"))
    return position, already_joined

def send_waitlist_email(email: str, position: Optional[int] = None, already_joined: bool = False) -> None:
    """Send the waitlist welcome email through Resend.

    Resend is used instead of Gmail SMTP because Render/cloud hosts can block or
    timeout outbound SMTP ports. Resend sends over HTTPS, which is reliable on
    Render.
    """
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY is not configured")

    resend.api_key = RESEND_API_KEY

    position_line = f"Your waitlist position is #{position}." if position else "You are officially on the early access list."
    status_html = f"Your waitlist position is <strong>#{position}</strong>." if position else "You are confirmed on the early access waitlist."
    greeting = "You're already on the AegisForge AI waitlist!" if already_joined else "You're officially on the waitlist!"

    text = f"""Welcome to AegisForge AI!

{position_line}

Thank you for joining our waitlist. We'll notify you when the full platform launches.

AegisForge AI
Build. Secure. Deploy.
"""

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 620px; margin: auto; padding: 40px; background: #0f0f0f; color: white; border-radius: 16px; border: 1px solid rgba(0,255,200,0.25);">
        <div style="font-size: 34px; margin-bottom: 12px;">⚡ AegisForge AI</div>
        <h2 style="color: #00ffcc; margin: 0 0 18px;">{greeting}</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #e5e7eb;">Thank you for joining AegisForge AI.</p>
        <p style="font-size: 16px; line-height: 1.6; color: #e5e7eb;">We're building an autonomous AI platform that builds, secures, and deploys applications automatically.</p>
        <div style="margin: 28px 0; padding: 18px; background: rgba(0,255,200,0.08); border-left: 4px solid #00ffcc; border-radius: 10px;">
            <strong style="color: #00ffcc;">Status:</strong> {status_html}
        </div>
        <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1;">We'll notify you when the full platform launches and when founder-tier access opens.</p>
        <p style="margin-top: 32px; color: #94a3b8; font-size: 13px;">AegisForge AI — Build. Secure. Deploy.</p>
    </div>
    """

    result = resend.Emails.send({
        "from": FROM_EMAIL,
        "to": [email],
        "subject": "🎉 Welcome to AegisForge AI Waitlist",
        "html": html,
        "text": text,
    })

    if not result or not result.get("id"):
        raise RuntimeError(f"Resend did not return a message id: {result}")

@app.post("/waitlist")
async def join_waitlist(payload: WaitlistRequest, request: Request):
    """Join waitlist, store email when configured, and send confirmation email."""
    enforce_rate_limit(request, "waitlist", WAITLIST_RATE_LIMIT)
    email = payload.email.strip().lower()

    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Valid email required")

    if not RESEND_API_KEY:
        raise HTTPException(status_code=500, detail="Email service not configured")

    try:
        position, already_joined = register_waitlist_email(email)
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "unknown"
        response_text = e.response.text[:500] if e.response is not None else str(e)
        print(f"❌ Supabase waitlist storage failed for {email}: status={status_code}, response={response_text}")
        raise HTTPException(
            status_code=500,
            detail="Could not save your waitlist position. Please check Supabase service_role key and table setup."
        )
    except Exception as e:
        print(f"❌ Supabase waitlist storage failed for {email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not save your waitlist position. Please try again shortly."
        )

    try:
        send_waitlist_email(email, position=position, already_joined=already_joined)
        print(f"✅ Waitlist email sent to {email} (position={position}, already_joined={already_joined})")
        return {
            "success": True,
            "message": "You are already on the waitlist" if already_joined else "Welcome email sent",
            "email": email,
            "position": position,
            "already_joined": already_joined
        }
    except Exception as e:
        print(f"❌ Resend waitlist email failed for {email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Saved to waitlist, but could not send welcome email. Please check Resend API key, sender, or domain verification."
        )

@app.get("/waitlist/stats")
async def waitlist_stats():
    """Public waitlist stats for social proof."""
    try:
        total = get_waitlist_total()
    except Exception as e:
        print(f"❌ Waitlist stats failed: {str(e)}")
        total = 0

    return {
        "total": total,
        "first_1000_remaining": max(0, 1000 - total),
        "storage_configured": supabase_configured()
    }

@app.get("/admin/waitlist/stats")
async def admin_waitlist_stats(request: Request):
    """Admin-only waitlist stats."""
    require_admin(request)
    total = get_waitlist_total()
    return {
        "total": total,
        "first_1000_remaining": max(0, 1000 - total),
        "storage_configured": supabase_configured(),
        "table": WAITLIST_TABLE
    }

@app.get("/admin/waitlist/export.csv")
async def export_waitlist_csv(request: Request):
    """Admin-only CSV export of waitlist signups."""
    require_admin(request)
    rows = fetch_waitlist_rows()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["position", "id", "email", "source", "created_at"])
    for position, row in enumerate(rows, start=1):
        writer.writerow([
            position,
            row.get("id", ""),
            row.get("email", ""),
            row.get("source", ""),
            row.get("created_at", ""),
        ])

    output.seek(0)
    filename = f"aegisforge-waitlist-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ============================================
# NO-COST SMART PREVIEW ENGINE
# ============================================

PREVIEW_KEYWORDS = {
    "marketplace": ["marketplace", "delivery", "vendor", "rider", "restaurant", "booking platform", "connect buyers", "multi vendor", "multi-vendor"],
    "ecommerce": ["store", "shop", "ecommerce", "e-commerce", "fashion", "products", "cart", "checkout", "inventory"],
    "dashboard": ["dashboard", "admin", "analytics", "management", "school", "student", "teacher", "crm", "inventory", "finance"],
    "booking": ["booking", "appointment", "salon", "fitness", "coach", "clinic", "consultation", "service business"],
    "mobile": ["mobile", "ios", "android", "app", "phone", "tracking", "chat"],
    "website": ["website", "landing", "portfolio", "agency", "real estate", "property", "business site", "company"]
}

CATEGORY_PRESETS = {
    "marketplace": {
        "name": "MarketFlow",
        "tagline": "Connect customers, vendors, and operators in one secure marketplace.",
        "roles": ["Customer", "Vendor", "Operations Admin", "Support Agent"],
        "features": ["Vendor onboarding", "Listings/catalog", "Cart or request flow", "Payments", "Order tracking", "Admin approvals"],
        "pages": ["Homepage", "Vendor listing", "Product/service detail", "Checkout", "Customer dashboard", "Vendor dashboard", "Admin panel"],
        "database": ["users", "vendors", "listings", "orders", "payments", "reviews", "support_tickets"],
        "security": ["Role-based access control", "Payment webhook verification", "Input validation", "Rate limiting", "Audit logs"],
        "monetization": ["Commission per transaction", "Vendor subscription", "Featured listings", "Service fees"],
        "layout": "marketplace"
    },
    "ecommerce": {
        "name": "StorePilot",
        "tagline": "A polished online store with products, checkout, and growth tools.",
        "roles": ["Customer", "Store Admin", "Fulfillment Manager"],
        "features": ["Product catalog", "Cart", "Checkout", "Inventory tracking", "Order emails", "Discount codes"],
        "pages": ["Home", "Shop", "Product detail", "Cart", "Checkout", "Order confirmation", "Admin inventory"],
        "database": ["users", "products", "categories", "orders", "payments", "discounts", "shipments"],
        "security": ["Secure checkout", "Webhook verification", "Admin access control", "Fraud checks", "Secure cookies"],
        "monetization": ["Product sales", "Bundles", "Subscriptions", "Upsells"],
        "layout": "store"
    },
    "dashboard": {
        "name": "CommandDesk",
        "tagline": "A secure dashboard for managing operations, users, and insights.",
        "roles": ["Admin", "Manager", "Team Member", "Viewer"],
        "features": ["Analytics overview", "User management", "Reports", "Tasks/workflows", "Notifications", "Settings"],
        "pages": ["Overview", "Users", "Reports", "Tasks", "Activity logs", "Settings"],
        "database": ["users", "teams", "tasks", "reports", "events", "notifications", "audit_logs"],
        "security": ["RBAC permissions", "Audit logging", "Session security", "Data validation", "Admin action review"],
        "monetization": ["Monthly subscription", "Team seats", "Premium reports", "Managed setup"],
        "layout": "dashboard"
    },
    "booking": {
        "name": "BooklyPro",
        "tagline": "Let clients discover, book, and pay for services with confidence.",
        "roles": ["Client", "Service Provider", "Business Admin"],
        "features": ["Service catalog", "Availability calendar", "Booking form", "Payments/deposits", "Reminders", "Client records"],
        "pages": ["Home", "Services", "Booking", "Provider profile", "Client dashboard", "Admin calendar"],
        "database": ["users", "services", "providers", "availability", "bookings", "payments", "reminders"],
        "security": ["Booking spam protection", "Payment verification", "Client data privacy", "Admin permissions", "Rate limits"],
        "monetization": ["Booking fees", "Monthly subscription", "Premium provider profiles", "Deposits"],
        "layout": "booking"
    },
    "mobile": {
        "name": "AppPulse",
        "tagline": "A mobile-first experience with clean flows and secure user journeys.",
        "roles": ["Mobile User", "Admin", "Support"],
        "features": ["Onboarding", "User profiles", "Push notification plan", "In-app actions", "Activity tracking", "Support chat"],
        "pages": ["Splash", "Onboarding", "Home", "Details", "Profile", "Notifications", "Settings"],
        "database": ["users", "profiles", "sessions", "activities", "notifications", "support_messages"],
        "security": ["Secure sessions", "Device-aware login", "API rate limits", "Input validation", "Privacy-first profiles"],
        "monetization": ["Freemium", "In-app subscriptions", "Premium features", "Partner offers"],
        "layout": "mobile"
    },
    "website": {
        "name": "LaunchSite",
        "tagline": "A conversion-focused website built to explain, persuade, and capture leads.",
        "roles": ["Visitor", "Lead", "Site Admin"],
        "features": ["Hero CTA", "Services", "Testimonials", "Pricing", "FAQ", "Contact form"],
        "pages": ["Home", "About", "Services", "Pricing", "Contact", "Privacy", "Terms"],
        "database": ["leads", "contact_messages", "newsletter_subscribers", "analytics_events"],
        "security": ["Spam protection", "Form validation", "Privacy policy", "Secure hosting", "Rate limits"],
        "monetization": ["Lead generation", "Service packages", "Consulting", "Digital products"],
        "layout": "website"
    }
}

def save_preview_request(idea: str, project_type: str, category: str, generated_name: str) -> None:
    """Best-effort storage for preview requests.

    Preview generation should still work even if analytics storage fails.
    """
    if not supabase_configured():
        return

    try:
        response = requests.post(
            supabase_preview_table_url(),
            headers=supabase_headers({"Prefer": "return=minimal"}),
            json={
                "idea": idea,
                "project_type": project_type or "auto",
                "detected_category": category,
                "generated_name": generated_name,
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except Exception as e:
        print(f"⚠️ Preview request storage failed: {str(e)}")

def fetch_preview_request_rows(limit: int = 10000) -> list[dict]:
    if not supabase_configured():
        return []

    response = requests.get(
        supabase_preview_table_url(),
        headers=supabase_headers(),
        params={
            "select": "id,idea,project_type,detected_category,generated_name,created_at",
            "order": "created_at.desc",
            "limit": str(limit),
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()

def detect_preview_category(idea: str, project_type: str = "auto") -> str:
    normalized_type = (project_type or "auto").strip().lower().replace(" ", "_")
    if normalized_type in CATEGORY_PRESETS:
        return normalized_type

    text = idea.lower()
    scores = {}
    for category, keywords in PREVIEW_KEYWORDS.items():
        scores[category] = sum(1 for keyword in keywords if keyword in text)

    best_category = max(scores, key=scores.get)
    return best_category if scores[best_category] > 0 else "website"

def personalize_preview(base: dict, idea: str, category: str) -> dict:
    words = re.findall(r"[a-zA-Z0-9]+", idea)
    meaningful = [w for w in words if len(w) > 3 and w.lower() not in {"build", "want", "need", "create", "with", "that", "this", "for", "app", "website"}]
    focus = " ".join(meaningful[:4]).title() if meaningful else base["name"]

    name = base["name"]
    if category == "marketplace" and any(w in idea.lower() for w in ["food", "restaurant", "delivery"]):
        name = "FoodFlow"
    elif category == "website" and any(w in idea.lower() for w in ["property", "real estate", "agent"]):
        name = "PrimeListings"
    elif category == "ecommerce" and any(w in idea.lower() for w in ["fashion", "clothes", "clothing"]):
        name = "StyleCart"
    elif category == "booking" and any(w in idea.lower() for w in ["fitness", "coach", "gym"]):
        name = "FitBookings"
    elif meaningful:
        name = re.sub(r"[^A-Za-z0-9]", "", focus.split()[0])[:12] + "AI"

    return {**base, "name": name, "idea_focus": focus}

@app.post("/preview/generate")
async def generate_preview(payload: PreviewRequest, request: Request):
    """Generate a no-cost rule-based app/website preview and blueprint."""
    enforce_rate_limit(request, "preview", QUICK_SCAN_RATE_LIMIT)
    idea = payload.idea.strip()
    if len(idea) < 8:
        raise HTTPException(status_code=400, detail="Please describe your idea in a little more detail")
    if len(idea) > 600:
        raise HTTPException(status_code=400, detail="Idea is too long. Please keep it under 600 characters")

    category = detect_preview_category(idea, payload.project_type or "auto")
    preset = personalize_preview(CATEGORY_PRESETS[category], idea, category)

    response_payload = {
        "success": True,
        "category": category,
        "layout": preset["layout"],
        "name": preset["name"],
        "idea_focus": preset["idea_focus"],
        "tagline": preset["tagline"],
        "summary": f"{preset['name']} is a {category.replace('_', ' ')} concept generated from your idea: {idea}",
        "roles": preset["roles"],
        "features": preset["features"],
        "pages": preset["pages"],
        "database": preset["database"],
        "security": preset["security"],
        "monetization": preset["monetization"],
        "launch_plan": [
            "Validate the idea with a landing page and waitlist",
            "Build the core user flow first",
            "Add payments and notifications after validation",
            "Run security checks before launch",
            "Launch to a small beta group and improve from feedback"
        ],
        "disclaimer": "This is a smart preview generated from guided templates and rules. Full AI build modules are coming soon."
    }

    save_preview_request(idea, payload.project_type or "auto", category, preset["name"])
    return response_payload

@app.get("/admin/previews/export.csv")
async def export_preview_requests_csv(request: Request):
    """Admin-only CSV export of preview generator requests."""
    require_admin(request)
    rows = fetch_preview_request_rows()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "idea", "project_type", "detected_category", "generated_name", "created_at"])
    for row in rows:
        writer.writerow([
            row.get("id", ""),
            row.get("idea", ""),
            row.get("project_type", ""),
            row.get("detected_category", ""),
            row.get("generated_name", ""),
            row.get("created_at", ""),
        ])

    output.seek(0)
    filename = f"aegisforge-preview-requests-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ============================================
# MAIN SCAN ENDPOINT
# ============================================

@app.post("/scan")
async def scan_website(payload: ScanRequest, request: Request):
    """Full comprehensive security scan"""
    enforce_rate_limit(request, "scan", SCAN_RATE_LIMIT)
    url, domain = normalize_scan_target(payload.url)

    try:
        start_time = time.time()

        results = {
            "url": url,
            "domain": domain,
            "scanned_at": datetime.now().isoformat(),
            "checks": {
                "ssl": check_ssl(domain),
                "headers": check_headers(url),
                "reachability": check_reachability(url),
                "tech_stack": detect_tech_stack(url),
                "cookies": analyze_cookies(url),
                "cdn": detect_cdn(url),
                "redirects": check_redirects(url),
                "https_enforcement": check_https_enforcement(domain),
                "performance": check_performance(url),
                "dns": check_dns(domain),
                "security_txt": check_security_txt(url),
                "robots_txt": check_robots_txt(url)
            }
        }

        scan_duration = round(time.time() - start_time, 2)
        results["scan_duration_seconds"] = scan_duration
        results["risk_score"] = calculate_risk_score(results["checks"])
        results["recommendations"] = generate_recommendations(results["checks"])

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/quick-scan")
async def quick_scan(payload: ScanRequest, request: Request):
    """Fast basic security scan"""
    enforce_rate_limit(request, "quick_scan", QUICK_SCAN_RATE_LIMIT)
    url, domain = normalize_scan_target(payload.url)

    try:
        results = {
            "url": url,
            "domain": domain,
            "scanned_at": datetime.now().isoformat(),
            "checks": {
                "ssl": check_ssl(domain),
                "headers": check_headers(url),
                "reachability": check_reachability(url),
                "dns": check_dns(domain)
            }
        }

        results["risk_score"] = calculate_risk_score(results["checks"])
        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# ============================================
# SCANNER FUNCTIONS
# ============================================

def check_ssl(domain: str) -> dict:
    """Check SSL/HTTPS status"""
    try:
        if ':' in domain:
            domain = domain.split(':')[0]

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry - datetime.now()).days

                return {
                    "status": "secure",
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "unknown",
                    "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    "subject": dict(x[0] for x in cert['subject']).get('commonName', 'Unknown'),
                    "expires": cert['notAfter'],
                    "days_until_expiry": days_until_expiry,
                    "expiry_warning": days_until_expiry < 30,
                    "score": 100 if days_until_expiry > 30 else 60
                }
    except Exception as e:
        return {"status": "insecure", "error": str(e), "score": 0}

def check_headers(url: str) -> dict:
    """Check security headers"""
    try:
        response = fetch_url(url, allow_redirects=True)
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy")
        }

        present = sum(1 for v in security_headers.values() if v is not None)
        total = len(security_headers)
        score = int((present / total) * 100)
        missing = [key for key, value in security_headers.items() if value is None]

        return {
            "status_code": response.status_code,
            "headers_present": present,
            "headers_total": total,
            "score": score,
            "present_headers": {k: v for k, v in security_headers.items() if v is not None},
            "missing_headers": missing,
            "server": headers.get("Server", "Unknown"),
            "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "F"
        }
    except Exception as e:
        return {"error": str(e), "score": 0}

def check_reachability(url: str) -> dict:
    """Check if website is reachable"""
    try:
        response = fetch_url(url, allow_redirects=True)
        return {
            "reachable": True,
            "status_code": response.status_code,
            "response_time_ms": int(response.elapsed.total_seconds() * 1000),
            "final_url": response.url,
            "content_type": response.headers.get("Content-Type", "unknown"),
            "content_length": len(response.content),
            "score": 100 if response.status_code == 200 else 50
        }
    except requests.exceptions.Timeout:
        return {"reachable": False, "error": "Request timed out", "score": 0}
    except Exception as e:
        return {"reachable": False, "error": str(e), "score": 0}

def detect_tech_stack(url: str) -> dict:
    """Detect technologies used by the website"""
    try:
        response = fetch_url(url, allow_redirects=True)
        headers = response.headers
        html = response.text.lower()

        detected = {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Not disclosed"),
            "frameworks": [],
            "cms": None,
            "analytics": [],
            "libraries": []
        }

        if "wp-content" in html or "wordpress" in html:
            detected["cms"] = "WordPress"
        elif "drupal" in html:
            detected["cms"] = "Drupal"
        elif "shopify" in html:
            detected["cms"] = "Shopify"
        elif "wix.com" in html:
            detected["cms"] = "Wix"

        if "react" in html or "_next" in html:
            detected["frameworks"].append("React/Next.js")
        if "vue" in html or "nuxt" in html:
            detected["frameworks"].append("Vue.js/Nuxt")
        if "angular" in html:
            detected["frameworks"].append("Angular")

        if "google-analytics" in html or "gtag" in html:
            detected["analytics"].append("Google Analytics")
        if "facebook.com/tr" in html or "fbq(" in html:
            detected["analytics"].append("Facebook Pixel")

        if "jquery" in html:
            detected["libraries"].append("jQuery")
        if "bootstrap" in html:
            detected["libraries"].append("Bootstrap")
        if "tailwind" in html:
            detected["libraries"].append("Tailwind CSS")

        total_tech = len(detected["frameworks"]) + len(detected["analytics"]) + len(detected["libraries"])
        if detected["cms"]:
            total_tech += 1

        disclosure_penalty = 0
        if detected["server"] and detected["server"] != "Unknown":
            disclosure_penalty += 10
        if detected["powered_by"] and detected["powered_by"] != "Not disclosed":
            disclosure_penalty += 20

        return {
            "detected": detected,
            "total_technologies": total_tech,
            "score": max(60, 100 - disclosure_penalty),
            "disclosure_note": "Less server/framework disclosure is generally safer."
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_cookies(url: str) -> dict:
    """Analyze cookies for security and tracking"""
    try:
        response = fetch_url(url, allow_redirects=True)
        cookies = response.cookies

        cookie_list = []
        secure_count = 0
        tracking_count = 0
        tracking_names = ['_ga', '_gid', '_fbp', '_utm', 'ajs_', 'mp_']

        for cookie in cookies:
            is_tracking = any(t in cookie.name.lower() for t in tracking_names)
            if is_tracking:
                tracking_count += 1
            if cookie.secure:
                secure_count += 1
            cookie_list.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "secure": cookie.secure,
                "is_tracking": is_tracking
            })

        total = len(cookie_list)
        return {
            "total_cookies": total,
            "secure_cookies": secure_count,
            "tracking_cookies": tracking_count,
            "cookies": cookie_list[:10],
            "security_score": int((secure_count / total * 100)) if total > 0 else 100
        }
    except Exception as e:
        return {"error": str(e)}

def detect_cdn(url: str) -> dict:
    """Detect CDN usage"""
    try:
        response = fetch_url(url, allow_redirects=True)
        headers = response.headers

        cdn_indicators = {
            "Cloudflare": ["cf-ray", "cf-cache-status"],
            "Akamai": ["akamai"],
            "AWS CloudFront": ["cloudfront"],
            "Fastly": ["fastly"],
            "Vercel": ["x-vercel"],
            "Netlify": ["x-nf"]
        }

        detected_cdns = []
        headers_str = str(headers).lower()

        for cdn_name, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    if cdn_name not in detected_cdns:
                        detected_cdns.append(cdn_name)
                    break

        return {
            "using_cdn": len(detected_cdns) > 0,
            "cdns_detected": detected_cdns,
            "count": len(detected_cdns),
            "score": 100 if detected_cdns else 60
        }
    except Exception as e:
        return {"error": str(e)}

def check_redirects(url: str) -> dict:
    """Analyze redirect chain"""
    try:
        response = fetch_url(url, allow_redirects=True)
        redirect_chain = []
        for r in response.history:
            redirect_chain.append({
                "from": r.url,
                "to": r.headers.get('Location', 'unknown'),
                "status_code": r.status_code
            })

        total_redirects = len(response.history)
        return {
            "total_redirects": total_redirects,
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "has_redirects": total_redirects > 0,
            "score": 100 if total_redirects <= 2 else max(50, 100 - (total_redirects * 10))
        }
    except Exception as e:
        return {"error": str(e)}

def check_https_enforcement(domain: str) -> dict:
    """Check if HTTP redirects to HTTPS"""
    try:
        if ':' in domain:
            domain = domain.split(':')[0]

        http_url = f"http://{domain}"
        response = fetch_url(http_url, allow_redirects=False)

        redirects_to_https = False
        location = response.headers.get('Location', '')

        if response.status_code in [301, 302, 307, 308]:
            if location.startswith('https://'):
                redirects_to_https = True

        return {
            "enforces_https": redirects_to_https,
            "http_status_code": response.status_code,
            "redirect_location": location,
            "score": 100 if redirects_to_https else 0
        }
    except Exception as e:
        return {"enforces_https": None, "error": str(e), "score": 50}

def check_performance(url: str) -> dict:
    """Basic performance metrics"""
    try:
        start = time.time()
        response1 = fetch_url(url, allow_redirects=True)
        first_load = round((time.time() - start) * 1000)

        start = time.time()
        response2 = fetch_url(url, allow_redirects=True)
        second_load = round((time.time() - start) * 1000)

        content_size_kb = round(len(response1.content) / 1024, 2)

        if first_load < 500:
            grade = "A"
        elif first_load < 1000:
            grade = "B"
        elif first_load < 2000:
            grade = "C"
        elif first_load < 3000:
            grade = "D"
        else:
            grade = "F"

        return {
            "first_load_ms": first_load,
            "cached_load_ms": second_load,
            "content_size_kb": content_size_kb,
            "grade": grade,
            "score": max(0, 100 - (first_load // 30))
        }
    except Exception as e:
        return {"error": str(e), "score": 0}

def check_dns(domain: str) -> dict:
    """Basic DNS resolution analysis."""
    try:
        if ':' in domain:
            domain = domain.split(':')[0]

        addr_info = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        ipv4 = sorted({item[4][0] for item in addr_info if item[0] == socket.AF_INET})
        ipv6 = sorted({item[4][0] for item in addr_info if item[0] == socket.AF_INET6})

        return {
            "resolves": bool(ipv4 or ipv6),
            "ipv4_addresses": ipv4[:10],
            "ipv6_addresses": ipv6[:10],
            "ipv4_count": len(ipv4),
            "ipv6_count": len(ipv6),
            "score": 100 if (ipv4 or ipv6) else 0
        }
    except Exception as e:
        return {"resolves": False, "error": str(e), "score": 0}

def _origin_from_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def check_security_txt(url: str) -> dict:
    """Check for RFC 9116 security.txt locations."""
    try:
        origin = _origin_from_url(url)
        locations = [
            f"{origin}/.well-known/security.txt",
            f"{origin}/security.txt",
        ]

        attempts = []
        for location in locations:
            try:
                response = fetch_url(location, allow_redirects=True)
                found = response.status_code == 200 and "Contact:" in response.text[:5000]
                attempts.append({
                    "url": location,
                    "status_code": response.status_code,
                    "found": found
                })
                if found:
                    text = response.text[:5000]
                    return {
                        "found": True,
                        "url": location,
                        "status_code": response.status_code,
                        "has_contact": "Contact:" in text,
                        "has_expires": "Expires:" in text,
                        "has_policy": "Policy:" in text,
                        "score": 100
                    }
            except Exception as e:
                attempts.append({"url": location, "error": str(e), "found": False})

        return {
            "found": False,
            "attempts": attempts,
            "score": 40,
            "recommendation": "Add /.well-known/security.txt with a security contact policy."
        }
    except Exception as e:
        return {"found": False, "error": str(e), "score": 40}

def check_robots_txt(url: str) -> dict:
    """Check for robots.txt presence and basic accessibility."""
    try:
        origin = _origin_from_url(url)
        robots_url = f"{origin}/robots.txt"
        response = fetch_url(robots_url, allow_redirects=True)
        found = response.status_code == 200
        text = response.text[:5000] if found else ""

        return {
            "found": found,
            "url": robots_url,
            "status_code": response.status_code,
            "has_sitemap": "sitemap:" in text.lower(),
            "has_disallow": "disallow:" in text.lower(),
            "score": 100 if found else 70
        }
    except Exception as e:
        return {"found": False, "error": str(e), "score": 70}

# ============================================
# RISK SCORING & RECOMMENDATIONS
# ============================================

def calculate_risk_score(checks: dict) -> dict:
    """Calculate overall security risk score"""
    scores = []
    for check_name, check_data in checks.items():
        if isinstance(check_data, dict) and "score" in check_data:
            scores.append(check_data["score"])

    if not scores:
        return {"score": 0, "grade": "F", "status": "unknown"}

    average = sum(scores) / len(scores)

    if average >= 90:
        grade, status = "A", "excellent"
    elif average >= 80:
        grade, status = "B", "good"
    elif average >= 70:
        grade, status = "C", "fair"
    elif average >= 60:
        grade, status = "D", "poor"
    else:
        grade, status = "F", "critical"

    return {
        "score": int(average),
        "grade": grade,
        "status": status,
        "total_checks": len(scores)
    }

def generate_recommendations(checks: dict) -> List[dict]:
    """Generate actionable recommendations"""
    recommendations = []

    if "ssl" in checks:
        ssl_data = checks["ssl"]
        if ssl_data.get("status") != "secure":
            recommendations.append({
                "priority": "critical",
                "category": "SSL/TLS",
                "issue": "Website not using HTTPS",
                "fix": "Install SSL certificate and enable HTTPS"
            })

    if "headers" in checks:
        missing = checks["headers"].get("missing_headers", [])
        for header in missing:
            recommendations.append({
                "priority": "medium",
                "category": "Headers",
                "issue": f"Missing {header} header",
                "fix": f"Add {header} to your server configuration"
            })

    if "https_enforcement" in checks:
        if not checks["https_enforcement"].get("enforces_https"):
            recommendations.append({
                "priority": "critical",
                "category": "HTTPS",
                "issue": "HTTP not redirecting to HTTPS",
                "fix": "Configure server to redirect all HTTP traffic to HTTPS"
            })

    if "cdn" in checks:
        if not checks["cdn"].get("using_cdn"):
            recommendations.append({
                "priority": "low",
                "category": "Infrastructure",
                "issue": "Not using a CDN",
                "fix": "Consider Cloudflare or similar CDN for speed and security"
            })

    if "security_txt" in checks:
        if not checks["security_txt"].get("found"):
            recommendations.append({
                "priority": "low",
                "category": "Security Policy",
                "issue": "Missing security.txt",
                "fix": "Add /.well-known/security.txt so researchers know how to report vulnerabilities responsibly"
            })

    if "robots_txt" in checks:
        if checks["robots_txt"].get("found") and not checks["robots_txt"].get("has_sitemap"):
            recommendations.append({
                "priority": "low",
                "category": "SEO / Crawling",
                "issue": "robots.txt has no sitemap reference",
                "fix": "Add a Sitemap line to robots.txt to help search engines discover your pages"
            })

    return recommendations

# ============================================
# RUN SERVER
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
