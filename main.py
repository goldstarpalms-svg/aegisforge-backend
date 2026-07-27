from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
import resend

# Email Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "AegisForge AI <onboarding@resend.dev>")

# Optional Supabase waitlist storage. Use a service-role key on the backend only.
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
WAITLIST_TABLE = os.getenv("WAITLIST_TABLE", "waitlist")

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
            "HTTPS Enforcement Check",
            "Risk Scoring with AI Grading"
        ],
        "endpoints": {
            "health": "/health",
            "scan": "/scan (POST)",
            "quick_scan": "/quick-scan (POST)",
            "waitlist": "/waitlist (POST)",
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
        "waitlist_storage_configured": bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)
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
async def join_waitlist(request: WaitlistRequest):
    """Join waitlist, store email when configured, and send confirmation email."""
    email = request.email.strip().lower()

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

# ============================================
# MAIN SCAN ENDPOINT
# ============================================

@app.post("/scan")
async def scan_website(request: ScanRequest):
    """Full comprehensive security scan"""
    url, domain = normalize_scan_target(request.url)

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
                "performance": check_performance(url)
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
async def quick_scan(request: ScanRequest):
    """Fast basic security scan"""
    url, domain = normalize_scan_target(request.url)

    try:
        results = {
            "url": url,
            "domain": domain,
            "scanned_at": datetime.now().isoformat(),
            "checks": {
                "ssl": check_ssl(domain),
                "headers": check_headers(url),
                "reachability": check_reachability(url)
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

        return {
            "detected": detected,
            "total_technologies": total_tech
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
            "count": len(detected_cdns)
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

        return {
            "total_redirects": len(response.history),
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "has_redirects": len(response.history) > 0
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

    return recommendations

# ============================================
# RUN SERVER
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
