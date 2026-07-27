from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
import re
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Gmail SMTP Configuration
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class ScanRequest(BaseModel):
    url: str

class WaitlistRequest(BaseModel):
    email: str

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
        "version": "2.0.0"
    }

# ============================================
# WAITLIST ENDPOINT
# ============================================

@app.post("/waitlist")
async def join_waitlist(request: WaitlistRequest):
    """Send welcome email to new waitlist signup using Gmail SMTP"""
    email = request.email.strip().lower()

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")

    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise HTTPException(status_code=500, detail="Gmail credentials not configured")

    try:
        # Create email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🎉 You're In! Welcome to the AegisForge AI Waitlist"
        msg["From"] = f"AegisForge AI <{GMAIL_USER}>"
        msg["To"] = email

        html_content = """
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 620px; margin: auto; background: #0f0f0f; color: #ffffff; padding: 48px 40px; border-radius: 16px; border: 1px solid #1f1f1f;">
            
            <!-- Header -->
            <div style="text-align: center; margin-bottom: 32px;">
                <div style="display: inline-flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                    <span style="font-size: 42px;">⚡</span>
                    <span style="font-size: 28px; font-weight: 700; color: #fff;">AegisForge</span>
                    <span style="font-size: 22px; font-weight: 600; color: #00ffcc;">AI</span>
                </div>
                <div style="background: #00ffcc; color: #000; display: inline-block; padding: 6px 18px; border-radius: 9999px; font-size: 13px; font-weight: 700;">EARLY ACCESS</div>
            </div>

            <h1 style="font-size: 28px; line-height: 1.2; margin: 0 0 20px 0; text-align: center; color: #fff;">
                Welcome to the future of<br>building secure apps.
            </h1>

            <p style="font-size: 17px; line-height: 1.7; color: #ccc; text-align: center; margin-bottom: 32px;">
                You're officially one of the first 1000 founders getting early access to <strong>AegisForge AI</strong> — the autonomous platform that builds, secures, and deploys full applications from a single prompt.
            </p>

            <!-- CTA -->
            <div style="text-align: center; margin: 32px 0;">
                <a href="https://aegisforge-landing.vercel.app" 
                   style="background: #00ffcc; color: #000; padding: 16px 36px; text-decoration: none; border-radius: 10px; font-weight: 700; font-size: 16px; display: inline-block;">
                    🚀 Try the Free AI Security Scanner
                </a>
            </div>

            <div style="background: #1a1a1a; border-radius: 12px; padding: 24px; margin: 32px 0; font-size: 15px; line-height: 1.6;">
                <p style="margin: 0 0 12px 0; color: #00ffcc; font-weight: 600;">What happens next?</p>
                <ul style="margin: 0; padding-left: 20px; color: #ccc;">
                    <li style="margin-bottom: 8px;">You'll receive early access before the public launch</li>
                    <li style="margin-bottom: 8px;">Founder-tier pricing locked in for life</li>
                    <li>Exclusive updates and behind-the-scenes access</li>
                </ul>
            </div>

            <p style="font-size: 14px; color: #666; text-align: center; margin-top: 40px;">
                Built with ❤️ in Lagos &amp; the world<br>
                <span style="font-size: 12px;">AegisForge AI — Security by Default. Speed by Design.</span>
            </p>
        </div>
        """

        msg.attach(MIMEText(html_content, "html"))

        # Send via Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, email, msg.as_string())

        print(f"✅ Gmail email sent successfully to {email}")
        
        return {
            "success": True,
            "message": f"Welcome email sent to {email}"
        }
        
    except Exception as e:
        print(f"❌ Failed to send email to {email}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

# ============================================
# MAIN SCAN ENDPOINT
# ============================================

@app.post("/scan")
async def scan_website(request: ScanRequest):
    """Full comprehensive security scan"""
    url = request.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path

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

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/quick-scan")
async def quick_scan(request: ScanRequest):
    """Fast basic security scan"""
    url = request.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path

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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        response = requests.get(http_url, timeout=10, allow_redirects=False)

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
        response1 = requests.get(url, timeout=10, allow_redirects=True)
        first_load = round((time.time() - start) * 1000)

        start = time.time()
        response2 = requests.get(url, timeout=10, allow_redirects=True)
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
