from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

# Create FastAPI app
app = FastAPI(
    title="AegisForge AI Backend",
    description="Autonomous cybersecurity scanner API",
    version="1.0.0"
)

# Enable CORS (allows your frontend to talk to this backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request model for scan
class ScanRequest(BaseModel):
    url: str

# ============================================
# BASIC ENDPOINTS
# ============================================

@app.get("/")
async def root():
    """Welcome endpoint - shows the API is alive"""
    return {
        "name": "AegisForge AI Backend",
        "status": "operational",
        "version": "1.0.0",
        "message": "Welcome to the future of autonomous cybersecurity",
        "endpoints": {
            "health": "/health",
            "scan": "/scan (POST)",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint - confirms API is working"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "AegisForge AI Scanner"
    }

# ============================================
# SECURITY SCANNER ENDPOINTS
# ============================================

@app.post("/scan")
async def scan_website(request: ScanRequest):
    """
    Main scan endpoint - analyzes a website for security issues
    """
    url = request.url.strip()
    
    # Validate URL
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Add https if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Run all security checks
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
        
        # Calculate overall risk score
        results["risk_score"] = calculate_risk_score(results["checks"])
        
        return results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# ============================================
# SCANNER FUNCTIONS
# ============================================

def check_ssl(domain: str) -> dict:
    """Check SSL/HTTPS status of a domain"""
    try:
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    "status": "secure",
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "unknown",
                    "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    "expires": cert['notAfter'],
                    "score": 100
                }
    except Exception as e:
        return {
            "status": "insecure",
            "error": str(e),
            "score": 0
        }

def check_headers(url: str) -> dict:
    """Check security headers of a website"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        # Important security headers to check
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy")
        }
        
        # Count present headers
        present = sum(1 for v in security_headers.values() if v is not None)
        total = len(security_headers)
        score = int((present / total) * 100)
        
        # Identify missing headers
        missing = [key for key, value in security_headers.items() if value is None]
        
        return {
            "status_code": response.status_code,
            "headers_present": present,
            "headers_total": total,
            "score": score,
            "present_headers": {k: v for k, v in security_headers.items() if v is not None},
            "missing_headers": missing,
            "server": headers.get("Server", "Unknown")
        }
    except Exception as e:
        return {
            "error": str(e),
            "score": 0
        }

def check_reachability(url: str) -> dict:
    """Check if website is reachable and get basic info"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        return {
            "reachable": True,
            "status_code": response.status_code,
            "response_time_ms": int(response.elapsed.total_seconds() * 1000),
            "final_url": response.url,
            "content_type": response.headers.get("Content-Type", "unknown"),
            "score": 100 if response.status_code == 200 else 50
        }
    except requests.exceptions.Timeout:
        return {
            "reachable": False,
            "error": "Request timed out",
            "score": 0
        }
    except Exception as e:
        return {
            "reachable": False,
            "error": str(e),
            "score": 0
        }

def calculate_risk_score(checks: dict) -> dict:
    """Calculate overall security risk score"""
    scores = []
    
    if "ssl" in checks and "score" in checks["ssl"]:
        scores.append(checks["ssl"]["score"])
    
    if "headers" in checks and "score" in checks["headers"]:
        scores.append(checks["headers"]["score"])
    
    if "reachability" in checks and "score" in checks["reachability"]:
        scores.append(checks["reachability"]["score"])
    
    if not scores:
        return {"score": 0, "grade": "F", "status": "unknown"}
    
    average = sum(scores) / len(scores)
    
    # Determine grade
    if average >= 90:
        grade = "A"
        status = "excellent"
    elif average >= 80:
        grade = "B"
        status = "good"
    elif average >= 70:
        grade = "C"
        status = "fair"
    elif average >= 60:
        grade = "D"
        status = "poor"
    else:
        grade = "F"
        status = "critical"
    
    return {
        "score": int(average),
        "grade": grade,
        "status": status,
        "total_checks": len(scores)
    }

# ============================================
# RUN THE SERVER (for local testing)
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
