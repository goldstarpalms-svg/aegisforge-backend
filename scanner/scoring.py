"""P8: Weighted scoring, P9: Confidence, P10: Detailed recommendations."""
from .config import SCORE_WEIGHTS

def calculate_weighted_score(checks: dict) -> dict:
    """Weighted scoring: SSL 20%, Headers 25%, HTTPS 15%, DNS 10%, Cookies 10%, Infra 10%, Best 10%."""
    scores = {}
    if "ssl" in checks and checks["ssl"].get("score") is not None:
        scores["ssl"] = checks["ssl"]["score"]
    if "headers" in checks and checks["headers"].get("score") is not None:
        scores["headers"] = checks["headers"]["score"]
    if "https_enforcement" in checks and checks["https_enforcement"].get("score") is not None:
        scores["https"] = checks["https_enforcement"]["score"]
    if "dns" in checks and checks["dns"].get("score") is not None:
        scores["dns"] = checks["dns"]["score"]
    if "cookies" in checks:
        cs = checks["cookies"].get("security_score", checks["cookies"].get("score"))
        if cs is not None:
            scores["cookies"] = cs
    # Infrastructure: CDN + reachability
    infra_scores = []
    if "cdn" in checks and checks["cdn"].get("score") is not None:
        infra_scores.append(checks["cdn"]["score"])
    if "reachability" in checks and checks["reachability"].get("score") is not None:
        infra_scores.append(checks["reachability"]["score"])
    if infra_scores:
        scores["infrastructure"] = sum(infra_scores) // len(infra_scores)
    # Best practices: security.txt + robots.txt + performance
    bp_scores = []
    if "security_txt" in checks and checks["security_txt"].get("score") is not None:
        bp_scores.append(checks["security_txt"]["score"])
    if "robots_txt" in checks and checks["robots_txt"].get("score") is not None:
        bp_scores.append(checks["robots_txt"]["score"])
    if "performance" in checks and checks["performance"].get("score") is not None:
        bp_scores.append(checks["performance"]["score"])
    if bp_scores:
        scores["best_practices"] = sum(bp_scores) // len(bp_scores)

    weighted = 0.0
    for category, weight in SCORE_WEIGHTS.items():
        if category in scores:
            weighted += scores[category] * weight
    final_score = int(weighted)
    if final_score >= 90:
        grade, status = "A", "excellent"
    elif final_score >= 80:
        grade, status = "B", "good"
    elif final_score >= 70:
        grade, status = "C", "fair"
    elif final_score >= 60:
        grade, status = "D", "poor"
    else:
        grade, status = "F", "critical"
    return {"score": final_score, "grade": grade, "status": status, "weighted_breakdown": scores, "total_checks": len(scores)}

def generate_detailed_recommendations(checks: dict) -> list[dict]:
    """P10: Each recommendation includes severity, business impact, fix, difficulty, time, reference."""
    recs = []
    # SSL
    ssl = checks.get("ssl", {})
    if ssl.get("status") != "secure":
        recs.append({"priority": "critical", "category": "SSL/TLS", "issue": "Website not using HTTPS",
                     "business_impact": "Data intercepted in transit; browsers show warnings; SEO penalty.",
                     "fix": "Install SSL certificate and enable HTTPS. Use Let's Encrypt for free certificates.",
                     "difficulty": "Easy", "estimated_time": "15 minutes", "reference": "https://letsencrypt.org/",
                     "confidence": "high"})
    elif ssl.get("days_until_expiry", 999) < 30:
        recs.append({"priority": "high", "category": "SSL/TLS", "issue": f"Certificate expires in {ssl.get('days_until_expiry')} days",
                     "business_impact": "Site will become inaccessible; browsers will block it.",
                     "fix": "Renew your SSL certificate before it expires. Set up auto-renewal with certbot.",
                     "difficulty": "Easy", "estimated_time": "10 minutes", "reference": "https://certbot.eff.org/",
                     "confidence": "high"})
    # Headers
    missing = checks.get("headers", {}).get("missing_headers", [])
    for hdr in missing:
        recs.append({"priority": "medium", "category": "Headers", "issue": f"Missing {hdr} header",
                     "business_impact": "Browser cannot enforce security policy for this aspect.",
                     "fix": f"Add {hdr} to your server configuration.",
                     "difficulty": "Easy", "estimated_time": "5 minutes",
                     "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/" + hdr,
                     "confidence": "high"})
    # HTTPS
    https = checks.get("https_enforcement", {})
    if https.get("enforces_https") is False:
        recs.append({"priority": "critical", "category": "HTTPS", "issue": "HTTP not redirecting to HTTPS",
                     "business_impact": "Users can access insecure version; data exposure risk.",
                     "fix": "Configure 301 redirect from HTTP to HTTPS in your web server.",
                     "difficulty": "Easy", "estimated_time": "10 minutes",
                     "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_Strict_Transport_Security",
                     "confidence": "high"})
    # CDN
    cdn = checks.get("cdn", {})
    if not cdn.get("using_cdn"):
        recs.append({"priority": "low", "category": "Infrastructure", "issue": "No CDN detected",
                     "business_impact": "Slower load times for distant users; less DDoS protection.",
                     "fix": "Consider Cloudflare (free tier) for CDN and basic DDoS protection.",
                     "difficulty": "Easy", "estimated_time": "30 minutes", "reference": "https://www.cloudflare.com/",
                     "confidence": cdn.get("confidence", "medium")})
    # security.txt
    if not checks.get("security_txt", {}).get("found"):
        recs.append({"priority": "low", "category": "Best Practices", "issue": "Missing security.txt",
                     "business_impact": "No clear channel for vulnerability disclosure.",
                     "fix": "Add /.well-known/security.txt with a Contact directive.",
                     "difficulty": "Easy", "estimated_time": "10 minutes",
                     "reference": "https://securitytxt.org/", "confidence": "high"})
    return recs
