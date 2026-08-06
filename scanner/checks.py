"""All scanner check functions — P1 through P7."""
import ssl, socket, time
import dns.resolver
from ipwhois import IPWhois
from datetime import datetime
from .config import *
from .client import safe_get

# ── P1: HTTPS Redirect (follows full chain) ──
async def check_https_redirect(domain: str) -> dict:
    try:
        d = domain.split(":")[0]
        r = await safe_get(f"http://{d}", follow_redirects=False)
        if r.status_code in {301, 302, 303, 307, 308}:
            loc = r.headers.get("location", "")
            if loc.startswith("https://"):
                return {"enforces_https": True, "http_status_code": r.status_code, "redirect_location": loc, "score": 100, "confidence": "high"}
            r2 = await safe_get(f"http://{d}", follow_redirects=True)
            if r2.url.scheme == "https":
                return {"enforces_https": True, "http_status_code": r.status_code, "redirect_location": str(r2.url), "score": 100, "confidence": "high"}
            return {"enforces_https": False, "http_status_code": r.status_code, "redirect_location": loc, "score": 0, "confidence": "high"}
        try:
            r3 = await safe_get(f"https://{d}", follow_redirects=True)
            if r3.status_code < 400:
                return {"enforces_https": False, "http_status_code": r.status_code, "note": "HTTP accessible without redirect", "score": 40, "confidence": "high"}
        except Exception:
            pass
        return {"enforces_https": False, "http_status_code": r.status_code, "score": 0, "confidence": "medium"}
    except Exception as e:
        return {"enforces_https": None, "error": str(e), "score": 50, "confidence": "low"}

# ── P2: CDN Detection (headers + ASN) ──
async def check_cdn(url: str, domain: str) -> dict:
    cdns = []
    confidence = "medium"
    try:
        r = await safe_get(url)
        h_str = " ".join(f"{k}:{v}" for k, v in r.headers.multi_items()).lower()
        for name, keys in CDN_HEADER_MAP.items():
            for k in keys:
                if k.lower() in h_str:
                    if name not in cdns:
                        cdns.append(name)
                    break
    except Exception:
        pass
    if not cdns:
        try:
            d = domain.split(":")[0]
            cached = DNS_CACHE.get(f"asn:{d}")
            if cached and cached != "none":
                cdns.append(cached)
            elif cached is None:
                ips = socket.getaddrinfo(d, None, type=socket.SOCK_STREAM)
                ip = ips[0][4][0] if ips else None
                if ip:
                    try:
                        res = IPWhois(ip).lookup_rdap(depth=1)
                        asn = res.get("asn")
                        if asn and str(asn).isdigit():
                            cdn_name = CDN_ASN_MAP.get(int(asn))
                            if cdn_name and cdn_name not in cdns:
                                cdns.append(cdn_name)
                            DNS_CACHE[f"asn:{d}"] = cdn_name or "none"
                        else:
                            DNS_CACHE[f"asn:{d}"] = "none"
                    except Exception:
                        DNS_CACHE[f"asn:{d}"] = "none"
        except Exception:
            pass
    if cdns:
        confidence = "high"
    else:
        confidence = "low"
    return {"using_cdn": len(cdns) > 0, "cdns_detected": cdns or ["Unable to determine"], "confidence": confidence, "score": 100 if cdns else 50}

# ── P3: Security Headers (9 headers) ──
async def check_headers(url: str) -> dict:
    try:
        r = await safe_get(url)
        h = r.headers
        present = {}; missing = []; details = []
        for hdr in REQUIRED_HEADERS:
            val = h.get(hdr)
            if val:
                present[hdr] = val
                details.append({"header": hdr, "status": "present", "value": val[:120]})
            elif hdr in OPTIONAL_HEADERS:
                details.append({"header": hdr, "status": "not_applicable", "value": None})
            else:
                missing.append(hdr)
                details.append({"header": hdr, "status": "missing", "value": None})
        req_count = len([h for h in REQUIRED_HEADERS if h not in OPTIONAL_HEADERS])
        req_present = len([h for h in present if h not in OPTIONAL_HEADERS])
        score = int((req_present / max(req_count, 1)) * 100)
        grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
        return {"status_code": r.status_code, "headers_present": len(present), "headers_total": len(REQUIRED_HEADERS),
                "score": score, "grade": grade, "present_headers": present, "missing_headers": missing,
                "header_details": details, "server": h.get("server", "Unknown"), "confidence": "high"}
    except Exception as e:
        return {"error": str(e), "score": 0, "confidence": "low"}

# ── P4: SSL/TLS (signature algorithm + chain) ──
def check_ssl(domain: str) -> dict:
    try:
        d = domain.split(":")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((d, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=d) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
                sig_alg = "Unknown"
                if der:
                    try:
                        from cryptography import x509
                        c = x509.load_der_x509_certificate(der)
                        sig_alg = c.signature_algorithm_oid._name
                    except Exception:
                        pass
                chain = [dict(x[0]).get('commonName', '?') for x in cert.get('issuer', [])]
                return {"status": "secure", "protocol": ssock.version(), "cipher": ssock.cipher()[0] if ssock.cipher() else "unknown",
                        "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                        "subject": dict(x[0] for x in cert['subject']).get('commonName', 'Unknown'),
                        "expires": cert['notAfter'], "days_until_expiry": days_left, "expiry_warning": days_left < 30,
                        "signature_algorithm": sig_alg, "chain": chain[:5],
                        "score": 100 if days_left > 30 else 60 if days_left > 0 else 0, "confidence": "high"}
    except Exception as e:
        return {"status": "insecure", "error": str(e), "score": 0, "confidence": "high"}

# ── P5: DNS Security ──
def check_dns_security(domain: str) -> dict:
    d = domain.split(":")[0]
    results = {}; score = 50
    for rtype, key in [("A", "a_records"), ("AAAA", "aaaa_records")]:
        try:
            ans = dns.resolver.resolve(d, rtype)
            results[key] = [str(r) for r in ans][:5]
            if rtype == "A":
                score = 80
        except Exception:
            results[key] = []
    try:
        ans = dns.resolver.resolve(d, "MX")
        results["mx_records"] = [f"{r.preference} {r.exchange}" for r in ans][:5]
    except Exception:
        results["mx_records"] = []
    # SPF
    try:
        ans = dns.resolver.resolve(d, "TXT")
        for r in ans:
            if "v=spf1" in str(r).lower():
                results["spf"] = str(r); score += 5; break
        if "spf" not in results:
            results["spf"] = None
    except Exception:
        results["spf"] = None
    # DMARC
    try:
        ans = dns.resolver.resolve(f"_dmarc.{d}", "TXT")
        for r in ans:
            if "v=dmarc1" in str(r).lower():
                results["dmarc"] = str(r); score += 5; break
        if "dmarc" not in results:
            results["dmarc"] = None
    except Exception:
        results["dmarc"] = None
    # DKIM
    results["dkim"] = None
    for sel in ["default", "google", "selector1", "s1"]:
        try:
            ans = dns.resolver.resolve(f"{sel}._domainkey.{d}", "TXT")
            for r in ans:
                if "v=dkim1" in str(r).lower() or "k=" in str(r).lower():
                    results["dkim"] = f"{sel}: {str(r)[:80]}"; score += 3; break
            if results["dkim"]:
                break
        except Exception:
            continue
    # CAA
    try:
        ans = dns.resolver.resolve(d, "CAA")
        results["caa"] = [str(r) for r in ans][:3]; score += 2
    except Exception:
        results["caa"] = []
    results["score"] = min(score, 100)
    results["confidence"] = "high" if results.get("a_records") else "low"
    return results

def check_dns(domain: str) -> dict:
    d = domain.split(":")[0]
    try:
        ai = socket.getaddrinfo(d, None, type=socket.SOCK_STREAM)
        ipv4 = sorted({i[4][0] for i in ai if i[0] == socket.AF_INET})
        ipv6 = sorted({i[4][0] for i in ai if i[0] == socket.AF_INET6})
        return {"resolves": bool(ipv4 or ipv6), "ipv4_addresses": ipv4[:10], "ipv6_addresses": ipv6[:10],
                "ipv4_count": len(ipv4), "ipv6_count": len(ipv6), "score": 100, "confidence": "high"}
    except Exception as e:
        return {"resolves": False, "error": str(e), "score": 0, "confidence": "low"}

# ── P6: Technology Detection (Wappalyzer + fingerprints) ──
async def detect_tech_stack(url: str) -> dict:
    detected = {"server": "Unknown", "powered_by": "Not disclosed", "frameworks": [], "cms": None, "analytics": [], "libraries": []}
    score = 70; confidence = "medium"
    try:
        r = await safe_get(url)
        h = r.headers; html = r.text.lower()
        detected["server"] = h.get("server", "Unknown")
        detected["powered_by"] = h.get("x-powered-by", "Not disclosed")
        try:
            from Wappalyzer import Wappalyzer as WLib, WebPage
            wp = WebPage.new_from_response(r)
            techs = WLib.latest().analyze(wp)
            for name in techs:
                nl = name.lower()
                if any(x in nl for x in ["react", "next", "vue", "angular"]):
                    if name not in detected["frameworks"]:
                        detected["frameworks"].append(name)
                elif any(x in nl for x in ["wordpress", "drupal", "shopify"]):
                    if not detected["cms"]:
                        detected["cms"] = name
        except Exception:
            pass
        # Custom fallback
        if "wp-content" in html and not detected["cms"]:
            detected["cms"] = "WordPress"
        if "drupal" in html and not detected["cms"]:
            detected["cms"] = "Drupal"
        if "shopify" in html and not detected["cms"]:
            detected["cms"] = "Shopify"
        if ("react" in html or "_next" in html) and "React/Next.js" not in detected["frameworks"]:
            detected["frameworks"].append("React/Next.js")
        if ("vue" in html or "nuxt" in html) and "Vue/Nuxt" not in detected["frameworks"]:
            detected["frameworks"].append("Vue/Nuxt")
        if "angular" in html and "Angular" not in detected["frameworks"]:
            detected["frameworks"].append("Angular")
        if "google-analytics" in html or "gtag" in html:
            detected["analytics"].append("Google Analytics")
        if "jquery" in html and "jQuery" not in detected["libraries"]:
            detected["libraries"].append("jQuery")
        if "tailwind" in html and "Tailwind" not in detected["libraries"]:
            detected["libraries"].append("Tailwind CSS")
        penalty = 0
        if detected["server"] not in ("Unknown", "Not disclosed"):
            penalty += 8
        if detected["powered_by"] != "Not disclosed":
            penalty += 12
        score = max(50, 100 - penalty)
    except Exception as e:
        detected["error"] = str(e); score = 0; confidence = "low"
    return {"detected": detected, "score": score, "confidence": confidence}

# ── P7: Cookie Analysis ──
async def analyze_cookies(url: str) -> dict:
    try:
        r = await safe_get(url)
        cookies = []; secure_c = 0; httponly_c = 0; samesite_c = 0; tracking_c = 0
        tracking = ['_ga', '_gid', '_fbp', '_utm', 'ajs_', 'mp_']
        for c in r.cookies.jar:
            is_tracking = any(t in c.name.lower() for t in tracking)
            if is_tracking:
                tracking_c += 1
            if c.secure:
                secure_c += 1
            cookies.append({"name": c.name, "domain": c.domain, "secure": c.secure, "is_tracking": is_tracking})
        for k, v in r.headers.multi_items():
            if k.lower() == "set-cookie":
                vl = v.lower()
                if "httponly" in vl:
                    httponly_c += 1
                if "samesite" in vl:
                    samesite_c += 1
        total = max(len(cookies), 1)
        sec_score = int((secure_c / total) * 50 + (httponly_c / total) * 30 + (samesite_c / total) * 20)
        return {"total_cookies": len(cookies), "secure_cookies": secure_c, "httponly_cookies": httponly_c,
                "samesite_cookies": samesite_c, "tracking_cookies": tracking_c, "cookies": cookies[:10],
                "security_score": sec_score, "confidence": "high"}
    except Exception as e:
        return {"error": str(e), "security_score": 0, "confidence": "low"}

# ── Reachability ──
async def check_reachability(url: str) -> dict:
    try:
        s = time.time(); r = await safe_get(url); ms = round((time.time() - s) * 1000)
        return {"reachable": True, "status_code": r.status_code, "response_time_ms": ms,
                "final_url": str(r.url), "content_type": r.headers.get("content-type", "unknown"),
                "score": 100 if r.status_code == 200 else 50, "confidence": "high"}
    except Exception as e:
        return {"reachable": False, "error": str(e), "score": 0, "confidence": "medium"}

# ── Performance ──
async def check_performance(url: str) -> dict:
    try:
        s1 = time.time(); r1 = await safe_get(url); t1 = round((time.time() - s1) * 1000)
        s2 = time.time(); _ = await safe_get(url); t2 = round((time.time() - s2) * 1000)
        sz = round(len(r1.content) / 1024, 2)
        g = "A" if t1 < 500 else "B" if t1 < 1000 else "C" if t1 < 2000 else "D" if t1 < 3000 else "F"
        return {"first_load_ms": t1, "cached_load_ms": t2, "content_size_kb": sz, "grade": g,
                "score": max(0, 100 - (t1 // 30)), "confidence": "medium"}
    except Exception as e:
        return {"error": str(e), "score": 0, "confidence": "low"}

# ── security.txt / robots.txt ──
async def check_security_txt(url: str) -> dict:
    try:
        from urllib.parse import urlparse
        o = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for loc in [f"{o}/.well-known/security.txt", f"{o}/security.txt"]:
            try:
                r = await safe_get(loc)
                if r.status_code == 200 and "Contact:" in r.text[:5000]:
                    t = r.text[:5000]
                    return {"found": True, "url": loc, "has_contact": "Contact:" in t,
                            "has_expires": "Expires:" in t, "has_policy": "Policy:" in t,
                            "score": 100, "confidence": "high"}
            except Exception:
                continue
        return {"found": False, "score": 40, "confidence": "medium"}
    except Exception as e:
        return {"found": False, "error": str(e), "score": 40, "confidence": "low"}

async def check_robots_txt(url: str) -> dict:
    try:
        from urllib.parse import urlparse
        o = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        r = await safe_get(f"{o}/robots.txt")
        found = r.status_code == 200
        t = r.text[:5000] if found else ""
        return {"found": found, "has_sitemap": "sitemap:" in t.lower(), "has_disallow": "disallow:" in t.lower(),
                "score": 100 if found else 70, "confidence": "high"}
    except Exception as e:
        return {"found": False, "error": str(e), "score": 70, "confidence": "low"}
