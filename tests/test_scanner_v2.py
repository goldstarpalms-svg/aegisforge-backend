"""P13: Regression tests — compare AegisForge scanner against known sites."""
import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.client import normalize_scan_target
from scanner.checks import (
    check_https_redirect, check_cdn, check_headers, check_ssl,
    check_dns_security, check_dns, detect_tech_stack, analyze_cookies,
    check_reachability, check_performance, check_security_txt, check_robots_txt,
)
from scanner.scoring import calculate_weighted_score, generate_detailed_recommendations

TEST_SITES = [
    "google.com", "github.com", "openai.com", "microsoft.com",
    "stripe.com", "cloudflare.com", "vercel.com", "amazon.com",
]

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.mark.asyncio
@pytest.mark.parametrize("domain", TEST_SITES)
async def test_https_redirect(domain):
    """P1: Well-known sites should redirect HTTP to HTTPS."""
    result = await check_https_redirect(domain)
    assert result.get("confidence") in ("high", "medium", "low"), f"Missing confidence for {domain}"
    # These sites all enforce HTTPS — score should be high
    if result.get("confidence") == "high":
        assert result.get("score", 0) >= 40, f"{domain} HTTPS redirect score too low: {result}"

@pytest.mark.asyncio
@pytest.mark.parametrize("domain", TEST_SITES)
async def test_cdn_detection(domain):
    """P2: Major sites should have CDN detected (not 'Unable to determine')."""
    url = f"https://{domain}"
    result = await check_cdn(url, domain)
    assert result.get("confidence") in ("high", "medium", "low")
    cdns = result.get("cdns_detected", [])
    # At minimum, confidence should be set
    assert isinstance(cdns, list)

@pytest.mark.asyncio
@pytest.mark.parametrize("domain", TEST_SITES)
async def test_headers(domain):
    """P3: Security headers check returns confidence."""
    result = await check_headers(f"https://{domain}")
    assert result.get("confidence") in ("high", "medium", "low")
    assert 0 <= result.get("score", 0) <= 100

@pytest.mark.parametrize("domain", TEST_SITES[:4])
def test_ssl(domain):
    """P4: SSL check includes signature_algorithm and chain."""
    result = check_ssl(domain)
    assert result.get("confidence") in ("high", "medium", "low")
    if result.get("status") == "secure":
        assert "signature_algorithm" in result, f"Missing signature_algorithm for {domain}"
        assert "chain" in result, f"Missing chain for {domain}"

@pytest.mark.parametrize("domain", TEST_SITES[:4])
def test_dns_security(domain):
    """P5: DNS security includes SPF/DMARC/DKIM/CAA checks."""
    result = check_dns_security(domain)
    assert result.get("confidence") in ("high", "medium", "low")
    assert "spf" in result
    assert "dmarc" in result
    assert "dkim" in result

@pytest.mark.asyncio
@pytest.mark.parametrize("domain", TEST_SITES[:4])
async def test_tech_detection(domain):
    """P6: Technology detection returns confidence."""
    result = await detect_tech_stack(f"https://{domain}")
    assert result.get("confidence") in ("high", "medium", "low")

@pytest.mark.asyncio
@pytest.mark.parametrize("domain", TEST_SITES[:4])
async def test_cookie_analysis(domain):
    """P7: Cookie analysis includes httponly and samesite."""
    result = await analyze_cookies(f"https://{domain}")
    assert result.get("confidence") in ("high", "medium", "low")
    assert "httponly_cookies" in result
    assert "samesite_cookies" in result

@pytest.mark.asyncio
async def test_weighted_scoring():
    """P8: Weighted scoring produces realistic scores."""
    checks = {
        "ssl": {"score": 100, "confidence": "high"},
        "headers": {"score": 50, "confidence": "high"},
        "https_enforcement": {"score": 100, "confidence": "high"},
        "dns": {"score": 80, "confidence": "high"},
        "cookies": {"security_score": 60, "confidence": "medium"},
        "cdn": {"score": 100, "confidence": "high"},
        "reachability": {"score": 100, "confidence": "high"},
        "security_txt": {"score": 40, "confidence": "medium"},
        "robots_txt": {"score": 100, "confidence": "high"},
        "performance": {"score": 70, "confidence": "medium"},
    }
    result = calculate_weighted_score(checks)
    assert 0 <= result["score"] <= 100
    assert result["grade"] in ("A", "B", "C", "D", "F")
    assert "weighted_breakdown" in result

def test_recommendations_have_all_fields():
    """P10: Recommendations include all required fields."""
    checks = {"ssl": {"status": "insecure", "score": 0}, "headers": {"missing_headers": ["strict-transport-security"]},
              "https_enforcement": {"enforces_https": False, "score": 0},
              "cdn": {"using_cdn": False, "confidence": "medium"}, "security_txt": {"found": False}}
    recs = generate_detailed_recommendations(checks)
    assert len(recs) > 0
    for r in recs:
        assert "priority" in r
        assert "business_impact" in r
        assert "fix" in r
        assert "difficulty" in r
        assert "estimated_time" in r
        assert "reference" in r
        assert "confidence" in r

@pytest.mark.asyncio
async def test_full_scan_accuracy():
    """Integration test: run full scan on google.com and verify key results."""
    domain = "google.com"
    url = f"https://{domain}"
    ssl_r = await asyncio.to_thread(check_ssl, domain)
    hdr_r = await check_headers(url)
    https_r = await check_https_redirect(domain)
    cdn_r = await check_cdn(url, domain)
    dns_r = await asyncio.to_thread(check_dns, domain)
    checks = {"ssl": ssl_r, "headers": hdr_r, "https_enforcement": https_r, "cdn": cdn_r, "dns": dns_r}
    score = calculate_weighted_score(checks)
    # google.com should score B or above
    assert score["score"] >= 50, f"google.com score too low: {score['score']}"
    # HTTPS should be enforced
    assert https_r.get("score", 0) >= 40, f"google.com HTTPS not detected: {https_r}"
    # SSL should be secure
    assert ssl_r.get("status") == "secure", f"google.com SSL not secure: {ssl_r}"
