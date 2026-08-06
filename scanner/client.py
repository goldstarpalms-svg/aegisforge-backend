"""Shared async httpx client with retry + SSRF validation."""
import httpx, asyncio, re, socket
from ipaddress import ip_address as ipaddr
from urllib.parse import urlparse, urlunparse
from fastapi import HTTPException
from .config import REQUEST_TIMEOUT, MAX_RESPONSE_BYTES, MAX_REDIRECTS

_async_client: httpx.AsyncClient | None = None

async def get_client() -> httpx.AsyncClient:
    global _async_client
    if _async_client is None or _async_client.is_closed:
        _async_client = httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5),
            follow_redirects=True, max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": "AegisForgeAI-Scanner/2.1 (+https://aegisforge.ai)"},
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
        )
    return _async_client

async def safe_get(url: str, *, follow_redirects: bool = True, retries: int = 2) -> httpx.Response:
    client = await get_client()
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, follow_redirects=follow_redirects)
            if len(r.content) > MAX_RESPONSE_BYTES:
                r._content = r.content[:MAX_RESPONSE_BYTES]
            return r
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt == retries:
                raise
            await asyncio.sleep(0.3 * (2 ** attempt))
    raise httpx.HTTPError("Max retries exceeded")

def normalize_scan_target(raw: str) -> tuple[str, str]:
    url = (raw or "").strip()
    if not url:
        raise HTTPException(400, "URL is required")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(400, "Only HTTP/HTTPS supported")
    if not parsed.hostname:
        raise HTTPException(400, "Valid hostname required")
    if parsed.username or parsed.password:
        raise HTTPException(400, "No embedded credentials")
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(400, "Invalid port")
    hostname = parsed.hostname.strip().rstrip(".").lower()
    if not hostname or hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        raise HTTPException(400, "Localhost not allowed")
    try:
        hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(400, "Invalid hostname")
    # Block private IPs
    try:
        resolved = [ipaddr(hostname)]
    except ValueError:
        try:
            ai = socket.getaddrinfo(hostname, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            resolved = []
            for item in ai:
                try:
                    resolved.append(ipaddr(item[4][0]))
                except ValueError:
                    continue
        except socket.gaierror:
            raise HTTPException(400, "Hostname could not be resolved")
    if not resolved:
        raise HTTPException(400, "Hostname could not be resolved")
    for ip_obj in resolved:
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            raise HTTPException(400, "Private/internal targets not allowed")
    normalized = urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.params, parsed.query, ""))
    return normalized, hostname
