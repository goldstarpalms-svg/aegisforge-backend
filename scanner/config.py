import os

REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 2_000_000
MAX_REDIRECTS = 8
DNS_CACHE: dict = {}

SCORE_WEIGHTS = {
    "ssl": 0.20, "headers": 0.25, "https": 0.15,
    "dns": 0.10, "cookies": 0.10, "infrastructure": 0.10, "best_practices": 0.10,
}

REQUIRED_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
]
OPTIONAL_HEADERS = {"permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"}

CDN_HEADER_MAP = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "Akamai": ["x-akamai-transformed"],
    "AWS CloudFront": ["x-amz-cf-id"],
    "Fastly": ["x-served-by"],
    "Vercel": ["x-vercel-id"],
    "Netlify": ["x-nf-request-id"],
    "Google Cloud": ["x-goog-request-id"],
    "Azure CDN": ["x-azure-ref"],
}

CDN_ASN_MAP = {
    13335: "Cloudflare", 20940: "Akamai", 16509: "Amazon/CloudFront",
    54113: "Fastly", 19551: "Vercel", 15133: "Azure CDN",
    8075: "Microsoft/Azure", 15169: "Google", 36040: "Google",
}
