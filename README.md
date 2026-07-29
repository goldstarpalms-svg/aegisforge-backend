# AegisForge AI Backend

FastAPI backend for AegisForge AI.

It powers:

- Website security scanning with DNS, security.txt, robots.txt, SSL, header, cookie, CDN, HTTPS, and performance checks
- Waitlist signup
- Supabase waitlist storage and position tracking
- Resend welcome emails

## Main endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | API welcome and endpoint list |
| `GET` | `/health` | Health/config check |
| `POST` | `/waitlist` | Store waitlist email and send confirmation email |
| `GET` | `/waitlist/stats` | Public waitlist count and remaining founder spots |
| `POST` | `/preview/generate` | No-cost smart app/website preview generator |
| `GET` | `/admin/waitlist/stats` | Admin waitlist stats, protected by `ADMIN_API_KEY` |
| `GET` | `/admin/waitlist/export.csv` | Admin waitlist CSV export, protected by `ADMIN_API_KEY` |
| `GET` | `/admin/previews/export.csv` | Admin preview request CSV export, protected by `ADMIN_API_KEY` |
| `POST` | `/scan` | Full website security scan |
| `POST` | `/quick-scan` | Basic SSL/header/reachability scan |
| `GET` | `/docs` | FastAPI Swagger docs |

## Required environment variables

See `.env.example` for a copyable template.

Set these in Render or your backend hosting platform.

### Email delivery

```env
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxx
FROM_EMAIL=AegisForge AI <onboarding@resend.dev>
```

For production, verify your domain in Resend and use something like:

```env
FROM_EMAIL=AegisForge AI <waitlist@yourdomain.com>
```

### Supabase waitlist storage

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
WAITLIST_TABLE=waitlist
PREVIEW_REQUESTS_TABLE=preview_requests
```

`WAITLIST_TABLE` is optional. It defaults to `waitlist`.

Important: use the Supabase `service_role` key only on the backend. Never expose it in frontend code.

### Admin and rate limiting

```env
ADMIN_API_KEY=choose_a_long_random_secret
RATE_LIMIT_WINDOW_SECONDS=3600
WAITLIST_RATE_LIMIT=5
SCAN_RATE_LIMIT=10
QUICK_SCAN_RATE_LIMIT=20
```

`ADMIN_API_KEY` protects admin endpoints. Send it as the `x-admin-key` header, or as `?admin_key=...` for quick browser testing.

Example CSV export:

```bash
curl -H "x-admin-key: $ADMIN_API_KEY" https://aegisforge-backend.onrender.com/admin/waitlist/export.csv -o waitlist.csv
```

## Supabase setup

Run the SQL in `SUPABASE_WAITLIST_SETUP.sql` from the Supabase SQL Editor.

Expected `waitlist` table columns:

- `id`
- `email`
- `source`
- `created_at`

Expected `preview_requests` table columns:

- `id`
- `idea`
- `project_type`
- `detected_category`
- `generated_name`
- `created_at`

## Abuse protection

The backend includes simple in-memory per-IP rate limiting for waitlist and scanner endpoints. This is enough for basic protection on a single Render instance. For multi-instance production scaling, replace it with Redis-backed rate limiting.

## Scanner security protections

The scanner validates targets before making outbound requests. It blocks:

- localhost
- loopback IPs
- private/internal IP ranges
- link-local/reserved/unspecified IPs
- unsupported schemes like `ftp://`
- URLs with embedded credentials
- unsafe redirect targets

## Current scanner checks

The full `/scan` endpoint currently analyzes:

- SSL/TLS certificate health
- Security headers
- Reachability and response time
- Technology stack disclosure
- Cookie security
- CDN detection
- Redirect chain
- HTTPS enforcement
- Performance timing
- DNS resolution
- `/.well-known/security.txt`
- `/robots.txt`

## Local development

Install dependencies:

```bash
pip install -r requirements.txt
```

Run locally:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/health
```

## Deployment

This repo includes a Render-compatible `Procfile`:

```txt
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

## No-cost Smart Preview Engine

`POST /preview/generate` creates an app or website concept preview without calling paid AI APIs. It uses keyword detection, templates, and rule-based logic to return:

- category and layout
- product name and tagline
- roles
- features
- pages/screens
- database plan
- security checklist
- monetization ideas
- launch plan

This gives visitors a useful preview while the full AI modules are still coming soon.

Preview requests are stored best-effort in Supabase when `PREVIEW_REQUESTS_TABLE` exists. If storage fails, preview generation still works.
