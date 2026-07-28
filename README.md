# AegisForge AI Backend

FastAPI backend for AegisForge AI.

It powers:

- Website security scanning
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
| `GET` | `/admin/waitlist/stats` | Admin waitlist stats, protected by `ADMIN_API_KEY` |
| `GET` | `/admin/waitlist/export.csv` | Admin CSV export, protected by `ADMIN_API_KEY` |
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

Expected table columns:

- `id`
- `email`
- `source`
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
