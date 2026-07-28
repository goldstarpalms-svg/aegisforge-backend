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
| `POST` | `/scan` | Full website security scan |
| `POST` | `/quick-scan` | Basic SSL/header/reachability scan |
| `GET` | `/docs` | FastAPI Swagger docs |

## Required environment variables

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

## Supabase setup

Run the SQL in `SUPABASE_WAITLIST_SETUP.sql` from the Supabase SQL Editor.

Expected table columns:

- `id`
- `email`
- `source`
- `created_at`

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
