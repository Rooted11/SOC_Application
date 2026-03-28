# Ataraxia (AI-Powered SOC)

Ataraxia is a full-stack SOC prototype with FastAPI + PostgreSQL on the backend, React + Vite on the frontend, AI-assisted investigation, automated playbooks, threat intel correlation, optional TOTP MFA, and in-memory rate limiting. It ships with both a local dev stack and a hardened production stack fronted by an HTTPS reverse proxy.

## Features
- AI/ML anomaly detection over log streams with incident auto-creation
- Automated playbooks (isolate host, revoke credentials, block IP, send alert)
- Threat intel ingestion and correlation across IP/domain/hash/user artifacts
- Operator auth with bearer tokens, optional TOTP MFA, and login/API rate limiting
- Hardened production stack: nginx frontend, backend and DB not publicly exposed, TLS-ready reverse proxy example
- React Command Center with incidents, trends, threat intel, and AI advisor

## Stack
- Backend: FastAPI, SQLAlchemy, PostgreSQL, Isolation Forest ML
- Frontend: React, Vite, Tailwind, nginx (prod)
- Infrastructure: Docker Compose (dev + prod), optional Caddy reverse proxy

## Endpoint Targeting (Windows vs Ubuntu vs Docker)
- Windows host (VS/Vite, PowerShell scripts): call the backend at http://192.168.56.101:8000. The Vite dev server still runs at http://localhost:3000 on Windows.
- Ubuntu VM itself: backend http://localhost:8000, frontend http://localhost:3000.
- Inside Docker Compose: use service names (e.g., backend:8000, db:5432, redis:6379); avoid localhost or the VM IP for container-to-container calls.

## Dev Quickstart
1. Prereqs: Docker Desktop, Git; Python 3.10+ optional for running scripts directly.
2. Enter the project: `cd ai-soc`.
3. Start the dev stack:  
   ```
   docker compose up --build
   ```
4. Seed sample data (from another terminal):  
   ```
   docker compose exec backend python /data/../scripts/init_db.py
   ```
   or locally:  
   ```
   python scripts/init_db.py
   ```
5. Open the UI: from Windows use http://192.168.56.101:3000 when the frontend runs in Docker on the VM; if you run `npm run dev` locally on Windows, it stays at http://localhost:3000.
6. Simulate logs:  
   ```
   python scripts/simulate_logs.py --once --count 20
   python scripts/simulate_logs.py --interval 2 --count 5
   ```
7. Refresh the threat feed:  
   ```
   # Windows host -> Ubuntu backend
   python scripts/simulate_threat_feed.py --count 50 --push-url http://192.168.56.101:8000
   # On the Ubuntu VM itself, keep localhost
   # python scripts/simulate_threat_feed.py --count 50 --push-url http://localhost:8000
   ```
> Running the backend directly (outside Docker)? Start it on the Ubuntu VM with `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload` so the Windows browser can reach it.

## Tests
- Backend: `docker compose exec backend python -m unittest tests.test_api_smoke tests.test_security`
- Frontend build: `docker compose exec frontend npm run build`

## Event-Driven Mode (Redis Streams)
- Redis is bundled in both dev/prod compose files; the worker service consumes the log stream.
- Dev defaults to synchronous processing; turn on streaming by setting `USE_REDIS_STREAMS=true` (and `REDIS_URL` if different) for the backend and worker.
- In this repo, dev compose is now streaming-enabled by default; set `USE_REDIS_STREAMS=false` if you want the legacy inline path.
- With streaming enabled, `/api/logs/ingest` queues to Redis and returns 202; the worker handles scoring, correlation, incident creation, and playbooks.
- In prod compose, streaming is on by default.

## Production Deployment (Hardened)
1. Create a prod env file:  
   ```
   cp .env.production.example .env.production
   ```  
   Set strong values for `POSTGRES_PASSWORD`, `AUTH_PASSWORD`, `AUTH_TOKEN_SECRET`, `ALLOWED_HOSTS`, and `AUTH_TOTP_SECRET` if MFA is enabled.
   Generate a TOTP secret if needed:  
   ```
   python scripts/generate_mfa_secret.py --account soc_operator --issuer "Ataraxia"
   ```
2. Start the production stack (frontend bound to localhost only):  
   ```
   docker compose --env-file .env.production -f docker-compose.prod.yml up --build -d
   ```
3. Put HTTPS in front: terminate TLS on the host and proxy to `127.0.0.1:${PUBLIC_PORT:-3000}`. An example Caddy config is in `deploy/Caddyfile.example` and can be run with `caddy run --config deploy/Caddyfile.example` after updating the hostname.
4. Sign in at http://localhost:3000 using `AUTH_USERNAME` and `AUTH_PASSWORD`; if `AUTH_MFA_ENABLED=true`, enter the 6-digit TOTP code.

## Security Defaults
- Production enables bearer auth; dev keeps auth disabled.
- Optional TOTP MFA; login payload accepts `otp_code`.
- In-memory rate limiting by default (single-instance): `API_RATE_LIMIT_REQUESTS=300` per `API_RATE_LIMIT_WINDOW_SECONDS=60`; login limit `LOGIN_RATE_LIMIT_ATTEMPTS=5` per `LOGIN_RATE_LIMIT_WINDOW_SECONDS=300`.
- API docs disabled in production (`ENABLE_API_DOCS=false`).
- Backend and PostgreSQL are not published externally in prod; only nginx is exposed on localhost for a reverse proxy.
- Frontend nginx sets CSP, Permissions-Policy, server_tokens off, and forwards `X-Forwarded-*` headers.

## Config Cheatsheet (env vars)
- `AUTH_ENABLED` toggles auth (default true in prod).
- `AUTH_USERNAME` / `AUTH_PASSWORD` operator credentials.
- `AUTH_TOKEN_SECRET` HMAC secret for JWTs.
- `AUTH_TOKEN_TTL_MINUTES` token lifetime.
- `AUTH_MFA_ENABLED` enable TOTP; `AUTH_TOTP_SECRET` base32 secret; `AUTH_TOTP_ISSUER` app label.
- `RATE_LIMIT_ENABLED`, `API_RATE_LIMIT_REQUESTS`, `API_RATE_LIMIT_WINDOW_SECONDS`, `LOGIN_RATE_LIMIT_ATTEMPTS`, `LOGIN_RATE_LIMIT_WINDOW_SECONDS`.
- `ALLOWED_HOSTS` comma list for host allowlist.
- `ENABLE_API_DOCS` enable `/docs` (dev only recommended).
- `DATABASE_URL` Postgres/SQLite DSN; `POSTGRES_PASSWORD` for the bundled DB.
- `ANTHROPIC_API_KEY` optional; without it the AI advisor uses the fallback path.

## Helpful Scripts
- `scripts/init_db.py` seed sample data.
- `scripts/simulate_logs.py` stream or batch logs.
- `scripts/simulate_threat_feed.py` refresh IOCs.
- `scripts/auth_client.py` CLI login helper (handles MFA when enabled).
- `scripts/generate_mfa_secret.py` create a TOTP secret and otpauth URI.

## Troubleshooting
- Backend not ready: wait for Postgres health check; then retry.
- Login 429s: you’ve hit the login rate limit; wait for the window or raise `LOGIN_RATE_LIMIT_*`.
- MFA failures: confirm `AUTH_TOTP_SECRET` matches your authenticator; generate a fresh secret with `scripts/generate_mfa_secret.py`.
- Anthropic 401s in logs: set `ANTHROPIC_API_KEY` or ignore; the app falls back to the template advisor.
