# HoneyLens

AI-powered honeypot. A fake admin portal and fake API attract bots; every request is captured, classified (rules first, then LLM), mapped to MITRE ATT&CK with a recommended defense rule, and shown on a live dashboard.

```
 Bots/Attackers --> HONEYPOT (Flask) --> DB (events, status=pending)
                                           |
                       PIPELINE WORKER <---+  geo -> rules -> (LLM if unsure) -> update row
                                           |
 React Dashboard <-- polling every 3s -- DASHBOARD API (Flask) <-- DB
```

The database is the queue, so the honeypot and the API never call each other directly.

## Folders

| Folder | What |
|---|---|
| `honeypot/` | Public fake portal (Flask) |
| `shared/` | DB models and functions |
| `pipeline/` | Rules engine + worker |
| `ai/` | LLM client and prompts |
| `api/` | Dashboard API |
| `attack_sim/` | Attack simulator |
| `frontend/` | React dashboard |
| `docker/` | Dockerfiles (build context = repo root) |

## Run locally (no Docker, SQLite)

```bash
cp .env.example .env
pip install -r requirements.txt
python -m honeypot.app              # honeypot on :5000
python -m api.app                   # API + worker on :5001 (second terminal)
cd frontend && npm install && npm run dev   # dashboard on :5173
```

Run commands from the repo root so `shared/`, `honeypot/` etc. are importable (or set `PYTHONPATH=.`).
Quick check: `curl -i localhost:5000/.env` and `curl localhost:5000/health`.

## Run locally with Docker (Postgres)

```bash
cp .env.example .env
docker-compose up --build
```

Honeypot: http://localhost:5000, API: http://localhost:5001.
Seed demo data: `docker-compose exec api python -m api.seed`.

## Honeypot endpoints

`GET/POST` on `/`, `/admin`, `/admin/login`, `/administrator`, `/wp-login.php`, `/wp-admin`, `/login`, `/phpmyadmin/`, `/api/v1/login`, `/api/v1/users`, `/api/v1/config`, `/.env`, `/.git/config`, `/robots.txt`, plus a catch-all. `GET /health` returns `{"status":"ok"}` and is never logged.

Safety: input is never executed or reflected, bodies are truncated to 4 KB, and all fake data (`.env`, users) is invented.

## Deploy (free tier)

> Free-tier limits and names change. Verify current limits on each provider before relying on them.

1. **Database (Neon or Supabase):** create a free Postgres project and copy the connection string, e.g. `postgresql://user:pass@host/db?sslmode=require`. Do not use Render's free DB (expires) or SQLite on Render (disk is wiped).
2. **Honeypot on Render:** New > Web Service > connect the GitHub repo > Runtime: Docker.
   - Dockerfile path: `docker/honeypot.Dockerfile`, Docker context: `.` (repo root)
   - Env vars: `DATABASE_URL` (Neon string)
   - Health check path: `/health`
3. **API + worker on Render:** a second Web Service.
   - Dockerfile path: `docker/api.Dockerfile`, context `.`
   - Env vars: `DATABASE_URL`, `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_MAX_PER_MIN`, `ALLOWED_ORIGIN` (your Vercel URL), `RUN_WORKER=true`
   - Health check path: `/health`
   - Keep this service at one process (the Dockerfile already uses `--workers 1`) so only one worker thread runs.
4. **Keep-alive (UptimeRobot):** add two HTTP monitors, `https://<honeypot>.onrender.com/health` and `https://<api>.onrender.com/health`, every 5 minutes.
5. **Frontend on Vercel/Netlify:** import the repo, root directory `frontend`, build `npm run build`, output `dist`. Set `VITE_API_URL` to the API's public URL. Then update `ALLOWED_ORIGIN` on the API service to the frontend URL and redeploy.
6. **Verify:** `curl https://<honeypot>/health`, then `python attack_sim/simulate.py --target https://<honeypot>` and watch the dashboard.

Render sits behind a proxy, so the honeypot reads the client IP from the first `X-Forwarded-For` value.

Optional: an Oracle Cloud Always Free VM running `docker-compose up -d` gets a real public IP that real bots find quickly (needs card verification).

## Demo backup plan

If the live site is asleep or the network fails: `docker-compose up`, run `seed.py`, and keep a 1-minute screen recording ready. Open the live URLs 5 minutes before the demo.

## Rules for the team

Only attack our own honeypot with sqlmap/Nikto/simulate.py. Never scan anything else, including the college network. Never commit `.env`, keys or `*.db`.
