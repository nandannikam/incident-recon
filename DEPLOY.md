# Deployment Guide — Incident Reconstruction (Phase 3)

> **Scope:** take the finalized backend (FastAPI) + dashboard (React/Vite) from a git checkout to a
> running URL. The recommended path is a **single Linux host with SQLite** — **no PostgreSQL, no
> Docker required**. Docker and split-hosting variants are included at the end.

---

## 0. Short answer: is Step 7 (PostgreSQL) required to deploy?

**No.** Step 7 is marked "Must" in the roadmap only because the roadmap's Step 9 assumed a
`docker compose` stack (`api` + `db` + `web`). For _this_ product, PostgreSQL buys you nothing the
demo needs. Two hard facts about the current code:

- `src/app/storage.py` is **SQLite-only** — it does `settings.database_url.removeprefix("sqlite:///")`
  and hands the result to `sqlite3.connect()`. A `postgresql://…` URL would create a file literally
  named `postgresql://…` and break. So deploying with Postgres today **would require doing Step 7
  first**.
- Nothing in the pipeline needs concurrency or scale. Incidents are written once on `/analyze` and
  read once on `/incident/{id}`.

**What SQLite costs you:** if the host gives the app an **ephemeral filesystem** (many free PaaS
tiers), the incident-history DB resets on every redeploy/restart. The core demo
(upload → analyze → view) still works; only revisiting an _old_ `/incident/{id}` after a restart
would 404. Mitigate by putting the DB on a **persistent disk/volume** (a VM, or a Docker named
volume), or accept the reset — it is irrelevant during a single live demo.

**When you _would_ want Postgres:** a long-lived public deployment with multiple app instances or a
managed DB requirement. That is genuinely Step 7 + Step 9 work, and it is optional for the exhibition.

---

## 1. What actually gets deployed

| Piece                            | Runtime                                         | Why                                                          |
| -------------------------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| Backend (`src/app`)              | Python 3.11+ + `uvicorn`                        | serves `/upload`, `/analyze`, `/jobs/{id}`, `/incident/{id}` |
| Dashboard (`incident-dashboard`) | Node **only to build**, then plain static files | `npm run build` → `incident-dashboard/dist/`                 |
| Storage                          | one **SQLite file** on persistent disk          | incident history                                             |
| Config                           | a `.env` file (never committed)                 | CORS, upload limit, DB path, log level                       |

There are only **four backend routes** (`src/app/main.py`): `POST /upload`, `POST /analyze`,
`GET /jobs/{job_id}`, `GET /incident/{incident_id}`. There is no `/health` route yet.

---

## 2. Prerequisites

- A Linux host with a public IP (university VM, a small VPS, etc.). A domain name is optional.
- `python3` ≥ 3.11, `python3-venv`, `git`. Node.js 20+ (22 preferred) **only on the build machine**.
- ~1 GB free disk for the app + datasets; the APT29 campaign needs ~2.3 GB RAM and is **optional**.

---

## 3. Backend — build and run

```bash
# 1. Get the code
git clone <your-repo-url> /srv/incident-reconstruction
cd /srv/incident-reconstruction

# 2. Virtualenv + dependencies
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt   # full pinned set (uvicorn, matplotlib, pydantic-settings, ...)
.venv/bin/pip install -e .                   # makes `import app` resolve from src/ (pyproject packages.find = src)

# 3. Configuration
cp .env.example .env
# edit .env — see §7 for the values that matter

# 4. Smoke-run it (auto-reload off, bind to loopback; a reverse proxy fronts it)
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` on the box (or via SSH tunnel) to confirm it is up.

> **`pip install -e .` is required.** `pyproject.toml` sets `packages.find.where = ["src"]`, so only
> an editable install (or `PYTHONPATH=src`) makes `app.main` importable. `requirements.txt` alone is
> not enough.

### Optional: fetch the campaign datasets

```bash
make data     # downloads APT29 Day 1 + wevtutil into the git-ignored src/data/mordor/
make demo     # writes docs/demo/campaign_result.json (needs ~2.3 GB RAM)
```

Not required to run the app — it accepts any uploaded log. Only do this if you want the pre-baked
campaign artifact for the demo.

---

## 4. Frontend — build once, serve as static files

The dashboard reads its API base URL at **build time** (`incident-dashboard/src/api.ts:7`,
`import.meta.env.VITE_API_BASE_URL`). If you build without setting it, it falls back to
`http://localhost:8000` — wrong in production. **Set it to the public origin you will serve the site
from.**

```bash
cd /srv/incident-reconstruction/incident-dashboard
npm ci
VITE_API_BASE_URL="https://demo.example.com" npm run build   # -> incident-dashboard/dist/
```

Use your real domain/IP. If the frontend and API are served from the **same origin** (recommended,
§5A/§5B), this is simply that origin. Result: `dist/index.html`, `dist/assets/*`.

> Rebuilding is needed whenever `VITE_API_BASE_URL` changes — it is baked into the JS bundle.

---

## 5. Serve frontend + backend together

Pick **one** of these.

### 5A. Reverse proxy with Caddy (recommended — **no code changes**)

Caddy serves the static `dist/` and forwards the four API routes to uvicorn, with automatic HTTPS.
Same origin ⇒ no CORS issues.

`/etc/caddy/Caddyfile`:

```caddy
demo.example.com {
    # API routes -> FastAPI
    handle /upload*       { reverse_proxy 127.0.0.1:8000 }
    handle /analyze*      { reverse_proxy 127.0.0.1:8000 }
    handle /jobs*         { reverse_proxy 127.0.0.1:8000 }
    handle /incident*     { reverse_proxy 127.0.0.1:8000 }
    handle /docs*         { reverse_proxy 127.0.0.1:8000 }
    handle /openapi.json  { reverse_proxy 127.0.0.1:8000 }

    # everything else -> the built SPA (client-side routes fall back to index.html)
    handle {
        root * /srv/incident-reconstruction/incident-dashboard/dist
        file_server
        try_files {path} /index.html
    }
}
```

```bash
sudo systemctl reload caddy
```

### 5B. Serve the SPA from FastAPI (one small code change, good for Docker/PaaS)

Add this to `src/app/main.py` **after all routes** (mounting `/` last so it cannot shadow the API):

```python
from fastapi.staticfiles import StaticFiles

app.mount(
    "/",
    StaticFiles(directory="incident-dashboard/dist", html=True),
    name="ui",
)
```

Then set `VITE_API_BASE_URL=""` when building, so the frontend calls `/analyze` on its own origin:

```bash
VITE_API_BASE_URL="" npm run build
```

Run `uvicorn` as in §3/§6 — one process now serves both. (HTTPS still needs a TLS terminator such as
Caddy/nginx/Cloudflare in front.)

### 5C. nginx instead of Caddy

```nginx
server {
    listen 80;
    server_name demo.example.com;
    root /srv/incident-reconstruction/incident-dashboard/dist;

    location / { try_files $uri /index.html; }

    location ~ ^/(upload|analyze|jobs|incident|docs|openapi\.json) {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
```

---

## 6. Run the backend as a service (systemd)

`/etc/systemd/system/incident-api.service`:

```ini
[Unit]
Description=Incident Reconstruction API
After=network.target

[Service]
User=www-data
WorkingDirectory=/srv/incident-reconstruction
EnvironmentFile=/srv/incident-reconstruction/.env
ExecStart=/srv/incident-reconstruction/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now incident-api
sudo systemctl status incident-api
```

`WorkingDirectory` matters: the default relative `DATABASE_URL` and `.env` are resolved from it.

---

## 7. Environment reference (the gotchas)

`.env` (copy from `.env.example`):

| Variable                        | Deploy value                                              | Notes                                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                  | `sqlite:////var/lib/incident-reconstruction/incidents.db` | **four slashes** = absolute path. `storage.py` strips `sqlite:///`, leaving `/var/lib/...`. The parent dir must exist and be writable.                                          |
| `UPLOAD_DIR`                    | `/var/lib/incident-reconstruction/uploads`                | optional; defaults to the OS temp dir (files are never cleaned up automatically).                                                                                               |
| `CORS_ORIGINS`                  | `https://demo.example.com`                                | explicit origins only — `*` is rejected at startup (`config.py:76-86`). Irrelevant for same-origin serving, but must still be valid.                                            |
| `ENVIRONMENT`                   | `development`                                             | ⚠️ setting `production` makes `API_KEY` **mandatory** (`config.py:98-102`) even though no auth middleware is implemented yet. Leave it `development` unless/until Step 8 lands. |
| `API_KEY`                       | _(leave empty)_                                           | declared but **not enforced** — no route checks it today. Do not treat it as security.                                                                                          |
| `BACKGROUND_ANALYSIS_THRESHOLD` | `5000`                                                    | above this parsed-event count `/analyze` returns `202` + a job id to poll.                                                                                                      |
| `LOG_LEVEL`                     | `INFO`                                                    |                                                                                                                                                                                 |

**Do not commit `.env`.** It is already git-ignored.

---

## 8. Verify the deployment

```bash
# 1. API is up
curl -sS https://demo.example.com/docs -o /dev/null -w '%{http_code}\n'   # expect 200

# 2. A real upload produces an incident (no auth required today)
curl -sS -X POST https://demo.example.com/analyze \
  -F "file=@src/data/attack_sample.csv" | head -c 400

# 3. The dashboard loads and the browser can reach the API
#    open https://demo.example.com and upload src/data/attack_sample.csv
```

A 200 with `{"incident":…,"diagnostics":…}` (or `202` + `{"job_id":…}` for a large file, then poll
`/jobs/{id}`) means the backend is correct.

---

## 9. Optional: Docker (single container + SQLite volume — no Postgres)

Requires the §5B static mount (or run nginx as a second process). Minimal `Dockerfile`:

```dockerfile
# --- build the dashboard ---
FROM node:22-slim AS web
WORKDIR /web
COPY incident-dashboard/package*.json ./
RUN npm ci
COPY incident-dashboard/ ./
RUN VITE_API_BASE_URL="" npm run build

# --- runtime ---
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pyproject.toml .
COPY src/ ./src/
RUN pip install --no-cache-dir -e .
COPY --from=web /web/dist ./incident-dashboard/dist
ENV PYTHONPATH=/app/src
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Run with a **named volume** so the SQLite file survives restarts:

```bash
docker build -t incident-reconstruction .
docker run -d --name incident \
  -p 8000:8000 \
  -v incident-data:/data \
  -e DATABASE_URL="sqlite:////data/incidents.db" \
  -e ENVIRONMENT=development \
  incident-reconstruction
```

---

## 10. Optional: split hosting (frontend and backend on different hosts)

Possible, but more moving parts and it needs CORS:

1. Build with `VITE_API_BASE_URL=https://your-api-host` and deploy `dist/` to any static host
   (Vercel/Netlify/GitHub Pages…).
2. Deploy the backend as in §3/§6/§9 on its own host.
3. Set `CORS_ORIGINS=https://your-frontend-host` on the backend and restart it.

Only choose this if you must; same-origin (§5A/§5B) avoids the whole class of CORS problems.

---

## 11. Not required for this deployment

- **Step 7 — PostgreSQL:** see §0. Optional.
- **Step 9 — Docker/Compose:** §9 is a convenience, not a requirement.
- **Step 10 — CI/CD:** a nicety; irrelevant to serving the demo.
- **Step 8 — API hardening (auth, `/health`, rate limiting, JSON logs):** proportionate only if you
  expose the URL publicly. See §12.

---

## 12. Security caveats before exposing it publicly

The finalized product has **no authentication, no rate limiting, and no `/health`** — these are Step 8
items that were not completed. Concretely, anyone who can reach the URL can upload files and run
analysis. For a graded exhibition that is usually acceptable, but:

- Prefer a **LAN-only** or **university-network** deployment, or put the host behind an SSO/VPN.
- If it must be public, keep the upload cap (`MAX_UPLOAD_BYTES`), and add basic auth at the proxy.
- **Keep `ENVIRONMENT=development`.** Setting `production` forces you to supply an `API_KEY` that
  nothing actually checks, which is misleading rather than secure.

---

## 13. Offline / demo-day fallback

The venue network may fail. Have these ready locally:

- `src/data/attack_sample.csv` — a small (4-conclusion) synthetic incident that always works.
- `docs/demo/campaign_result.json` — the pre-computed APT29 result, if `make demo` was run.
- The app running on the presenter's laptop (`uvicorn` + `npm run dev`), independent of the deployed URL.

---

## 14. One-command local smoke test (no deployment)

```bash
# terminal 1 — backend
.venv/bin/uvicorn app.main:app --reload --port 8000

# terminal 2 — frontend (dev server, proxies nothing; uses the default localhost:8000)
cd incident-dashboard && npm run dev
# open http://localhost:5173, upload src/data/attack_sample.csv
```
