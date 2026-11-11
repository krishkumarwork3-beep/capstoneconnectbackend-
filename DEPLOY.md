# Deploying CapstoneConnect

Three parts, each deployable on any host that fits it; deploying is configuration only.

| Part | What it is | Runs on |
| --- | --- | --- |
| API (this repo) | FastAPI + PostgreSQL 14+ | any container host (the `Dockerfile`), or any machine with Python 3.12 and uv |
| Student site (`3dcapconnectfrontend`) | Next.js | Vercel, or any Node 22 host (`npm run build && npm start`) |
| Admin portal (`adminportal`) | static files (`dist/`) | any static host (Vercel, Netlify, Cloudflare Pages, S3 + CDN, nginx) |

You need: a PostgreSQL database, a place to run the API container, two static/Node sites, HTTPS for
all three, and (for password reset) a Twilio account. A custom domain is strongly recommended.

## 1. Pick the layout (decides the cookie settings)

The session is an httpOnly cookie set by the API. Browsers send it only if the site and the API
are "same site" (same registrable domain), unless SameSite=None.

| Layout | Example | API settings |
| --- | --- | --- |
| **A. Subdomains of one domain (recommended)** | `app.example.com`, `admin.example.com`, `api.example.com` | `COOKIE_SAMESITE=lax`, `COOKIE_SECURE=true`, `COOKIE_DOMAIN=` (empty) |
| B. One origin through a reverse proxy | `example.com` and `example.com/api` → the API | as A. The proxy must pass WebSocket upgrades for `/api/ws` |
| C. Different sites (no domain of your own) | `cc.vercel.app` + `cc-api.onrender.com` | `COOKIE_SAMESITE=none`, `COOKIE_SECURE=true`. Works in Chrome/Firefox; **Safari and iOS block such third-party cookies by default, so students on iPhones can't stay signed in.** Use A or B for real users |

The live chat socket signs in with the same cookie, so it works wherever login works.
`app/cookies.py` has the details; `tests/test_production.py` checks each layout.

## 2. Database

Create a PostgreSQL 14+ database (managed: Neon, Supabase, RDS, the host's own; or
`docker-compose.production.yml` on a VPS). Note its URL as
`postgresql+psycopg://USER:PASSWORD@HOST:5432/DB` (add `?sslmode=require` if the provider asks).

## 3. The API

1. Copy `.env.production.example` into your host's environment settings (or a `.env.production`
   file that is never committed) and fill in every `CHANGE_ME` and `example.com`:
   - `SECRET_KEY`: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
   - `DATABASE_URL`, `PUBLIC_BASE_URL=https://api.example.com`,
     `CORS_ORIGINS=["https://app.example.com","https://admin.example.com"]`
   - Uploads: a persistent disk at `/data/uploads` (`STORAGE_BACKEND=local`), **or**, if the host
     has no persistent disk (most free tiers) or you run more than one instance, a private
     S3-compatible bucket (`STORAGE_BACKEND=s3` and the `S3_*` settings; R2 and B2 are cheap).
   - `FORWARDED_ALLOW_IPS`: your load balancer's address (ask the host; `*` if only the proxy can
     reach the container). This makes the per-IP sign-in limits see visitors, not the proxy.
   - Twilio: `SMS_PROVIDER=twilio` and the three `TWILIO_*` values.
2. Build and run the image. The container applies migrations on start, then serves on `$PORT`
   with 2 workers (`WEB_CONCURRENCY`), `--proxy-headers --forwarded-allow-ips`:
   ```bash
   docker build -t capstoneconnect-api .
   docker run --env-file .env.production -p 8000:8000 -v cc-uploads:/data/uploads capstoneconnect-api
   ```
   On a container host, point it at this repository: it finds the `Dockerfile`. Health check path:
   `/api/health` (200 when the database answers, 503 when it doesn't).
3. Check the settings on the running service (exit code 0 means nothing unsafe):
   ```bash
   docker exec <container> python -m app.check_config
   ```
   With `COOKIE_SECURE=true` the API refuses to start with the default `SECRET_KEY`,
   `DEMO_LOGIN=true`, `ALLOW_DEV_CODE=true`, or Twilio chosen without credentials.
4. Create the first admin (it asks for the password; it is stored hashed in the database):
   ```bash
   docker exec -it <container> python -m app.admin_cli create you@example.com "Your Name"
   ```
   More admins: the portal's Admins page. Forgotten password: `python -m app.admin_cli password you@example.com`.

Without Docker: `uv sync --no-dev`, `uv run alembic upgrade head`, then
`uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 --proxy-headers --forwarded-allow-ips <proxy IP>`.

## 4. The student site

Set the variables from `3dcapconnectfrontend/.env.production.example` in the host (Vercel: Project
→ Settings → Environment Variables), then build. They are baked into the build:

```env
NEXT_PUBLIC_USE_MOCK=false
NEXT_PUBLIC_API_BASE_URL=https://api.example.com/api
```

The site sends its own security headers (CSP built from that API URL), so no host configuration
is needed for them. Add the custom domain `app.example.com` in the host.

## 5. The admin portal

```bash
cd adminportal
VITE_API_BASE_URL=https://api.example.com/api npm run build   # → dist/
```

Upload `dist/` to a static host as a single-page app (all paths → `index.html`; `vercel.json` does
this on Vercel). The build's `index.html` carries its CSP for that API; `dist/_headers` (Netlify,
Cloudflare Pages) and `vercel.json` add frame protection. Keep it private if you can (an IP
allow-list or the host's password protection) and serve it at `admin.example.com`.

### Vercel settings (site and portal)

Both builds fail closed: a production build without the variables below stops with an error that
names them (this is the "Deployment has failed" check on a new Vercel project). Set them for the
Production (and Preview) environment, then redeploy.

| Setting | Student site | Admin portal |
|---|---|---|
| Framework preset | Next.js | Vite |
| Root directory | `3dcapconnectfrontend` | `adminportal` |
| Build command | from `vercel.json`: `next build` with `NEXT_PUBLIC_USE_MOCK` defaulting to `true` (the demo) when the project does not set it | `npm run build` (`tsc -b && vite build`) |
| Output directory | default (`.next`) | `dist` |
| Install command | `npm ci` | `npm ci` |
| Demo (mock data, no API) | `NEXT_PUBLIC_USE_MOCK=true` | not supported: the portal always needs the API |
| Real site | `NEXT_PUBLIC_USE_MOCK=false`<br>`NEXT_PUBLIC_API_BASE_URL=https://api.example.com/api`<br>`NEXT_PUBLIC_WS_URL=wss://api.example.com/api/ws` (optional; derived from the API URL when empty) | `VITE_API_BASE_URL=https://api.example.com/api` |
| SPA routes | handled by Next.js | `vercel.json` rewrites `/(.*)` → `/index.html` |
| Security headers | sent by `next.config.ts` (CSP from the API URL) | `vercel.json` headers + CSP `<meta>` in `index.html` |

The API URLs must be `https://` / `wss://` (plain http is refused except for localhost). Nothing
calls the API while building, so the build succeeds even when the API is down; live data is
fetched in the browser.

## 6. Upload limits across the stack

| Layer | Limit |
| --- | --- |
| Site (before upload) | photo 2 MB, résumé 5 MB, chat file 5 MB |
| API (enforced, by content type) | the same: photo 2 MB PNG/JPG, résumé 5 MB PDF, attachment 5 MB PDF/PNG/JPG/DOCX/ZIP |
| Reverse proxy / host | must allow at least **6 MB** request bodies: **nginx defaults to 1 MB** (`client_max_body_size 6m;`), Cloudflare's free plan allows 100 MB, Render/Railway/Fly have no small default, Vercel functions 4.5 MB (the API is not on Vercel, so this doesn't apply) |

### WebSocket limits are per process

The live-socket limits (`WS_MAX_SOCKETS`, and `WS_ACCOUNT_FRAMES` frames per account in 10 s) are
counted by each API worker on its own. With `WEB_CONCURRENCY=2` an account can send up to
2 x `WS_ACCOUNT_FRAMES` frames in 10 s in all (one socket per worker). Lower `WS_ACCOUNT_FRAMES`
if you run many workers.

## 7. Smoke test after deploying

- [ ] `https://api.example.com/api/health` → `{"status":"ok","database":"ok"}`
- [ ] `docker exec <container> python -m app.check_config` → "No unsafe production settings found."
- [ ] The site has **no "Demo mode" badge**.
- [ ] Sign up with your phone, upload a photo and a résumé, log out, log in. In the browser's
      dev tools → Application → Cookies, `cc_session` on `api.example.com` is HttpOnly, Secure.
- [ ] Forgot password: the SMS arrives; the page does **not** show the code.
- [ ] Two browsers, two students: a direct chat shows live messages, ticks and "typing…"
      (dev tools → Network → WS: `wss://api.example.com/api/ws`, status 101).
- [ ] Admin portal: sign in, suspend a test student → their open tab signs out at once; lift it.
- [ ] Post an announcement → it shows on the site; delete it.
- [ ] Report a test student → it shows in the portal's Reports.
- [ ] Dev tools console on the site, the portal and in 3D mode: no CSP, CORS or mixed-content errors.
- [ ] On an iPhone (Safari): log in, reload, still signed in (see `MANUAL_TESTS.md`).

## 8. Operations

**Backups** (do this daily, and before every deploy; keep copies off the server):
```bash
# inside the container, then copy it out:
docker exec <container> python scripts/db_backup.py backup --out /tmp/cc.dump
docker cp <container>:/tmp/cc.dump ./cc-$(date +%F).dump
# or from any machine with the PostgreSQL client tools and DATABASE_URL set:
uv run python scripts/db_backup.py backup --out backups/cc-$(date +%F).dump
```
Also back up the uploads (the `/data/uploads` volume, or the bucket). Restore into a new, empty
database (it refuses to overwrite `DATABASE_URL`'s own database):
```bash
uv run python scripts/db_backup.py restore backups/cc-2026-11-04.dump --into "postgresql+psycopg://…/capstoneconnect_restored" --create
```
then point `DATABASE_URL` at it. Managed databases also have point-in-time restore: turn it on.

**Rotating SECRET_KEY** (after a leak, or yearly): set a new value and restart. Every student and
admin is signed out (sessions and reset links are signed with it); nothing else changes.

**Rotating an admin's password**: `python -m app.admin_cli password you@example.com` (signs that
admin out everywhere). `ADMIN_PASSWORD` in the environment only creates the first admin; it never
changes an existing one.

**Moving uploads to S3 later**: set the `S3_*` settings, run
`python scripts/migrate_uploads.py --dry-run`, then without `--dry-run`, then `STORAGE_BACKEND=s3`
and restart. Links don't change (the database keeps paths; the API serves either storage).

**Changing the API's domain**: just change `PUBLIC_BASE_URL` (and `CORS_ORIGINS`, the site's
`NEXT_PUBLIC_API_BASE_URL`, the portal's `VITE_API_BASE_URL`). File links follow automatically.

**Logs**: one JSON line per request (`app.requests`: request id, method, path, status, ms, client)
and full tracebacks for unexpected errors (`app.errors`). Students get the request id in error
answers (`X-Request-ID`), so you can find their request. Passwords, codes and tokens are never
logged.
