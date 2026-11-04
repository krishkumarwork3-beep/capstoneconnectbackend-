# CapstoneConnect backend

FastAPI + PostgreSQL API for [CapstoneConnect](../3dcapconnectfrontend): students, capstone groups,
join requests and invitations, recommendations, chat, file uploads, password reset by SMS code, and
real all-time GitHub contributions, with **live chat over WebSockets** (WhatsApp-style ticks,
typing and online status).

The frontend already talks to it: set `NEXT_PUBLIC_USE_MOCK=false` there (see *Frontend* below).

## Stack

- **FastAPI** (Python 3.12), **SQLAlchemy 2** ORM, **Alembic** migrations, **psycopg 3**
- **PostgreSQL 16** (any 14+ works)
- Sessions: a signed (JWT, HS256) **httpOnly cookie**, `SameSite=Lax`; also accepted as
  `Authorization: Bearer …` for API clients. Passwords: **bcrypt**.
- Package manager: **[uv](https://docs.astral.sh/uv/)**

## Run it

```bash
uv sync                                   # Python 3.12 + dependencies into .venv
cp .env.example .env                      # then edit; every setting is in app/config.py
```

**PostgreSQL** — pick one:

| | |
| --- | --- |
| No install (development) | `uv run python scripts/local_postgres.py` starts an embedded PostgreSQL 16 in `.pgdata/` and writes its `DATABASE_URL` into `.env` (run it again after a reboot; `--stop` stops it) |
| Docker | `docker compose up -d`, then `DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/capstoneconnect` |
| Installed / hosted | create a `capstoneconnect` database (and `capstoneconnect_test` for tests) and put its URL in `.env` |

```bash
uv run alembic upgrade head               # create the tables
uv run python -m app.seed                 # optional: the demo students, groups and chats
uv run uvicorn app.main:app --reload --port 8000
```

- API: <http://localhost:8000/api> · interactive docs: <http://localhost:8000/docs>
- Every seeded student signs in with their phone number and `password123`
  (for example `+91 98765 43210`, Aarav Sharma, a Group Lead).

## Tests

```bash
uv run pytest
```

90 tests against a real PostgreSQL database named `capstoneconnect_test` (from `TEST_DATABASE_URL`,
or `DATABASE_URL` with the database renamed). They never touch the development database. They
cover sign-up and sessions, the whole password-reset flow, every group/request/recommendation rule,
search and sorting, profile edits, GitHub verification, upload checks, chat visibility and the
live socket (messages, receipts, typing, presence, sign-in and origin checks), and the admin API
(access and read-only admins, lock-out, students, suspensions and blocked numbers enforced on the
student side, groups, chat moderation, admin accounts, audit log), throttling, phone-number privacy,
private uploads (including path traversal and renamed executables) and unsafe-settings checks.
GitHub is mocked in the tests.

## Frontend

In `3dcapconnectfrontend/.env.local`:

```env
NEXT_PUBLIC_USE_MOCK=false
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api
```

Restart `npm run dev`. Open the site on the **same host** as the API (`localhost` with
`localhost`), so the session cookie is same-site. Add the site's origin to `CORS_ORIGINS`.

## Forgot password (SMS code)

1. `POST /api/auth/password/forgot {phone}` — if an account uses the number, a 6-digit code is sent.
   The answer is the same either way (no account discovery). One code per minute.
2. `POST /api/auth/password/verify {phone, code}` — 5 tries, 10 minutes; returns a `reset_token`
   (15 minutes, single use).
3. `POST /api/auth/password/reset {reset_token, password}` — sets the password, signs in, and signs
   out every other session.

Only a keyed hash of each code is stored. `SMS_PROVIDER=console` (default) writes the SMS to the
server log. The code is also returned to the app as `dev_code` (and shown on the forgot-password
page) **only** with `ALLOW_DEV_CODE=true`, for local development: otherwise anyone who knows a phone
number could reset that account. For real SMS set `SMS_PROVIDER=twilio` and the three `TWILIO_*`
variables (a Twilio number that can send to India).

## Throttling

Sign-in, sign-up and each password-reset step are limited per phone number **and** per IP address;
over the limit the API answers `429` with "Too many attempts. Try again in N minutes." and a
`Retry-After` header.

| Step | Per number | Per IP | Window |
| --- | --- | --- | --- |
| `POST /auth/login` (wrong passwords) | 5 | 20 | 15 min |
| `POST /auth/signup` | 5 | 10 | 60 min |
| `POST /auth/password/forgot` | 5 | 20 | 60 min |
| `POST /auth/password/verify` and `/reset` | 10 | 30 | 15 min |

A successful sign-in clears the number's count. The counters are rows in the `rate_limits` table,
updated with one atomic upsert, so every worker shares them (`--workers 2`). Behind a reverse proxy
run uvicorn with `--proxy-headers` so the visitor's address is used. Every limit is a setting
(`LOGIN_LIMIT_PER_PHONE` …, see `.env.example`).

## Privacy and uploads

- **Phone numbers:** a student's full number goes only to themselves, their group's members and
  anyone they had a request or invitation accepted with (`phone_visible: true`). Everyone else gets
  a masked number (`+91 98••• ••210`, `phone_visible: false`). Admins see every number.
- **Uploads** (`/uploads/...`, same links as before): avatars are public; résumés need a signed-in
  student or an admin; chat attachments are served only to the conversation's participants (and
  admins). A message can only attach a file just uploaded to this server, and a file can't be
  re-sent to another conversation. Types are checked by content and sizes are capped
  (avatar 2 MB PNG/JPG, résumé 5 MB PDF, attachment 5 MB PDF/PNG/JPG/DOCX/ZIP).

## Unsafe settings

```bash
uv run python -m app.check_config          # lists unsafe production settings, exit code 1 if any
```

With `COOKIE_SECURE=true` (a real HTTPS deployment) the API refuses to start if `SECRET_KEY` is
the development default, `DEMO_LOGIN=true` or `ALLOW_DEV_CODE=true`, and logs a loud warning for
`SMS_PROVIDER=console`.

## GitHub contributions

The total shown and used for the "Most contributions" sort is the account's **all-time**
contributions: GitHub's contribution calendar total for every year since the account was created.

- With `GITHUB_TOKEN` (any classic token, no scopes): one GraphQL query, and a 5,000/hour limit.
- Without it: the public calendar page for each year (what github.com shows), about 2 s per user.

It is checked at sign-up (in the background), when a profile's username is verified, and refreshed
in the background when a profile is viewed and the cached total is older than
`GITHUB_REFRESH_HOURS` (24). A client never sets the total: the server looks it up itself.
The seeded usernames are examples; their totals are demo values until a refresh checks them.

## Live chat (WebSocket)

`ws://localhost:8000/api/ws`, signed in by the same session cookie. Messages are still sent with
`POST /conversations/{id}/messages` (pass a `client_id` to match the optimistic copy); the socket
carries everything that happens next, to every open tab of every participant:

| Event | |
| --- | --- |
| `message.new` | a new message (the sender's other tabs get it too) |
| `typing` | someone started or stopped typing (cleared when they disconnect) |
| `delivered` / `read` | receipts: one tick when stored, two when it reached everyone, blue when everyone read it |
| `presence` | someone you chat with came online or left (with `last_seen`) |
| `conversations.changed` | a group chat appeared or went (joined, left, removed, deleted) |

The client sends `ping` (~25 s), `typing`, `delivered` and `read`. Receipts are stored per
participant (`last_delivered_at`, `last_read_at`), so the ticks are right after a reload too.

Events go through **PostgreSQL `LISTEN/NOTIFY`**, published in the same transaction as the change,
so they are sent only if it commits and reach a socket on any worker (`--workers 2` works). A
socket with an `Origin` not in `CORS_ORIGINS` is refused (close code 4403); a missing or ended
session closes with 4401. Behind a reverse proxy, pass WebSocket upgrades for `/api/ws` through
(nginx: `proxy_http_version 1.1` and the `Upgrade`/`Connection` headers).

## Admin portal and admin API

The admin portal (`../adminportal`, port 3100) runs on `/api/admin` (see its README for every page).

- **Admins** are their own accounts (`admin_users`), signed in by email and password with their own
  cookie (`ADMIN_COOKIE_NAME`, `cc_admin`). Roles: `admin` (can change anything) and `viewer`
  (read-only, enforced by the API). Five wrong passwords lock an email out for two minutes.
- **First admin:** `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env`, created at startup if missing; or
  `uv run python -m app.admin_cli create you@example.com "Your Name"` (also `password` and `list`).
- **Suspended accounts** (`users.banned_at`) and **blocked numbers** (`banned_phones`) are enforced
  on the student side: sign-up and sign-in, every authenticated request (403), password reset (no
  code is sent) and the live socket (closed with 4401).
- **Audit log:** every change made through the admin API is written to `audit_log`.

| Area | Endpoints (under `/api/admin`) |
| --- | --- |
| Sign-in | `POST /auth/login` `POST /auth/logout` `GET /auth/me` `POST /auth/password` |
| Dashboard | `GET /stats` |
| Students | `GET /users` (q, status, college, sort, page, page_size) `GET /users/colleges` `GET /users/export.csv` `POST /users` `GET/PATCH/DELETE /users/{id}` `POST /users/{id}/password` `POST /users/{id}/ban` `POST /users/{id}/unban` `POST /users/bulk` |
| Blocked numbers | `GET/POST /banned-phones` `DELETE /banned-phones/{phone}` |
| Student files | `DELETE /users/{id}/avatar` `DELETE /users/{id}/resume` (the file is deleted from disk too) |
| Groups and requests | `GET /groups` `GET/PATCH/DELETE /groups/{id}` `POST /groups/{id}/lead` `DELETE /groups/{id}/members/{userId}` `GET /requests` `POST /requests/{id}/cancel` `GET /recommendations` |
| Select all and bulk | `GET /users/ids` `GET /groups/ids` `GET /requests/ids` `POST /groups/bulk-delete` `POST /banned-phones/bulk-delete` `POST /requests/bulk-cancel` `POST /messages/bulk-delete` |
| Chat | `GET /conversations` `GET /conversations/{id}/messages` `DELETE /messages/{id}` |
| Admins and audit | `GET/POST /admins` `PATCH/DELETE /admins/{id}` `GET /audit` |

Every endpoint is in the interactive docs (`/docs`) under the "admin:" sections; signed in to the
portal on the same host, they can be tried there directly.

## API

All under `/api`. Errors are `{"message": "…"}`; rule errors use the same wording as the UI
(`Group Full`, `Max Invites`, `Lead Only`, …).

| Area | Endpoints |
| --- | --- |
| Auth | `POST /auth/signup` `POST /auth/login` `POST /auth/logout` `GET /auth/me` `POST /auth/demo-login/{id}` (only with `DEMO_LOGIN=true`) |
| Password | `POST /auth/password/forgot` `…/verify` `…/reset` |
| Students | `GET /users` (search, college, passing_year, hasGroup, sort, cursor, limit) `GET/PATCH /users/{id}` `POST /users/{id}/avatar` `POST /users/{id}/resume` `GET /users/{id}/github` `POST /users/{id}/invitations` |
| Groups | `GET/POST /groups` `GET /groups/mine` `GET/PATCH/DELETE /groups/{id}` `POST /groups/{id}/leave` `DELETE /groups/{id}/members/{memberId}` `POST /groups/{id}/join-requests` |
| Requests | `GET /requests?direction=sent\|received` `PATCH /requests/{id}` (accepted, declined, withdrawn, cancelled) |
| Recommendations | `GET/POST /recommendations` `POST /recommendations/{id}/dismiss` `POST /recommendations/{id}/invite` |
| Chat | `WS /ws` `GET /conversations` `POST /conversations/direct` `GET /conversations/{id}` `GET/POST /conversations/{id}/messages` `POST /conversations/{id}/read` `POST /uploads/attachments` |
| Other | `GET /counts` `POST /counts/outcomes` `POST /presence` `GET /github/verify?username=` `GET /health` |

## Data model

`users` · `groups` · `group_members` (unique `user_id`: one group per student) · `join_requests`
(join requests and invitations, with the group's name kept for history) · `recommendations` ·
`conversations` + `conversation_participants` (per-user unread counts and read/delivered times) · `messages` ·
`password_reset_codes` · `admin_users` · `banned_phones` · `audit_log` · `rate_limits`. Migrations in `alembic/versions/`.

Seat-changing operations lock the group row (`SELECT … FOR UPDATE`), so two simultaneous accepts
can't overfill a group.

## Production checklist

- A long random `SECRET_KEY`, `COOKIE_SECURE=true` (HTTPS), `DEMO_LOGIN=false`, `ALLOW_DEV_CODE=false`;
  `uv run python -m app.check_config` must report nothing
- A strong `ADMIN_PASSWORD` (or create admins with `app.admin_cli` and leave it empty); the admin
  portal's origin in `CORS_ORIGINS`, on the same site as the API
- `CORS_ORIGINS` = the site's origin; frontend and API on the same site (e.g. `app.example.com` and
  `api.example.com`) so the `SameSite=Lax` cookie is sent
- `SMS_PROVIDER=twilio` with credentials; a `GITHUB_TOKEN`
- `UPLOAD_DIR` on persistent storage and `PUBLIC_BASE_URL` set to the API's public URL
- Run `uv run alembic upgrade head` on deploy; serve with
  `uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2` behind a reverse proxy
