# CapstoneConnect backend

FastAPI + PostgreSQL API for [CapstoneConnect](../3dcapconnectfrontend): students, capstone groups,
join requests and invitations, recommendations, chat, file uploads, password reset by SMS code, and
real all-time GitHub contributions.

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

34 tests against a real PostgreSQL database named `capstoneconnect_test` (from `TEST_DATABASE_URL`,
or `DATABASE_URL` with the database renamed). They never touch the development database. They
cover sign-up and sessions, the whole password-reset flow, every group/request/recommendation rule,
search and sorting, profile edits, GitHub verification, upload checks and chat visibility.
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

Only a keyed hash of each code is stored. `SMS_PROVIDER=console` (default) logs the SMS and returns
the code as `dev_code` so the flow works without a phone; the frontend shows it. For real SMS set
`SMS_PROVIDER=twilio` and the three `TWILIO_*` variables (a Twilio number that can send to India).

## GitHub contributions

The total shown and used for the "Most contributions" sort is the account's **all-time**
contributions: GitHub's contribution calendar total for every year since the account was created.

- With `GITHUB_TOKEN` (any classic token, no scopes): one GraphQL query, and a 5,000/hour limit.
- Without it: the public calendar page for each year (what github.com shows), about 2 s per user.

It is checked at sign-up (in the background), when a profile's username is verified, and refreshed
in the background when a profile is viewed and the cached total is older than
`GITHUB_REFRESH_HOURS` (24). A client never sets the total: the server looks it up itself.
The seeded usernames are examples; their totals are demo values until a refresh checks them.

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
| Chat | `GET /conversations` `POST /conversations/direct` `GET /conversations/{id}` `GET/POST /conversations/{id}/messages` `POST /conversations/{id}/read` `POST /uploads/attachments` |
| Other | `GET /counts` `POST /counts/outcomes` `POST /presence` `GET /github/verify?username=` `GET /health` |

## Data model

`users` · `groups` · `group_members` (unique `user_id`: one group per student) · `join_requests`
(join requests and invitations, with the group's name kept for history) · `recommendations` ·
`conversations` + `conversation_participants` (per-user unread counts) · `messages` ·
`password_reset_codes`. Migrations in `alembic/versions/`.

Seat-changing operations lock the group row (`SELECT … FOR UPDATE`), so two simultaneous accepts
can't overfill a group.

## Production checklist

- A long random `SECRET_KEY`, `COOKIE_SECURE=true` (HTTPS), `DEMO_LOGIN=false`
- `CORS_ORIGINS` = the site's origin; frontend and API on the same site (e.g. `app.example.com` and
  `api.example.com`) so the `SameSite=Lax` cookie is sent
- `SMS_PROVIDER=twilio` with credentials; a `GITHUB_TOKEN`
- `UPLOAD_DIR` on persistent storage and `PUBLIC_BASE_URL` set to the API's public URL
- Run `uv run alembic upgrade head` on deploy; serve with
  `uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2` behind a reverse proxy
