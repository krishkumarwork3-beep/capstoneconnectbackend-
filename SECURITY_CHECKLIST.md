# Security checklist

Before every release, and when adding a route, a field, a page or a dependency. SECURITY.md says
what covers each class and which test proves it.

## Every change
- [ ] `uv run pytest` passes, including `tests/attacks` (fuzz, Schemathesis, IDOR sweep, races).
- [ ] `npm run lint && npm run typecheck && npm run test:unit` in the site; `npm run lint && npm run test:unit && npm run build` in the portal.
- [ ] `npx playwright test` (Chrome and WebKit), including the `security` project.
- [ ] `node scripts/check-bundle-secrets.mjs <build dir> --env=../capstoneconnectbackend/.env` in both frontends.
- [ ] `npm audit --omit=dev --audit-level=high` (both) and `pip-audit` on `uv export --no-dev` are clean.

## A new API route
- [ ] Request model inherits `In` (`extra="forbid"`); every string has `max_length`, every list `max_length`, ids use `Id`/`PathId`.
- [ ] A `response_model` (no bare dicts); nothing internal in it.
- [ ] Classified in `tests/attacks/test_route_inventory.py` (public / student / admin).
- [ ] If its path has an id: an attack case (or a documented public reason) in `tests/attacks/test_access.py` (the sweep fails otherwise).
- [ ] A write: counted by `limits.per_account(...)`; a state change under concurrency: row locks in the order group → student → request, or a unique index.
- [ ] Admin writes are audited (`test_audit.py` checks every one).

## A new field that ends up in a link, a file or a spreadsheet
- [ ] Links: `app/links.py::clean_link` on the server and `safeHref` in the UI.
- [ ] CSV cells: `app/links.py::csv_cell`.
- [ ] Uploads: through `uploads.save` (content checks, re-encoding, clean names).

## A new outbound request
- [ ] Through a guarded transport like `github.GuardedTransport` (fixed hosts, public IPs, no redirects, size cap, timeouts); inputs validated before they reach a URL.

## A new page or component
- [ ] No `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `postMessage` (the unit scans fail otherwise).
- [ ] New-tab links: `rel="noopener noreferrer"`; data-driven `href`s: `safeHref(...)`.
- [ ] Errors shown through `errorMessage` (site) or `friendlyError` (portal).
- [ ] No third-party script, style or font (self-host it; the CSP blocks it anyway).

## Deploying
- [ ] `uv run python -m app.check_config` passes with the production settings (refuses the dev key, demo login, dev codes, plain-http cookies).
- [ ] `SECRET_KEY` 48+ random characters; `COOKIE_SECURE=true`; `ALLOWED_HOSTS`, `CORS_ORIGINS`, `PUBLIC_BASE_URL` set to the real names; `TRUSTED_PROXY_IPS` to the proxy.
- [ ] Proxy: HTTPS only, `client_max_body_size 6m`, a request-rate limit (see SECURITY.md, Deployment layer).
- [ ] Database: least-privilege role, `sslmode=require` if remote, backups scheduled.
