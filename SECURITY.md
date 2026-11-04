# CapstoneConnect security

Three apps: the API (`capstoneconnectbackend`, FastAPI + PostgreSQL), the student site
(`3dcapconnectfrontend`, Next.js) and the admin portal (`adminportal`, Vite). Every class below is
either **covered** (by code, with the test that proves it by sending the attack), **not
applicable** (with the reason and the test or guard that keeps it so), or left to the
**deployment** layer (with the one setting that does it).

Test files: API `tests/attacks/*.py` (plus `tests/test_*.py`); site `tests/unit/security.test.ts`,
`e2e/security.spec.ts`, `e2e/xss.security.spec.ts`, `e2e/https.spec.ts`; portal
`tests/unit/security.test.ts`. Run: `uv run pytest` · `npm run test:unit` · `npx playwright test`.

## Injection

| Class | Status | Proof |
| --- | --- | --- |
| SQL injection | Covered: SQLAlchemy binds every value; no SQL built from strings; sort fields are `Literal` allowlists | `test_injection.py::test_sql_payloads_in_search_change_nothing`, `::test_sql_payload_is_stored_as_text`, `::test_no_raw_sql_built_from_strings` |
| LIKE wildcard injection | Covered: `%`, `_`, `\` escaped (`app/search.py`) | `test_injection.py::test_like_wildcards_are_matched_literally` |
| NoSQL operator injection | Covered: strict typed models refuse `{"$ne": …}` | `test_injection.py::test_operator_objects_are_refused` |
| LDAP / XPath injection | N/A: no LDAP or XML store; the payloads are in the fuzz corpus and come back as text | `test_fuzz_routes.py` (corpus `payloads.LDAP_XPATH`) |
| Command injection | N/A by guard: no subprocess, `os.system`, shells | `test_injection.py::test_no_dangerous_imports_or_calls`, `::test_shell_metacharacters_are_plain_text` |
| SSTI | N/A by guard: no template engine; text stays text | `test_injection.py::test_template_syntax_is_never_evaluated`, `test_abuse.py::test_no_server_side_rendering_of_user_text` |
| Unsafe deserialization | N/A by guard: no pickle, marshal, shelve, yaml, jsonpickle | `test_injection.py::test_no_dangerous_imports_or_calls` |
| XML / XXE | N/A by guard: no XML parser; XML bodies refused (415) | `test_injection.py::test_no_dangerous_imports_or_calls`, `test_abuse.py::test_no_body_format_but_json_and_multipart_is_read` |
| Mass assignment | Covered: every request model `extra="forbid"`; locked fields ignored by name | `test_access.py::test_no_body_accepts_privileged_fields`, `::test_signup_can_not_set_privileged_fields`, `::test_ignored_profile_fields_really_are_ignored`, `test_input_models.py` |
| Unbounded input | Covered: every string `max_length`, every list `max_items`, every query/path string bounded | `test_input_models.py::test_request_bodies_are_strict_and_bounded`, `::test_query_and_path_strings_are_bounded` |
| ReDoS | Covered: every regex reviewed and bounded (two quadratic GitHub patterns fixed) | `test_injection.py::test_every_regex_runs_in_linear_time`, `::test_regex_inventory_is_reviewed` |
| Log injection | Covered: one line per entry, control/ANSI escaped, 4000-char cap, secrets masked | `test_abuse.py::test_log_lines_can_not_be_forged_or_colour_the_terminal`, `::test_the_filter_is_installed_on_the_app_handlers` |
| Header / CRLF injection | Covered: request ids sanitised; download names stripped of CR/LF and quotes | `test_takeover.py::test_request_ids_are_never_echoed_raw`, `::test_download_names_can_not_inject_headers` |
| Fuzzing (all routes) | Every OpenAPI route × position × role: no 500, no leak, no unescaped echo; Schemathesis property run | `test_fuzz_routes.py`, `test_schemathesis.py`, `test_route_inventory.py` |

## Browser

| Class | Status | Proof |
| --- | --- | --- |
| Stored / reflected XSS | Covered: React escapes; no HTML sinks anywhere; JSON answers with `nosniff`; Playwright stores payloads in every field and renders both apps | site + portal `test:unit` "no raw HTML sinks", `e2e/xss.security.spec.ts` "stored XSS payloads stay text", `test_output.py::test_xss_payloads_come_back_as_json_text` |
| `javascript:` / `data:` links | Covered: server refuses them (`app/links.py`); both apps render data hrefs only through `safeHref` | `test_output.py::test_announcement_links_refuse_scripts_and_redirect_tricks`, `::test_github_repo_links_are_rebuilt_not_trusted`, unit "every href built from data goes through safeHref" |
| Open redirect | Covered: `?next=` only same-site paths (`//`, `/\`, tab/newline, encoded, schemes refused) | unit "safeNextPath … stays on this site", `e2e/security.spec.ts` "log-in ?next= only goes to pages on this site" |
| Reverse tabnabbing | Covered: `rel="noopener noreferrer"` on every new tab | unit "every new-tab link has rel=…" (both apps) |
| Prototype pollution | Covered: network JSON parsed without `__proto__`/`constructor`/`prototype` | unit "network JSON can't pollute Object.prototype", portal "API answers can't pollute" |
| DOM clobbering | Covered: no HTML from data, no globals read by name; Playwright plants clobbering markup | unit "no cross-window messaging and no globals read by name", e2e XSS sweep (`getElementById` intact) |
| postMessage | N/A by guard: no `postMessage` or `message` listeners | unit tests (both apps) |
| CSV / formula injection | Covered: cells starting `= + - @ \t \r` prefixed with `'` | `test_output.py::test_csv_export_neutralises_formulas` |
| CSP | Site: `default-src 'self'`, no `unsafe-eval` in production, `frame-ancestors 'none'`; `'unsafe-inline'` scripts kept only for Next's own flight data (verified: SRI + `script-src 'self'` stops hydration). Portal: `script-src 'self'`. API: `default-src 'none'`. Docs: self-hosted assets | `e2e/xss.security.spec.ts` "our only inline scripts are Next.js's own", `e2e/security.spec.ts` "security headers…", `test_abuse.py::test_api_docs_load_nothing_from_other_sites` |
| Clickjacking | Covered: `frame-ancestors 'none'` + `X-Frame-Options: DENY` everywhere except the docs (portal only) | `e2e/xss.security.spec.ts` "clickjacking: a foreign page can't frame…", `test_abuse.py::test_api_answers_can_not_be_framed`, `::test_docs_may_only_be_framed_by_the_portal` |
| Third-party scripts | Covered: none. Fonts self-hosted by Next; API docs (Swagger UI, ReDoc) vendored under `app/static/docs` | `test_abuse.py::test_api_docs_load_nothing_from_other_sites` |
| Secrets in bundles | Covered: build scan for keys, tokens, URLs with passwords and every private env value | `scripts/check-bundle-secrets.mjs` (CI step, both apps) |
| Error details | Covered: API 500s are generic with a request id; UIs never show JS errors or stacks | `test_fuzz_routes.py` (leak markers), unit "the UI never shows raw error text", portal "never shows raw error text" |
| Caching of personal data | Covered: `Cache-Control: no-store` on every API answer | `test_abuse.py::test_api_answers_are_never_cached` |

## Authentication, sessions, access control

| Class | Status | Proof |
| --- | --- | --- |
| JWT forgery | Covered: HS256 pinned (header checked), `exp iat iss aud sub sid kind` required, one audience per kind, `iat` in the future refused | `test_tokens_sessions.py::test_forged_student_tokens_are_refused` (25 forgeries incl. `alg: none`, HS512, wrong key/audience/issuer/kind, no exp, tampering), `::test_forged_admin_tokens_are_refused`, `::test_tokens_never_cross_audiences` |
| Weak signing key | Covered: `SECRET_KEY` under 32 characters refuses to start; production check refuses the dev key | `test_tokens_sessions.py::test_short_or_default_secret_keys_are_refused`, `test_production.py` |
| Session replay after logout | Covered: server-side `auth_sessions`; logout revokes the row | `test_tokens_sessions.py::test_stolen_cookie_dies_with_logout`, `::test_admin_stolen_cookie_dies_with_logout_and_logout_all`, `::test_stolen_cookie_can_not_open_the_socket_after_logout`, `e2e/security.spec.ts` "log out on all devices…" |
| Session fixation | Covered: every sign-in makes a new row and revokes the one presented | `test_tokens_sessions.py::test_login_always_issues_a_new_session_and_revokes_the_old` |
| Sign out everywhere | Covered: `/auth/logout-all`, `/admin/auth/logout-all`, in both UIs | `test_tokens_sessions.py::test_sign_out_everywhere` |
| Sessions after password change, reset, suspension, block, deletion, deactivation | Covered: all revoked (and not revived by unbanning) | `test_tokens_sessions.py::test_password_reset_ends_every_session`, `::test_admin_actions_end_sessions_for_good`, `::test_admin_deactivation_and_password_change_end_sessions` |
| Cookie theft / overwrite | Covered: `HttpOnly`, `SameSite=Lax`, `Secure` + `__Host-` prefix over HTTPS (no Domain) | `test_tokens_sessions.py::test_session_cookies_are_httponly_samesite_and_host_only`, `::test_secure_cookies_use_the_host_prefix`, `test_production.py::test_cookie_attributes_for_each_layout`, `e2e/https.spec.ts` |
| CSRF | Covered: cookie-carrying writes need an allowed Origin/Referer; bodies only JSON or multipart | `test_access.py::test_student_writes_from_another_origin_are_refused` (null, look-alikes), `::test_admin_writes_from_another_origin_are_refused`, `::test_simple_request_content_types_are_refused`, `::test_logout_can_not_be_forced_from_another_site` |
| IDOR | Covered: every id route has an attack case or a documented public reason; the sweep fails on a new uncovered route | `test_access.py::test_every_id_route_is_covered`, `::test_idor`, `::test_attachments_are_only_for_the_conversation`, `::test_profiles_hide_phone_numbers_from_strangers`; admin routes: `test_audit.py::test_every_admin_route_needs_an_admin`, `::test_read_only_admins_cannot_write_anywhere` |
| Brute force / credential stuffing | Covered: per-account lock-out with doubling back-off (15 min → 1 day), shared by every phone format and email spelling, kept in PostgreSQL; per-IP limits on top | `test_takeover.py::test_number_formats_share_one_lock_out`, `::test_lock_out_grows_after_each_further_failure`, `::test_admin_lock_out_is_per_account_across_spellings`, `::test_unknown_numbers_lock_too`, `test_races.py::test_logging_in_many_times_at_once_counts_every_failure` |
| Account takeover via reset | Covered: OTP hashed with the key, attempts counted atomically, one code → one grant, grant single-use and expiring, all sessions end | `test_takeover.py::test_reset_grant_works_once`, `::test_reset_grant_used_twice_at_the_same_moment_works_once`, `::test_expired_reset_grant_is_refused`, `::test_one_code_gives_one_grant`, `::test_parallel_code_guesses_can_not_exceed_the_attempt_limit` |
| OTP limits bypass (format, IP, User-Agent) | Covered: keyed by the normalised number; forwarded headers ignored unless a proxy is trusted | `test_takeover.py::test_code_requests_share_one_limit_across_number_formats`, `::test_otp_limits_can_not_be_dodged_with_headers` |
| User enumeration | Covered: same answers for unknown numbers; dummy hash for timing | `test_takeover.py::test_answers_do_not_tell_which_numbers_exist`, `test_password_reset.py::test_unknown_numbers_get_the_same_answer` |
| Host header poisoning | Covered: `ALLOWED_HOSTS`; links only from `PUBLIC_BASE_URL` | `test_takeover.py::test_host_header_poisoning_is_refused`, `::test_no_link_is_built_from_the_request_host`, `::test_unknown_hosts_are_refused` |
| Weak / breached passwords | Covered: common list + leetspeak, years, symbols, keyboard and alphabet runs, repeats, short numbers, the phone number | `test_takeover.py::test_breached_and_guessable_passwords_are_refused`, `::test_signup_refuses_a_breached_password` |
| WebSocket abuse | Covered: origin exact-match, 2 KB frames, text only, strict schema, 30 frames/10 s, 10 sockets per account, process cap, 90 s idle, session re-checked | `test_websocket.py` (all) |
| OAuth / SSO, MFA | N/A: phone + password only; no OAuth or MFA endpoints exist | `test_abuse.py::test_no_graphql_oauth_mfa_xml_or_import_endpoints_exist` |
| GraphQL | N/A as a server (the API only calls GitHub's) | `test_abuse.py::test_no_graphql_oauth_mfa_xml_or_import_endpoints_exist` |

## WebSocket message layer

What happens to frames once a socket is open (`app/routers/realtime.py`, `app/realtime.py`; the
site's client `lib/realtime/`). Tests: `tests/attacks/test_ws_*.py` and `test_websocket.py`.

| Class | Status | Proof |
| --- | --- | --- |
| Fuzzing over frames | Covered: every frame type × every field × the payload corpus (SQL, operators, shell, SSTI, XSS, CRLF, unicode, NUL, sizes, nesting, privileged fields), as anonymous, student and admin cookie; never an unhandled error, a leak or an echo to another participant | `test_ws_messages.py::test_fuzz_every_frame_type_and_field_as_a_student`, `::test_a_single_frame_never_kills_the_connection`, `::test_anonymous_sockets_never_get_to_send_anything`, `::test_an_admin_session_is_not_a_socket_session` |
| Frame inventory | Covered: every accepted type classified (roles, object it is authorized against, what it writes) | `test_ws_messages.py::test_every_frame_type_is_classified`, `::test_unknown_frame_types_do_nothing` |
| Schema validation | Covered: one strict model per type (`extra="forbid"`, strict JSON types, every field required, ids `^[A-Za-z0-9_-]{1,64}$`); depth checked before parsing; duplicate keys and `NaN`/`Infinity` refused; refusals answer `{type:error, code:invalid}` | `test_ws_schema.py::test_frames_must_match_their_type_exactly`, `::test_duplicate_keys_and_non_json_numbers_are_refused`, `::test_each_type_has_its_own_strict_schema` |
| Injection over frames | Covered: ids only, ORM lookups by key, no LIKE, constant SQL with bound parameters (`LISTEN` via `psycopg.sql.Identifier`) | `test_ws_schema.py::test_database_calls_reachable_from_a_frame_are_parameterized`, fuzz |
| Mass assignment over frames | Covered: privileged fields refused, never applied; the sender is always the connection | `test_ws_schema.py::test_privileged_fields_are_refused_and_never_applied`, `::test_the_real_sender_is_always_the_connection` |
| Unsafe parsing | Covered: strict JSON only (no eval/exec, pickle, yaml, xml, templates on the socket path) | `test_ws_schema.py::test_frames_are_parsed_one_strict_way_only` |
| IDOR over frames | Covered: every frame naming a conversation re-checks participation in the database (never cached); unknown and foreign ids answer the same `forbidden` | `test_ws_access.py::test_a_frame_naming_someone_elses_conversation_is_refused`, `::test_unknown_and_existing_conversations_answer_the_same`, `::test_removed_from_a_group_mid_session_can_no_longer_use_its_chat`, `::test_typing_shows_the_current_name_not_one_cached_at_connect` |
| Lead-only socket actions | N/A: none exist (accept, remove, invite are HTTP only) | `test_ws_access.py::test_no_socket_action_needs_or_grants_a_role` |
| XSS through pushed content | Covered: the client checks every event's shape (`lib/realtime/events.ts`) and renders text as React text; a hostile name and hostile messages pushed live stay inert | site `tests/unit/realtime-events.test.ts`, `e2e/xss.security.spec.ts` "payloads pushed live over the socket render as text" |
| Tokens in the URL | Covered: never read from the query string | `test_ws_sessions.py::test_a_token_in_the_query_string_is_never_read`, `test_ws_hardening.py::test_a_ticket_in_the_url_is_not_read` |
| Sockets outliving their session | Covered: log-out closes that session's socket; sign out everywhere, password reset or change, suspension, block, deletion close all; every acting frame re-checks the session | `test_ws_sessions.py` (`test_logout_closes_that_sessions_socket_now` … `test_a_revoked_session_is_refused_on_the_next_frame_even_without_the_push`) |
| CSWSH (cross-site socket hijacking) | Covered (code side): exact Origin check plus a one-time ticket, bound to the session, required as the first frame; a valid cookie alone is refused. Edge-side controls: see SECURITY_CHECKLIST.md | `test_ws_hardening.py::test_a_valid_cookie_without_a_ticket_is_refused`, `::test_a_ticket_works_once`, `::test_a_ticket_is_bound_to_its_session`, `::test_tickets_can_not_be_had_cross_site_or_signed_out`, e2e "WebSocket: … no ticket is refused" |
| Dead or stuck clients | Covered: server heartbeat (30 s, 20 s to answer → 4408), separate from the 90 s idle timeout | `test_ws_hardening.py::test_a_client_that_never_answers_the_heartbeat_is_closed`, `::test_a_wrong_acknowledgement_does_not_count` |
| Slow consumers (backpressure) | Covered: outbound queue bounded at 256; a peer that can't keep up is closed once (1013) without slowing others | `test_ws_hardening.py::test_a_slow_consumer_has_a_bounded_queue_and_is_cut_off`, `::test_a_slow_consumer_does_not_slow_the_others` |
| Write spam through one socket | Covered (code side): per-account budgets inside the handlers — receipts shared with `POST /conversations/{id}/read`, typing across all of an account's sockets — plus the per-connection frame limit | `test_ws_hardening.py::test_receipts_share_one_limit_between_http_and_the_socket`, `::test_socket_receipts_count_against_the_http_limit`, `::test_typing_is_limited_per_account_across_all_its_sockets` |
| Races through frames | Covered: receipts from many sockets at once settle once; no seat, join or request action exists on the socket | `test_ws_sessions.py::test_receipts_racing_from_many_sockets_settle_once`, `::test_no_seat_join_or_request_action_exists_on_the_socket` |
| Sign-in / OTP over the socket | N/A: no such frames (they share nothing because they don't exist) | `test_ws_sessions.py::test_sign_in_and_otp_can_not_be_driven_over_the_socket` |
| GraphQL subscriptions | N/A: no endpoint, no server library, no runtime dependency | `test_ws_sessions.py::test_no_graphql_subscription_endpoint_exists`, `::test_no_graphql_server_exists` |

## Abuse and availability

| Class | Status | Proof |
| --- | --- | --- |
| Race conditions | Covered: row locks in one order (group → student → request), unique indexes, atomic counters | `test_races.py` (last seat, double accept, two groups, duplicate invites/requests/reports, message `client_id`, one attachment twice, delete during join, double sign-up) |
| Request size / shape DoS | Covered: 1 MB JSON, 6 MB uploads (also while streaming), depth 32, arrays 5000, duplicate keys refused | `test_abuse.py::test_oversized_json_bodies_are_refused`, `::test_oversized_bodies_without_a_length_are_cut_off`, `::test_deeply_nested_json_is_refused`, `::test_huge_arrays_are_refused`, `test_uploads.py::test_uploads_over_the_cap_are_cut_off_while_streaming` |
| Paging / export DoS | Covered: page sizes capped; CSV export capped at 50,000 rows | `test_abuse.py::test_page_sizes_are_capped`, `::test_admin_page_sizes_are_capped`, `test_output.py::test_csv_export_is_bounded` |
| Slow queries | Covered: `statement_timeout` (15 s) and idle-transaction timeout; a cancelled query answers 503 | `test_abuse.py::test_statement_timeout_is_set`, `::test_a_slow_query_is_cut_off_and_answers_503` |
| Write spam | Covered: per-account limits (messages, requests, invitations, recommendations, groups, profile edits, uploads, reports, GitHub lookups) | `test_abuse.py::test_write_limits_stop_scripts`, `::test_write_limits_are_per_account`, `::test_group_creation_is_limited`, `::test_github_lookups_are_limited_per_address` |
| Over-sharing in answers | Covered: response models on every route; internal fields never sent | `test_abuse.py::test_answers_never_carry_internal_fields`, `::test_every_json_route_declares_what_it_answers` |
| SSRF (GitHub client) | Covered: strict usernames; only `https://api.github.com` / `github.com:443`; public IPs at resolve and on the socket (DNS rebinding); no redirects; 2 MB identity bodies; timeouts | `test_ssrf.py` (all) |
| Malicious uploads | Covered: type by content; images decoded and re-encoded (metadata, polyglots and trailing data gone; pixel bombs refused); PDFs with JS/actions/embedded files or HTML refused; ZIP/DOCX directory checked (bombs, slip names, nesting) and never extracted; names cleaned; always `attachment`, `nosniff`, sandbox CSP | `test_uploads.py` (all), `test_injection.py::test_archives_are_never_extracted` |
| Path traversal / zip slip | Covered: stored names must match `^[a-z]{3}_[0-9a-f]{16}\.(ext)$` before storage is touched; zips never extracted | `test_uploads.py::test_path_traversal_finds_nothing`, `HOSTILE["zip slip"]` |
| Parameter pollution | Covered: a repeated query parameter is refused (400) | `test_abuse.py::test_duplicate_query_parameters_are_refused` |
| Verb tampering / method override | Covered: unknown methods 405; `X-HTTP-Method-Override` ignored | `test_route_inventory.py` |
| CORS | Covered: exact origins; `null` and look-alikes get no `Access-Control-Allow-Origin` | `test_abuse.py::test_cors_never_trusts_null_or_look_alike_origins` |
| Vulnerable dependencies | Covered: exact versions, lockfiles committed; CI fails on `npm audit --omit=dev --audit-level=high` and on any `pip-audit` finding | `.github/workflows/ci.yml` (all three) |

## Deployment layer (not in the code)

| Concern | Setting |
| --- | --- |
| TLS everywhere, HSTS | Terminate HTTPS at the proxy; set `COOKIE_SECURE=true` (the API then sends `Strict-Transport-Security`). |
| WebSocket at the edge | Keep the proxy from buffering socket frames, cap upgrades per IP and total open sockets, and bot rules on `/api/ws` and `/api/realtime/ticket` (the app enforces the per-account and per-connection side). |
| Real client IPs for per-IP limits | `TRUSTED_PROXY_IPS=<proxy address>` (otherwise forwarded headers are ignored). |
| Volumetric DDoS / connection floods | At the proxy or CDN, e.g. nginx `limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;`. |
| Body size before the app | nginx `client_max_body_size 6m;` (matches `MAX_UPLOAD_BODY_BYTES`). |
| WebSocket frame size at the server | Set in `docker-entrypoint.sh`: `--ws-max-size 65536 --limit-concurrency 500 --timeout-keep-alive 10` (the app also closes frames over 2 KB). |
| Database credentials and transport | A least-privilege PostgreSQL role; `DATABASE_URL=…?sslmode=require` when the database is remote. |
| Secrets | From the host's secret store, never in the image; rotate `SECRET_KEY` to sign everyone out. |
| Backups | `scripts/db_backup.py` on a schedule (see DEPLOY.md). |
