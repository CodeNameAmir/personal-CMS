# Security Summary

**Reviewed Files**: 22
**Issues Resolved**: 11

### Issues Resolved
| Area | File | Line | What Was Happening | Impact | Status | How It Was Fixed |
|---|---|---|---|---|---|---|
| Reverse Proxy & Header Spoofing | `server/security.ts` & `server.ts` | 45, 918 | Express `trust proxy` defaulted to `1`, allowing unproxied deployments to trust attacker-supplied `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` headers. | High | Fixed | Changed `validateTrustProxy` / `parseTrustProxy` default to `false`, rejected `"true"`, validated hop/preset/IP-CIDR entries, and gated `X-Forwarded-*` checks behind `isProxyTrusted(req)`. |
| Public Signup Anti-Abuse & Flood Protection | `server.ts`, `server/security.ts`, `supabase/migrations/0002_deep_security_hardening.sql` | 151, 366, 260 | Express BFF lacked configurable per-IP/global signup controls and static mode relied only on per-username limits, enabling arbitrary-username registration and bcrypt/DB exhaustion. | High | Fixed | Kept public signup enabled while adding configurable IP, username, and global burst caps in Express (`SIGNUP_RATE_LIMIT_*`) plus DB-level global burst/daily limits and probabilistic stale rate-limit cleanup in `lb_signup`. |
| Unbounded In-Memory Rate Limiter Store | `server/security.ts` | 408 | `SlidingWindowRateLimiter` only evicted expired windows when full; active distributed key floods could exceed `maxEntries` and grow memory without bound. | High | Fixed | Rebuilt `SlidingWindowRateLimiter` as a strict memory-bounded LRU `Map` (`store.size <= maxEntries` invariant) with bounded expired-entry sweep followed by oldest-key LRU eviction. |
| PostgreSQL Schema Creation & Function `search_path` | `supabase/migrations/0002_deep_security_hardening.sql` & `supabase/schema.sql` | 14, 145 | `CREATE` privilege on `schema public` was not explicitly revoked from `PUBLIC`/`anon`/`authenticated`, and function `search_path` lacked `pg_catalog` first. | Medium | Fixed | Added `REVOKE CREATE ON SCHEMA public FROM PUBLIC, anon, authenticated` and pinned `search_path = pg_catalog, public` (or `pg_catalog, public, extensions`) across all helper and RPC functions. |
| Non-Empty Category Deletion Foreign Key Defect | `supabase/migrations/0002_deep_security_hardening.sql` & `supabase/schema.sql` | 35, 420 | Composite tenant foreign key `logs_user_category_fkey` had `NO ACTION` on delete, blocking deletion of any category containing logs. | Medium | Fixed | Added `ON DELETE SET NULL (category_id)` on PG 15+ and explicit per-user log `category_id = null` cleanup inside `lb_delete_category` for PG 14/15+ compatibility. |
| Type Coercion, Content-Type & Bulk Input Validation | `server.ts` & `src/utils/logFormatters.ts` | 144, 542, 582 | Mutating endpoints accepted non-JSON `Content-Type` and non-object JSON payloads, coerced `"false"` via `Boolean("false")`, allowed stray `category_id` in non-category bulk requests, and silently fell back on invalid import `pinned`/`created_at`. | Medium | Fixed | Added `requireJsonContentType` (`415`), `requireBodyObject` (`400`), `parseStrictBoolean`, bulk field validation, and strict per-row boolean/timestamp validation in both `server.ts` and `logFormatters.ts`. |
| Import RPC Transaction Abort & Tag Upsert Race | `supabase/migrations/0002_deep_security_hardening.sql` & `supabase/schema.sql` | 450, 505 | Non-array `tags`, non-boolean `pinned`, or malformed `created_at` aborted the entire `lb_import_logs` batch, and concurrent tag creation lacked `ON CONFLICT`. | Medium | Fixed | Added safe `jsonb_typeof` guards and per-row `created_at` exception handling in `lb_import_logs`, plus `ON CONFLICT (user_id, name) DO UPDATE` in `lb_create_or_get_tag` and `lb_bulk_logs_action`. |
| Production Start Script & CI Lockfile Mismatch | `package.json` & `.github/workflows/deploy.yml` | 8, 25 | `npm start` failed with `ERR_MODULE_NOT_FOUND` under Node ESM, and GitHub Actions ran `npm ci` without `package-lock.json` and without test/lint/audit gates. | Medium | Fixed | Bundled `server.ts` into `dist-server/server.mjs` via `esbuild`, updated `npm start`, switched CI to `bun install --frozen-lockfile`, and added `lint`, `test`, and `bun audit` before deploy. |
| Static Hosting Security Headers | `public/_headers` & `deploy/nginx-security.conf` | 1 | Static builds lacked documented security headers (`CSP`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) for Cloudflare/Netlify/Nginx hosts. | Low | Fixed | Added `public/_headers` (copied into `dist/`), `deploy/nginx-security.conf`, and `Permissions-Policy` in `server.ts`. |
| Unused Template Assets Bundled into Build Output | `public/assets/aistudio/*` | — | Unreferenced template/HTML/markdown files in `public/assets/aistudio/` were copied into `dist/assets/aistudio/`. | Low | Fixed | Deleted the unused `public/assets/aistudio/` files so only application assets ship in `dist/`. |
| GitHub Actions Action Version Tags | `.github/workflows/deploy.yml` | 23 | GitHub Actions steps use floating major tags (`@v4`, `@v5`, `@v2`, `@v3`) instead of immutable commit SHAs. | Low | Needs Follow-Up | Offline environment prevented resolving upstream SHA hashes; pin action references to full commit SHAs after pushing. |

### Safeguards Verified
| Area | File | How It's Protected |
|---|---|---|
| Session Storage & Cookies | `server/security.ts`, `src/api/client.ts` | BFF sessions use `HttpOnly` cookies (`SameSite=None; Secure; Partitioned` over trusted HTTPS, `SameSite=Lax` over HTTP); static fallback keeps tokens strictly in memory. |
| CSRF & CORS Controls | `server/security.ts`, `server.ts` | Cookie-authenticated mutating requests verify `Origin`/`Referer` against an explicit allowlist or trusted `Host` plus `X-Requested-With: XMLHttpRequest`; strict CORS never uses `*`. |
| Row-Level Security & Private Helpers | `supabase/schema.sql`, `supabase/migrations/0002_deep_security_hardening.sql` | Direct table access is denied to `anon`/`authenticated`/`PUBLIC` via RLS `deny_direct_access` and `REVOKE ALL`; internal `SECURITY DEFINER` helpers revoke `EXECUTE` from `PUBLIC`, `anon`, and `authenticated`. |
| Password & Token Cryptography | `supabase/schema.sql` | Passwords use SHA-256 pre-hashed bcrypt (`v2:`, cost 12, 12–128 chars); session (`lbs_`) and webhook (`lbk_`) tokens are stored only as SHA-256 hashes. |
| CSV Spreadsheet Injection | `src/utils/logFormatters.ts` | Formula prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`, including after leading whitespace) are prefixed with `'` during CSV export. |
| Error Sanitization | `server.ts`, `server/supabaseProxy.ts` | Internal SQL/stack errors map to generic `Internal server error.` (`500 INTERNAL_ERROR`) responses without leaking internal table or schema names. |

## PoC Verification

### Unverified Reverse Proxy Header Spoofing
#### Summary
| Field | Value |
|---|---|
| Issue Type | Trusted Proxy Default & Header Spoofing |
| Impact | High |
| Affected File | `server/security.ts:45`, `server.ts:918` |
| Test Scenario | `POST /api/auth/login` with spoofed `X-Forwarded-Proto: https`, `X-Forwarded-Host: attacker.example`, `Origin: https://attacker.example`, and `X-Forwarded-For` IP rotation on `POST /api/auth/signup`. |

#### How It Was Fixed
Defaulted `TRUST_PROXY` parsing (`validateTrustProxy` / `parseTrustProxy`) to `false`, rejected `"true"`, and gated both `isHttpsRequest` and `isOriginAllowed` behind explicit Express `trust proxy` configuration (`isProxyTrusted(req)`).

#### Step-by-Step Trace
| Step | What Happens in the Code | Outcome |
|---|---|---|
| 1 | Request with spoofed `X-Forwarded-*` headers arrives at default `createApp()`. | `app.get('trust proxy')` is `false`. |
| 2 | `isOriginAllowed()` checks `isProxyTrusted(req)` (`server/security.ts:281`). | `X-Forwarded-Host` is ignored; `Origin` does not match `Host` and returns `403 FORBIDDEN_ORIGIN`. |
| 3 | Without foreign `Origin`, `buildSessionCookieAttributes()` calls `isHttpsRequest(req)` (`server/security.ts:187`). | `X-Forwarded-Proto` is ignored over plain HTTP; cookie omits `Secure`. |
| 4 | Rotated `X-Forwarded-For` headers hit `/api/auth/signup`. | `getClientIp(req)` uses actual socket IP; HTTP `429` triggers after the configured IP cap (`SIGNUP_RATE_LIMIT_IP_MAX`). |

#### Conclusion
**Fix Verified** — Automated integration tests confirm spoofed `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For` headers are ignored unless a trusted proxy is explicitly configured.

### Strict Boolean Coercion & Per-Row Import Resilience
#### Summary
| Field | Value |
|---|---|
| Issue Type | Improper Input Type Coercion & Batch Abort |
| Impact | Medium |
| Affected File | `server.ts:542,665,736,869`, `supabase/migrations/0002_deep_security_hardening.sql:505` |
| Test Scenario | `POST /api/logs` and `POST /api/webhook` with `{"message":"hello","pinned":"false"}`; `parseImportJSON` and `lb_import_logs` with `pinned: "maybe"` and `created_at: "not-a-date"`. |

#### How It Was Fixed
Replaced truthy `Boolean(...)` coercion with `parseStrictBoolean` in `server.ts`, added strict boolean/timestamp error reporting in `src/utils/logFormatters.ts`, and added `jsonb_typeof` and exception-guarded `timestamptz` parsing inside `lb_import_logs`.

#### Step-by-Step Trace
| Step | What Happens in the Code | Outcome |
|---|---|---|
| 1 | `POST /api/logs` receives `{"message":"hello","pinned":"false"}`. | Passes `requireJsonContentType` and `requireBodyObject`. |
| 2 | `parseStrictBoolean(body.pinned, false)` inspects `typeof value === 'boolean'` (`server/security.ts:112`). | Returns `{ ok: false }` instead of coercing `"false"` to `true`. |
| 3 | Route throws `BffError('Pinned field must be a boolean.', 400, 'VALIDATION_ERROR')`. | Client receives HTTP `400`; valid import rows succeed while bad rows increment `failed`. |

#### Conclusion
**Fix Verified** — Automated server and formatter tests confirm `"false"` is rejected with HTTP `400` and malformed import rows fail cleanly per row.
