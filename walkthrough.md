# Security Summary

This audit and remediation hardened the Logbook application across PostgreSQL/Supabase, the Express Backend-for-Frontend (BFF), and the React frontend while preserving all existing features, bilingual English/Persian UI, themes, and user data.

## Key Remediations Implemented

1. **PostgreSQL Function Privileges & `SECURITY DEFINER` Isolation (`supabase/migrations/0001_security_hardening.sql`, `supabase/schema.sql`)**
   - Configured `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated` so future functions are never exposed by default.
   - Revoked public execution from internal helpers (`lb_hash_token`, `lb_is_valid_hex_color`, `lb_normalize_username`, `lb_normalize_tag`, `lb_default_tag_color`, `lb_hash_password`, `lb_verify_password`, `lb_check_rate_limit`, `lb_require_session`, `lb_hydrate_log`, `lb_find_or_create_category`, `lb_sync_log_tags`), and restricted `lb_cleanup_expired_sessions` to `service_role`.
   - Fixed `search_path = public, pg_catalog` and explicit schema qualification on every `SECURITY DEFINER` function.
   - Added strict caller ownership checks inside `lb_hydrate_log(uuid, uuid)`, `lb_find_or_create_category(uuid, text)`, `lb_sync_log_tags(uuid, uuid, text[])`, `lb_create_log`, `lb_update_log`, and `lb_bulk_logs_action`.

2. **Cross-Tenant Authorization & Database Integrity**
   - Enforced composite foreign keys `(user_id, category_id) -> categories(user_id, id)` on `logs` and `(user_id, log_id)` / `(user_id, tag_id)` on `log_tags` (with safe backfill and orphaned cross-tenant cleanup in the migration).
   - Validated case-insensitive unique usernames (`lower(username)`) safely before creating `idx_users_username_lower`.
   - Added explicit `deny_direct_access` RLS policies and `REVOKE ALL` on every table in `public`.
   - Updated `lb_bulk_logs_action`, `lb_create_log`, and `lb_update_log` to reject foreign/nonexistent `category_id` values instead of silently stripping them.

3. **Authentication, Session Management & Password Hardening**
   - Migrated Express-hosted authentication to `HttpOnly` cookie sessions (`lb_session`) with `Path=/`, `Max-Age=604800`, and `Secure; SameSite=None; Partitioned` over HTTPS (`SameSite=Lax` on local HTTP), removing all `localStorage` session token/user storage from `src/api/client.ts`.
   - Updated `lb_change_password` to revoke all existing sessions and issue a rotated session token, updating the browser `HttpOnly` cookie automatically.
   - Enforced 12–128 character passwords on signup and password change, pre-hashed passwords with SHA-256 before bcrypt cost-12 (`v2:` format) to eliminate bcrypt's 72-byte truncation limit, and preserved backward compatibility with legacy cost-10 hashes via transparent rehash on login.
   - Removed per-request `DELETE FROM sessions` in `lb_require_session`, added `idx_sessions_expires_at`, and added `lb_cleanup_expired_sessions` plus a 6-hour background cleanup interval in `server.ts`.

4. **Rate Limiting, CSRF, Security Headers & Input Validation**
   - Added PostgreSQL rate limiting (`public.lb_rate_limits` + `lb_check_rate_limit`) and Express sliding-window rate limiting (`SlidingWindowRateLimiter`) returning HTTP `429` + `Retry-After` on login, signup, password change, token creation, bulk operations, imports, exports, and webhooks.
   - Added CSRF middleware requiring `X-Requested-With: XMLHttpRequest` and `Origin`/`Referer` host verification on mutating cookie-authenticated BFF routes, while exempting Bearer-authenticated `/api/webhook`.
   - Added `helmet` security headers (CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, production HSTS), strict CORS without wildcard `*` on `/api/*`, bounded `trust proxy = 1`, payload size caps (`100 KB` default / `1 MB` import), and sanitized error responses.
   - Enforced `#RRGGBB` hex color validation on database, server, and UI layers (`safeHexColor`), capped tags per log (25), log message length (10,000), bulk IDs (200), import rows (500), and strengthened CSV formula injection neutralization.

5. **Server-Side Pagination & Scalability**
   - Upgraded `lb_get_workspace` and `/api/workspace` to perform filtering, sorting, pagination (`1..100`), and SQL-aggregated `stats` server-side, eliminating N+1 hydration and unbounded client-side workspace loading.

---

## PoC Verification

### 1. Automated Unit & BFF Integration Suite (`node:test`)
- **Command**: `npx --yes tsx --test src/utils/logFormatters.test.ts src/i18n/translations.test.ts server/security.test.ts`
- **Coverage & Results (15/15 passing)**:
  - Verified `HttpOnly`, `SameSite`, `Secure`, `Partitioned`, and `Max-Age` cookie attributes on signup/login/change-password/logout and confirmed raw tokens are never returned in JSON bodies.
  - Verified CSRF rejection (`403 CSRF_REQUIRED` / `403 FORBIDDEN_ORIGIN`) on missing `X-Requested-With` or disallowed `Origin`/`Referer`, and confirmed `/api/webhook` works with `Authorization: Bearer lbk_...`.
  - Verified HTTP `429` + `Retry-After` rate-limit enforcement on repeated login attempts.
  - Verified rejection of weak passwords (`< 12` chars), invalid usernames, invalid UUIDs, invalid hex colors (`javascript:alert(1)`), oversized messages (`> 10,000`), excess tags (`> 25`), excess bulk IDs (`> 200`), malformed JSON, and sanitized `500` responses with zero stack/SQL leakage.
  - Verified CSV formula injection neutralization (`=`, `+`, `-`, `@`, `\t`, leading whitespace) and import size/row limits.

### 2. Build, Type Check & Dependency Audit
- `tsc --noEmit` (`npm run lint`): passed with 0 errors.
- `vite build` (`npm run build`): passed cleanly.
- `bun audit --json`: exited 0 with `{}` (0 known dependency vulnerabilities).

### 3. Headless Browser Verification (`playwright-cli` on `http://localhost:3000`)
- Verified `GET /api/config` returns `bffEnabled: true` without exposing secret keys and includes `Content-Security-Policy` and `X-Content-Type-Options: nosniff`.
- Verified unauthenticated `GET /api/workspace` returns HTTP `401`.
- Verified `localStorage` contains no session tokens (`logbook_session_token` and `logbook_session_user` are `null`).
- Verified English (LTR) and Persian (RTL) AuthScreen rendering and signup `minlength="12"` / `maxlength="128"` / username `maxlength="64"` attributes.
- **Note**: Live PostgreSQL credentials are not present in this sandbox environment; therefore, executing `supabase/migrations/0001_security_hardening.sql` against the live Supabase project is documented in deployment instructions for the repository owner.
