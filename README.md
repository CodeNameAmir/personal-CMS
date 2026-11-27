# Logbook

A fast, bilingual (**English LTR** & **Persian RTL**) structured log manager built with React, Vite, Tailwind CSS, Express, and **Supabase PostgreSQL**. Supports both a hardened **Express Backend-for-Frontend (BFF)** runtime and static deployment to **ArvanCloud Object Storage** and **GitHub Pages** (`log.codenameamir.ir`).

---

## Features

- **Dual-Mode Security Architecture**:
  - **Express BFF Mode (`server.ts`)**: Stores sessions in `HttpOnly` cookies (`SameSite`, `Secure` over HTTPS), enforces CSRF protection (`Origin`/`Referer` verification + `X-Requested-With`), memory-bounded LRU rate limiting (with configurable IP/username/global signup protections), `Content-Type: application/json` enforcement, Helmet CSP/Permissions-Policy security headers, strict CORS, and bounded request payloads.
  - **Static Hosting Fallback**: Deployable as a static SPA to ArvanCloud Object Storage and GitHub Pages without exposing `localStorage` session tokens (keeps session tokens strictly in memory when no BFF is present) while relying on Supabase RLS-locked tables, hardened `SECURITY DEFINER` RPCs, and `public/_headers` / `deploy/nginx-security.conf` security headers.
- **Hardened PostgreSQL / Supabase Layer**:
  - Row-Level Security (`RLS`) with explicit `deny_direct_access` policies, `REVOKE CREATE ON SCHEMA public`, and `REVOKE ALL` across all tables (`users`, `sessions`, `api_tokens`, `categories`, `tags`, `logs`, `log_tags`, `lb_rate_limits`).
  - Locked-down `SECURITY DEFINER` functions with pinned `search_path = pg_catalog, public, extensions`, ownership checks, composite tenant foreign keys, SHA-256 session/API token hashing, SHA-256 pre-hashed bcrypt (`v2:`, cost 12) password hashing (6–128 characters, backward-compatible with legacy hashes), and database-backed rate limiting (including global signup flood protection).
- **Server-Side Pagination & Analytics**: Filtering, search, sorting, pagination (`1..100` per page), and 30-day / category / tag dashboard statistics computed in PostgreSQL.
- **Categories & Multi-Tagging**: Color-coded (`#RRGGBB` validated) categories and `#tags` with `Any` / `All` match modes and inline creation.
- **Pinning & Bulk Actions**: Pin critical entries to the top of the feed and perform bulk pin, unpin, category move, tag assignment, or delete operations (capped at 200 items per request).
- **Collapsible Sidebar**: Collapse the left/right sidebar on desktop into a compact rail to maximize horizontal reading space.
- **Import & Export**: Import up to 500 records (1 MB max) and export up to 5,000 logs in **JSON** and **CSV** formats with spreadsheet formula-injection protection and strict boolean/timestamp validation.
- **API Tokens & Webhooks**: Generate `lbk_...` API tokens and ingest automated logs via the Express BFF (`POST /api/webhook`) or directly via Supabase RPC (`POST /rest/v1/rpc/lb_ingest_webhook`).
- **Bilingual & Multi-Theme**: Instant English (LTR) / Persian (RTL) switching plus Dark (Graphite), Midnight, and Light themes.

---

## 1. Supabase Setup

1. Create a project in [Supabase](https://supabase.com/).
2. Open **SQL Editor** in your Supabase Dashboard:
   - **Fresh installation**: Run the full contents of [`supabase/schema.sql`](supabase/schema.sql).
   - **Upgrading an existing database**: Run [`supabase/migrations/0001_security_hardening.sql`](supabase/migrations/0001_security_hardening.sql), [`supabase/migrations/0002_deep_security_hardening.sql`](supabase/migrations/0002_deep_security_hardening.sql), and [`supabase/migrations/0003_relax_password_min_length.sql`](supabase/migrations/0003_relax_password_min_length.sql) (preserves existing user data while upgrading schema privileges, constraints, indexes, function `search_path`, DB signup flood limits, import resilience, and 6-character minimum passwords).
   - *(Optional verification)*: Run [`supabase/tests/security_verification.sql`](supabase/tests/security_verification.sql) against a staging database (wrapped in `BEGIN; ... ROLLBACK;`) to verify privilege lockdown and tenant isolation.
3. From **Project Settings → API**, copy:
   - **Project URL** (`SUPABASE_URL` / `VITE_SUPABASE_URL`)
   - **Publishable / Anon Key** (`SUPABASE_PUBLISHABLE_KEY` / `VITE_SUPABASE_PUBLISHABLE_KEY`)
   - *(Optional, server-only)* **Secret / Service Role Key** (`SUPABASE_SECRET_KEY`) for scheduled expired-session & rate-limit cleanup in Express BFF mode.

> **Security Note**: Never place `SUPABASE_SECRET_KEY` or `service_role` in `VITE_*` variables or static frontend builds. Only `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` should be present in static builds.

---

## 2. Automated Deployment (ArvanCloud Object Storage & GitHub Pages)

This repository includes:
- [`public/CNAME`](public/CNAME) configured for `log.codenameamir.ir`
- [`public/_headers`](public/_headers) for Cloudflare Pages / Netlify-compatible static security headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`)
- [`deploy/nginx-security.conf`](deploy/nginx-security.conf) reference configuration for Nginx reverse-proxying (Express BFF) or static SPA serving
- [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) (`Deploy to ArvanCloud & GitHub Pages`), which installs dependencies via `bun install --frozen-lockfile`, runs typechecks, unit/security tests, and `bun audit`, builds `./dist`, syncs `./dist` to **ArvanCloud Object Storage**, and deploys to **GitHub Pages** on every push to `main` (or manual `workflow_dispatch`).

### Configure Repository Secrets

Go to **Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret | Purpose |
| --- | --- |
| `VITE_SUPABASE_URL` | Public Supabase project URL (`https://<project-ref>.supabase.co`) |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | Public Supabase publishable / anon key (`sb_publishable_...`) |
| `ARVAN_ACCESS_KEY` | ArvanCloud Object Storage S3 access key |
| `ARVAN_SECRET_KEY` | ArvanCloud Object Storage S3 secret key |
| `ARVAN_BUCKET_NAME` | Target ArvanCloud Object Storage bucket name |
| `ARVAN_ENDPOINT` | ArvanCloud S3 endpoint URL (e.g., `https://s3.ir-thr-at1.arvanstorage.ir`) |

### Configure GitHub Pages & ArvanCloud DNS (`log.codenameamir.ir`)

1. In GitHub **Settings → Pages**:
   - Set **Build and deployment → Source** to **GitHub Actions**.
   - Verify the custom domain `log.codenameamir.ir` is configured (populated from `CNAME`).
2. In your **ArvanCloud DNS / CDN** panel for `codenameamir.ir`:
   - Configure the `CNAME` record (`log` → target host) with SSL mode set to **Full** or **Full Strict** once certificates are active.
   - Use a short/bypassed CDN cache rule for `/index.html` and `/` while caching hashed `/assets/*` files.
   - Configure ArvanCloud CDN **Response Header Rules** (since GitHub Pages and plain S3 buckets do not read `_headers`) to inject `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and a strict `Content-Security-Policy` allowing only `'self'` and your Supabase URL in `connect-src`.

> **Deployment Note**: Static deployments (ArvanCloud Object Storage / GitHub Pages) do not have a Node.js server to set `HttpOnly` cookies, so sessions remain strictly in memory (`inMemoryStaticToken`, cleared on page refresh). If you want persistent `HttpOnly` cookie sessions across page reloads, host the Express BFF (`server.ts`) on a Node.js runtime.

---

## 3. Express BFF Hosting (Recommended for `HttpOnly` Cookie Sessions)

To run Logbook with `HttpOnly` cookie sessions, CSRF protection, and server-side IP rate limiting:

1. Configure server environment variables (see [`.env.example`](.env.example)):
   - `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (and optionally `VITE_SUPABASE_URL` / `VITE_SUPABASE_PUBLISHABLE_KEY`)
   - `SUPABASE_SECRET_KEY` *(optional, enables 6-hour background cleanup via `lb_cleanup_expired_sessions`)*
   - `ALLOWED_ORIGINS` *(comma-separated browser origins allowed by CORS/CSRF, e.g. `https://log.codenameamir.ir`)*
   - `TRUST_PROXY=false` *(secure default when exposed directly; set to `1`, `loopback`, or an explicit proxy IP/CIDR allowlist only behind a trusted reverse proxy such as Nginx or Cloudflare/ArvanCloud CDN; never set `"true"`)*
   - `COOKIE_SAME_SITE` *(optional override for HTTPS production: `lax`, `strict`, or default `none` with `Partitioned`)*
   - Signup & auth rate-limit overrides *(all optional with safe defaults)*: `SIGNUP_RATE_LIMIT_IP_MAX` (`10`), `SIGNUP_RATE_LIMIT_IP_WINDOW_SEC` (`900`), `SIGNUP_RATE_LIMIT_USER_MAX` (`5`), `SIGNUP_RATE_LIMIT_USER_WINDOW_SEC` (`900`), `SIGNUP_RATE_LIMIT_GLOBAL_MAX` (`60`), `SIGNUP_RATE_LIMIT_GLOBAL_WINDOW_SEC` (`3600`), `LOGIN_RATE_LIMIT_IP_MAX` (`20`), `LOGIN_RATE_LIMIT_USER_MAX` (`12`), `WEBHOOK_RATE_LIMIT_IP_MAX` (`120`).
2. Build and start:

```bash
bun install --frozen-lockfile
npm run lint
npm test
npm run build
NODE_ENV=production npm start
```

---

## 4. Webhook Usage

Generate an `lbk_...` token inside **Settings & Webhooks → API & Webhooks**.

### When running the Express BFF (`POST /api/webhook`)

```bash
curl -X POST "https://YOUR_HOST/api/webhook" \
  -H "Authorization: Bearer lbk_YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Backup completed successfully",
    "category": "Deployment",
    "tags": ["prod", "backup"],
    "pinned": false
  }'
```

### When using static hosting (`POST /rest/v1/rpc/lb_ingest_webhook`)

```bash
curl -X POST "https://<YOUR_PROJECT>.supabase.co/rest/v1/rpc/lb_ingest_webhook" \
  -H "apikey: <VITE_SUPABASE_PUBLISHABLE_KEY>" \
  -H "Authorization: Bearer <VITE_SUPABASE_PUBLISHABLE_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "p_raw_token": "lbk_YOUR_API_TOKEN",
    "p_message": "Backup completed successfully",
    "p_category": "Deployment",
    "p_tags": ["prod", "backup"],
    "p_pinned": false
  }'
```

---

## 5. Local Development & Testing

```bash
bun install
cp .env.example .env
# Fill SUPABASE_URL / VITE_SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY / VITE_SUPABASE_PUBLISHABLE_KEY in .env
npm run dev
```

Run tests, type checks, and production build:

```bash
npm test
npm run lint
npm run build
```
