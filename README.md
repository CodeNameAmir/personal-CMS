# Logbook

A fast, bilingual (**English LTR** & **Persian RTL**) structured log manager built with React, Vite, Tailwind CSS, Express, and **Supabase PostgreSQL**. Supports both a hardened **Express Backend-for-Frontend (BFF)** runtime and static deployment to **ArvanCloud Object Storage** and **GitHub Pages** (`log.codenameamir.ir`).

---

## Features

- **Dual-Mode Security Architecture**:
  - **Express BFF Mode (`server.ts`)**: Stores sessions in `HttpOnly` cookies (`SameSite`, `Secure` over HTTPS), enforces CSRF protection (`Origin`/`Referer` verification + `X-Requested-With`), sliding-window rate limiting, Helmet CSP/security headers, strict CORS, and bounded request payloads.
  - **Static Hosting Fallback**: Deployable as a static SPA to ArvanCloud Object Storage and GitHub Pages without exposing `localStorage` session tokens (keeps session tokens strictly in memory when no BFF is present) while relying on Supabase RLS-locked tables and hardened `SECURITY DEFINER` RPCs.
- **Hardened PostgreSQL / Supabase Layer**:
  - Row-Level Security (`RLS`) with explicit `deny_direct_access` policies and `REVOKE ALL` across all tables (`users`, `sessions`, `api_tokens`, `categories`, `tags`, `logs`, `log_tags`, `lb_rate_limits`).
  - Locked-down `SECURITY DEFINER` functions with pinned `search_path`, ownership checks, composite tenant foreign keys, SHA-256 session/API token hashing, SHA-256 pre-hashed bcrypt (`v2:`, cost 12) password hashing (12–128 characters, backward-compatible with legacy hashes), and database-backed rate limiting.
- **Server-Side Pagination & Analytics**: Filtering, search, sorting, pagination (`1..100` per page), and 30-day / category / tag dashboard statistics computed in PostgreSQL.
- **Categories & Multi-Tagging**: Color-coded (`#RRGGBB` validated) categories and `#tags` with `Any` / `All` match modes and inline creation.
- **Pinning & Bulk Actions**: Pin critical entries to the top of the feed and perform bulk pin, unpin, category move, tag assignment, or delete operations (capped at 200 items per request).
- **Collapsible Sidebar**: Collapse the left/right sidebar on desktop into a compact rail to maximize horizontal reading space.
- **Import & Export**: Import up to 500 records (1 MB max) and export up to 5,000 logs in **JSON** and **CSV** formats with spreadsheet formula-injection protection.
- **API Tokens & Webhooks**: Generate `lbk_...` API tokens and ingest automated logs via the Express BFF (`POST /api/webhook`) or directly via Supabase RPC (`POST /rest/v1/rpc/lb_ingest_webhook`).
- **Bilingual & Multi-Theme**: Instant English (LTR) / Persian (RTL) switching plus Dark (Graphite), Midnight, and Light themes.

---

## 1. Supabase Setup

1. Create a project in [Supabase](https://supabase.com/).
2. Open **SQL Editor** in your Supabase Dashboard:
   - **Fresh installation**: Run the full contents of [`supabase/schema.sql`](supabase/schema.sql).
   - **Upgrading an existing database**: Run [`supabase/migrations/0001_security_hardening.sql`](supabase/migrations/0001_security_hardening.sql) (preserves existing user data while upgrading constraints, indexes, function privileges, rate limits, and password hashing).
3. From **Project Settings → API**, copy:
   - **Project URL** (`SUPABASE_URL` / `VITE_SUPABASE_URL`)
   - **Publishable / Anon Key** (`SUPABASE_PUBLISHABLE_KEY` / `VITE_SUPABASE_PUBLISHABLE_KEY`)
   - *(Optional, server-only)* **Secret / Service Role Key** (`SUPABASE_SECRET_KEY`) for scheduled expired-session & rate-limit cleanup in Express BFF mode.

> **Security Note**: Never place `SUPABASE_SECRET_KEY` or `service_role` in `VITE_*` variables or static frontend builds. Only `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` should be present in static builds.

---

## 2. Automated Deployment (ArvanCloud Object Storage & GitHub Pages)

This repository includes:
- [`public/CNAME`](public/CNAME) configured for `log.codenameamir.ir`
- [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) (`Deploy to ArvanCloud & GitHub Pages`), which builds `./dist` with Node.js 20 (`npm ci` + `npm run build`), syncs the bundle to **ArvanCloud Object Storage**, and deploys to **GitHub Pages** on every push to `main` (or manual `workflow_dispatch`).

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

> **Deployment Note**: Static deployments (ArvanCloud Object Storage / GitHub Pages) do not have a Node.js server to set `HttpOnly` cookies, so sessions remain strictly in memory (`inMemoryStaticToken`, cleared on page refresh). If you want persistent `HttpOnly` cookie sessions across page reloads, host the Express BFF (`server.ts`) on a Node.js runtime.

---

## 3. Express BFF Hosting (Recommended for `HttpOnly` Cookie Sessions)

To run Logbook with `HttpOnly` cookie sessions, CSRF protection, and server-side IP rate limiting:

1. Configure server environment variables (see [`.env.example`](.env.example)):
   - `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (and optionally `VITE_SUPABASE_URL` / `VITE_SUPABASE_PUBLISHABLE_KEY`)
   - `SUPABASE_SECRET_KEY` *(optional, enables 6-hour background cleanup via `lb_cleanup_expired_sessions`)*
   - `ALLOWED_ORIGINS` *(comma-separated browser origins allowed by CORS/CSRF, e.g. `https://log.codenameamir.ir`)*
   - `TRUST_PROXY=1` *(proxy hop count behind CDN/load balancer, or `false` if direct)*
   - `COOKIE_SAME_SITE` *(optional override for HTTPS production: `lax`, `strict`, or default `none` with `Partitioned`)*
2. Build and start:

```bash
npm ci
npm run lint
npm run build
NODE_ENV=production npx tsx server.ts
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
npm install
cp .env.example .env
# Fill SUPABASE_URL / VITE_SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY / VITE_SUPABASE_PUBLISHABLE_KEY in .env
npm run dev
```

Run tests, type checks, and production build:

```bash
npx tsx --test src/utils/logFormatters.test.ts src/i18n/translations.test.ts server/security.test.ts
npm run lint
npm run build
```
