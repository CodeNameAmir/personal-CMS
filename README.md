# Logbook

A fast, bilingual (**English LTR** & **Persian RTL**) structured log manager built with React, Vite, Tailwind CSS, and **Supabase PostgreSQL**, ready for static deployment on **GitHub Pages** behind **ArvanCloud CDN** (`log.codenameamir.ir`).

---

## Features

- **Supabase-Only Architecture**: Static SPA that talks directly to Supabase via Row-Level Security (`RLS`) locked tables and `SECURITY DEFINER` RPC functions (`pgcrypto` bcrypt password hashing + SHA-256 session and API tokens).
- **Per-User Isolated Workspaces**: Secure username & password authentication with isolated logs, categories, tags, and API tokens per account.
- **Categories & Advanced Multi-Tagging**: Color-coded categories and `#tags` with `Any` / `All` match modes and inline creation (without noisy log levels like INFO/ERROR).
- **Pinning**: Pin critical entries to the top of the feed with a dedicated quick filter.
- **Collapsible Sidebar**: Collapse the left/right sidebar on desktop into a compact rail to maximize horizontal space for reading logs.
- **Import & Export**: Import and export logs in **JSON** and **CSV** formats.
- **API Tokens & Webhooks**: Generate `lbk_...` API tokens and push automated logs directly to `POST https://<PROJECT>.supabase.co/rest/v1/rpc/lb_ingest_webhook`.
- **Bilingual & Multi-Theme**: Instant English / Persian (RTL) switching plus Dark (Graphite), Midnight, and Light themes.

---

## 1. Supabase Setup

1. Create a new project in [Supabase](https://supabase.com/).
2. Open **SQL Editor** in your Supabase Dashboard, paste the full contents of [`supabase/schema.sql`](supabase/schema.sql), and click **Run**.
   - This creates `users`, `sessions`, `api_tokens`, `categories`, `tags`, `logs`, and `log_tags`.
   - Enables **Row Level Security** on all tables so raw PostgREST table queries cannot read or modify user data.
   - Exposes parameterized `lb_*` RPC functions for authentication, log management, import, and webhook ingestion.
3. From **Project Settings → API**, copy:
   - **Project URL** (`VITE_SUPABASE_URL`)
   - **Publishable / Anon Key** (`VITE_SUPABASE_PUBLISHABLE_KEY`)

> **Security Note**: Never place `SUPABASE_SECRET_KEY` or `service_role` in `VITE_*` variables or GitHub Pages builds. Only `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` are needed by the frontend.

---

## 2. GitHub Pages + GitHub Actions Setup

This repository includes:
- [`public/CNAME`](public/CNAME) configured for `log.codenameamir.ir`
- [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) which runs `npm run lint`, `npm run build`, and deploys `./dist` on every push to `main`.

### Configure Repository Secrets & Pages

1. Push this codebase to your GitHub repository (`main` branch).
2. Go to **Settings → Secrets and variables → Actions → New repository secret** and add:
   - `VITE_SUPABASE_URL` = `https://<your-project-ref>.supabase.co`
   - `VITE_SUPABASE_PUBLISHABLE_KEY` = `sb_publishable_...`
3. Go to **Settings → Pages**:
   - Under **Build and deployment → Source**, select **GitHub Actions**.
   - Under **Custom domain**, verify `log.codenameamir.ir` is set (populated automatically from `CNAME` after first deploy).

---

## 3. ArvanCloud CDN & DNS Configuration (`log.codenameamir.ir`)

1. **DNS Record** in ArvanCloud DNS panel for `codenameamir.ir`:
   - **Type**: `CNAME`
   - **Name**: `log`
   - **Value**: `<your-github-username>.github.io`
   - **Cloud Status (Proxy)**: Enabled (orange cloud) after GitHub verifies the domain.
     - *Tip*: During initial GitHub Pages certificate verification, keep proxy off (DNS-only) until GitHub finishes issuing the domain certificate and **Enforce HTTPS** is active, then turn the ArvanCloud cloud proxy ON.
2. **SSL / TLS Mode** in ArvanCloud CDN → HTTPS Settings:
   - Set SSL mode to **Full** (or **Full Strict**) once GitHub Pages HTTPS is enabled to avoid redirect loops.
3. **Caching Page Rules** (Recommended):
   - Bypass CDN cache (or use very short TTL) for `/index.html` and `/` so new deployments show up immediately.
   - Cache `/assets/*` aggressively (hashed Vite filenames).

---

## 4. Webhook Usage

Generate a token in **Settings & Webhooks → API & Webhooks**, then send logs from any script or server:

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

## 5. Local Development

```bash
npm install
cp .env.example .env
# Fill VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in .env
npm run dev
```

Run tests & type check:

```bash
npx tsx --test src/utils/logFormatters.test.ts src/i18n/translations.test.ts
npm run lint
npm run build
```
