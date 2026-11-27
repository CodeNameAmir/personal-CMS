import dotenv from 'dotenv';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  clearSessionCookie,
  csrfProtectionMiddleware,
  getClientIp,
  getSessionCookie,
  isOriginAllowed,
  isValidDateString,
  isValidHexColor,
  isValidUsername,
  isValidUuid,
  MAX_BULK_IDS,
  MAX_CATEGORY_NAME_LENGTH,
  MAX_IMPORT_RECORDS,
  MAX_LOG_MESSAGE_LENGTH,
  MAX_SEARCH_QUERY_LENGTH,
  MAX_TAGS_PER_LOG,
  normalizeUsername,
  setSessionCookie,
  SlidingWindowRateLimiter,
  validatePassword,
} from './server/security';
import { BffError, callSupabaseRpc, getSupabaseServerConfig } from './server/supabaseProxy';

dotenv.config();
dotenv.config({ path: '.env.local', override: true });

export interface CreateAppOptions {
  rpcCaller?: typeof callSupabaseRpc;
  rateLimiter?: SlidingWindowRateLimiter;
}

function parseTrustProxy(): boolean | number | string {
  const raw = (process.env.TRUST_PROXY || '').trim().toLowerCase();
  if (raw === 'false' || raw === '0') return false;
  if (raw === 'loopback' || raw === 'linklocal' || raw === 'uniquelocal') return raw;
  const hops = Number(raw);
  if (Number.isInteger(hops) && hops > 0 && hops <= 10) return hops;
  return 1; // Trust single reverse-proxy hop by default (never arbitrary `true`)
}

function parseTagsArray(input: unknown): string[] | null {
  if (!Array.isArray(input)) return null;
  if (input.length > MAX_TAGS_PER_LOG) return null;
  const out: string[] = [];
  for (const item of input) {
    if (typeof item !== 'string') return null;
    const trimmed = item.trim();
    if (trimmed) out.push(trimmed.slice(0, 64));
  }
  return out;
}

function requireSessionFromCookie(req: Request): string {
  const token = getSessionCookie(req);
  if (!token) {
    throw new BffError('Missing session cookie', 401, 'UNAUTHORIZED');
  }
  return token;
}

export function createApiRouter(options: CreateAppOptions = {}): express.Router {
  const rpc = options.rpcCaller || callSupabaseRpc;
  const limiter = options.rateLimiter || new SlidingWindowRateLimiter();
  const router = express.Router();

  const enforceLimit = (
    req: Request,
    res: Response,
    scope: string,
    key: string,
    max: number,
    windowMs: number
  ): boolean => {
    const status = limiter.check(scope, key, max, windowMs);
    res.setHeader('X-RateLimit-Remaining', String(status.remaining));
    if (!status.allowed) {
      res.setHeader('Retry-After', String(status.retryAfterSec));
      res.status(429).json({
        error: 'Too many requests. Please try again later.',
        code: 'RATE_LIMITED',
      });
      return false;
    }
    return true;
  };

  // Strict CORS for /api/* (never wildcard '*' on authenticated endpoints)
  router.use((req, res, next) => {
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
    if (origin) {
      if (!isOriginAllowed(origin, req)) {
        res.status(403).json({ error: 'Origin not allowed.', code: 'FORBIDDEN_ORIGIN' });
        return;
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Requested-With,Authorization,X-API-Key');
    }
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  // CSRF check for all cookie-authenticated mutating routes
  router.use(csrfProtectionMiddleware);

  // Import route allows up to 1 MB; all other API routes cap at 100 KB
  const jsonSmall = express.json({ limit: '100kb' });
  const jsonImport = express.json({ limit: '1mb' });

  router.use((req, res, next) => {
    if (req.path === '/logs/import') {
      jsonImport(req, res, next);
      return;
    }
    jsonSmall(req, res, next);
  });

  // Public runtime configuration (NEVER exposes secret/service_role keys)
  router.get('/config', (_req, res) => {
    const cfg = getSupabaseServerConfig();
    res.json({
      bffEnabled: true,
      supabaseUrl: cfg.supabaseUrl,
      supabasePublishableKey: cfg.supabasePublishableKey,
      supabaseConfigured: cfg.supabaseConfigured,
    });
  });

  /* ---------------- Auth ---------------- */
  router.post('/auth/signup', async (req, res, next) => {
    try {
      const ip = getClientIp(req);
      const username = normalizeUsername(req.body?.username);
      if (!enforceLimit(req, res, 'signup_ip', ip, 10, 15 * 60_000)) return;
      if (!enforceLimit(req, res, 'signup_user', username || 'empty', 5, 15 * 60_000)) return;

      if (username.length < 2 || username.length > 64 || !isValidUsername(username)) {
        throw new BffError(
          'Username must be 2–64 characters using lowercase letters, numbers, dots, underscores, or hyphens.',
          400,
          'VALIDATION_ERROR'
        );
      }
      const pwError = validatePassword(req.body?.password);
      if (pwError) {
        throw new BffError(pwError, 400, 'VALIDATION_ERROR');
      }

      const result = await rpc<{ token: string; user: { id: string; username: string } }>('lb_signup', {
        p_username: username,
        p_password: req.body.password,
      });

      setSessionCookie(res, req, result.token);
      res.status(201).json({ user: result.user });
    } catch (err) {
      next(err);
    }
  });

  router.post('/auth/login', async (req, res, next) => {
    try {
      const ip = getClientIp(req);
      const username = normalizeUsername(req.body?.username);
      if (!enforceLimit(req, res, 'login_ip', ip, 20, 15 * 60_000)) return;
      if (!enforceLimit(req, res, 'login_user', username || 'empty', 12, 15 * 60_000)) return;

      const password = req.body?.password;
      if (!username || username.length > 64 || typeof password !== 'string' || !password || password.length > 128) {
        throw new BffError('Invalid username or password.', 400, 'VALIDATION_ERROR');
      }

      const result = await rpc<{ token: string; user: { id: string; username: string } }>('lb_login', {
        p_username: username,
        p_password: password,
      });

      setSessionCookie(res, req, result.token);
      res.json({ user: result.user });
    } catch (err) {
      next(err);
    }
  });

  router.get('/auth/me', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const user = await rpc<{ id: string; username: string }>('lb_me', { p_token: token });
      res.json({ user });
    } catch (err) {
      if (err instanceof BffError && err.status === 401) {
        clearSessionCookie(res, req);
      }
      next(err);
    }
  });

  router.post('/auth/logout', async (req, res) => {
    const token = getSessionCookie(req);
    clearSessionCookie(res, req);
    if (token) {
      try {
        await rpc<boolean>('lb_logout', { p_token: token });
      } catch {
        // Ignore upstream errors on logout after clearing cookie
      }
    }
    res.json({ ok: true });
  });

  router.post('/auth/change-password', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'change_pw', ip, 10, 15 * 60_000)) return;

      const currentPassword = req.body?.currentPassword;
      const newPassword = req.body?.newPassword;
      if (typeof currentPassword !== 'string' || !currentPassword || currentPassword.length > 128) {
        throw new BffError('Current password is required.', 400, 'VALIDATION_ERROR');
      }
      const pwError = validatePassword(newPassword);
      if (pwError) {
        throw new BffError(pwError, 400, 'VALIDATION_ERROR');
      }

      const result = await rpc<{ ok: boolean; token?: string }>('lb_change_password', {
        p_token: token,
        p_current_password: currentPassword,
        p_new_password: newPassword,
      });

      if (result?.token) {
        setSessionCookie(res, req, result.token);
      }
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /* ---------------- Workspace, Pagination & Export ---------------- */
  router.get('/workspace', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const pageRaw = Number(req.query.page ?? 1);
      const pageSizeRaw = Number(req.query.pageSize ?? 20);
      const page = Number.isFinite(pageRaw) && pageRaw >= 1 ? Math.floor(pageRaw) : 1;
      const pageSize =
        Number.isFinite(pageSizeRaw) && pageSizeRaw >= 1 ? Math.min(100, Math.floor(pageSizeRaw)) : 20;

      const q = typeof req.query.q === 'string' ? req.query.q.slice(0, MAX_SEARCH_QUERY_LENGTH) : '';
      const categoryIdRaw = typeof req.query.categoryId === 'string' ? req.query.categoryId.trim() : '';
      if (categoryIdRaw && !isValidUuid(categoryIdRaw)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }

      const tagsRaw = typeof req.query.tags === 'string' ? req.query.tags : '';
      const selectedTags = tagsRaw
        ? tagsRaw
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean)
            .slice(0, MAX_TAGS_PER_LOG)
        : [];

      const tagMatchMode = req.query.tagMatchMode === 'all' ? 'all' : 'any';
      const dateFromRaw = typeof req.query.dateFrom === 'string' ? req.query.dateFrom.trim() : '';
      if (dateFromRaw && !isValidDateString(dateFromRaw)) {
        throw new BffError('Invalid date filter.', 400, 'VALIDATION_ERROR');
      }
      const pinnedOnly = req.query.pinnedOnly === 'true';

      const data = await rpc('lb_get_workspace', {
        p_token: token,
        p_page: page,
        p_page_size: pageSize,
        p_q: q,
        p_category_id: categoryIdRaw || null,
        p_tags: selectedTags,
        p_tag_match_mode: tagMatchMode,
        p_date_from: dateFromRaw || null,
        p_pinned_only: pinnedOnly,
      });

      res.json(data);
    } catch (err) {
      next(err);
    }
  });

  router.get('/logs/export', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'export', ip, 20, 5 * 60_000)) return;

      const q = typeof req.query.q === 'string' ? req.query.q.slice(0, MAX_SEARCH_QUERY_LENGTH) : '';
      const categoryIdRaw = typeof req.query.categoryId === 'string' ? req.query.categoryId.trim() : '';
      if (categoryIdRaw && !isValidUuid(categoryIdRaw)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }

      const tagsRaw = typeof req.query.tags === 'string' ? req.query.tags : '';
      const selectedTags = tagsRaw
        ? tagsRaw
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean)
            .slice(0, MAX_TAGS_PER_LOG)
        : [];
      const tagMatchMode = req.query.tagMatchMode === 'all' ? 'all' : 'any';
      const dateFromRaw = typeof req.query.dateFrom === 'string' ? req.query.dateFrom.trim() : '';
      if (dateFromRaw && !isValidDateString(dateFromRaw)) {
        throw new BffError('Invalid date filter.', 400, 'VALIDATION_ERROR');
      }
      const pinnedOnly = req.query.pinnedOnly === 'true';

      const logs = await rpc('lb_export_logs', {
        p_token: token,
        p_q: q,
        p_category_id: categoryIdRaw || null,
        p_tags: selectedTags,
        p_tag_match_mode: tagMatchMode,
        p_date_from: dateFromRaw || null,
        p_pinned_only: pinnedOnly,
      });

      res.json({ logs });
    } catch (err) {
      next(err);
    }
  });

  /* ---------------- Categories ---------------- */
  router.post('/categories', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      const color = typeof req.body?.color === 'string' ? req.body.color.trim() : '#3b82f6';
      if (!name || name.length > MAX_CATEGORY_NAME_LENGTH) {
        throw new BffError(`Category name must be between 1 and ${MAX_CATEGORY_NAME_LENGTH} characters.`, 400, 'VALIDATION_ERROR');
      }
      if (!isValidHexColor(color)) {
        throw new BffError('Category color must be a valid #RRGGBB hex code.', 400, 'VALIDATION_ERROR');
      }

      const cat = await rpc('lb_create_category', {
        p_token: token,
        p_name: name,
        p_color: color,
      });
      res.status(201).json(cat);
    } catch (err) {
      next(err);
    }
  });

  router.patch('/categories/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }
      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      const color = typeof req.body?.color === 'string' ? req.body.color.trim() : '#3b82f6';
      if (!name || name.length > MAX_CATEGORY_NAME_LENGTH) {
        throw new BffError(`Category name must be between 1 and ${MAX_CATEGORY_NAME_LENGTH} characters.`, 400, 'VALIDATION_ERROR');
      }
      if (!isValidHexColor(color)) {
        throw new BffError('Category color must be a valid #RRGGBB hex code.', 400, 'VALIDATION_ERROR');
      }

      const cat = await rpc('lb_update_category', {
        p_token: token,
        p_id: req.params.id,
        p_name: name,
        p_color: color,
      });
      res.json(cat);
    } catch (err) {
      next(err);
    }
  });

  router.delete('/categories/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }
      await rpc('lb_delete_category', { p_token: token, p_id: req.params.id });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /* ---------------- Tags ---------------- */
  router.post('/tags', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      const color = typeof req.body?.color === 'string' && req.body.color.trim() ? req.body.color.trim() : null;
      if (!name || name.length > 64) {
        throw new BffError('Tag name is required.', 400, 'VALIDATION_ERROR');
      }
      if (color !== null && !isValidHexColor(color)) {
        throw new BffError('Tag color must be a valid #RRGGBB hex code.', 400, 'VALIDATION_ERROR');
      }

      const tag = await rpc('lb_create_or_get_tag', {
        p_token: token,
        p_name: name,
        p_color: color,
      });
      res.status(201).json(tag);
    } catch (err) {
      next(err);
    }
  });

  router.patch('/tags/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid tag ID.', 400, 'VALIDATION_ERROR');
      }
      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      const color = typeof req.body?.color === 'string' ? req.body.color.trim() : '#64748b';
      if (!name || name.length > 64) {
        throw new BffError('Tag name is required.', 400, 'VALIDATION_ERROR');
      }
      if (!isValidHexColor(color)) {
        throw new BffError('Tag color must be a valid #RRGGBB hex code.', 400, 'VALIDATION_ERROR');
      }

      const tag = await rpc('lb_update_tag', {
        p_token: token,
        p_id: req.params.id,
        p_name: name,
        p_color: color,
      });
      res.json(tag);
    } catch (err) {
      next(err);
    }
  });

  router.delete('/tags/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid tag ID.', 400, 'VALIDATION_ERROR');
      }
      await rpc('lb_delete_tag', { p_token: token, p_id: req.params.id });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /* ---------------- Logs CRUD, Bulk & Import ---------------- */
  router.post('/logs', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
      if (!message || message.length > MAX_LOG_MESSAGE_LENGTH) {
        throw new BffError(
          `Log message must be between 1 and ${MAX_LOG_MESSAGE_LENGTH.toLocaleString()} characters.`,
          400,
          'VALIDATION_ERROR'
        );
      }

      const categoryId = req.body?.category_id ?? null;
      if (categoryId !== null && !isValidUuid(categoryId)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }

      const tags = parseTagsArray(req.body?.tags ?? []);
      if (tags === null) {
        throw new BffError(`Tags must be an array of at most ${MAX_TAGS_PER_LOG} strings.`, 400, 'VALIDATION_ERROR');
      }

      const log = await rpc('lb_create_log', {
        p_token: token,
        p_message: message,
        p_category_id: categoryId,
        p_tags: tags,
        p_pinned: Boolean(req.body?.pinned),
        p_created_at: null,
      });
      res.status(201).json(log);
    } catch (err) {
      next(err);
    }
  });

  router.post('/logs/bulk', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'bulk_ip', ip, 40, 60_000)) return;

      const ids = req.body?.ids;
      if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_BULK_IDS || !ids.every(isValidUuid)) {
        throw new BffError(
          `Bulk action requires between 1 and ${MAX_BULK_IDS} valid log IDs.`,
          400,
          'VALIDATION_ERROR'
        );
      }

      const actionType = req.body?.type;
      if (!['pin', 'unpin', 'delete', 'category', 'add_tag'].includes(actionType)) {
        throw new BffError('Unsupported bulk action.', 400, 'VALIDATION_ERROR');
      }

      const categoryId = req.body?.category_id ?? null;
      if (actionType === 'category' && categoryId !== null && !isValidUuid(categoryId)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }

      const tag = typeof req.body?.tag === 'string' ? req.body.tag.trim().slice(0, 64) : null;

      const affected = await rpc<number>('lb_bulk_logs_action', {
        p_token: token,
        p_ids: ids,
        p_action: actionType,
        p_category_id: categoryId,
        p_tag: tag,
      });

      res.json({ affected: affected ?? 0 });
    } catch (err) {
      next(err);
    }
  });

  router.post('/logs/import', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'import_ip', ip, 10, 5 * 60_000)) return;

      const records = req.body?.records;
      if (!Array.isArray(records) || records.length === 0 || records.length > MAX_IMPORT_RECORDS) {
        throw new BffError(
          `Import requires between 1 and ${MAX_IMPORT_RECORDS} records per request.`,
          400,
          'VALIDATION_ERROR'
        );
      }

      const result = await rpc('lb_import_logs', {
        p_token: token,
        p_records: records,
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  router.patch('/logs/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid log ID.', 400, 'VALIDATION_ERROR');
      }

      const message =
        req.body?.message === undefined || req.body?.message === null
          ? null
          : typeof req.body.message === 'string'
            ? req.body.message.trim()
            : '';

      if (message !== null && (!message || message.length > MAX_LOG_MESSAGE_LENGTH)) {
        throw new BffError(
          `Log message must be between 1 and ${MAX_LOG_MESSAGE_LENGTH.toLocaleString()} characters.`,
          400,
          'VALIDATION_ERROR'
        );
      }

      const hasCategoryField = Object.prototype.hasOwnProperty.call(req.body || {}, 'category_id');
      const categoryId = req.body?.category_id ?? null;
      if (categoryId !== null && !isValidUuid(categoryId)) {
        throw new BffError('Invalid category ID.', 400, 'VALIDATION_ERROR');
      }

      let tags: string[] | null = null;
      if (req.body?.tags !== undefined && req.body?.tags !== null) {
        tags = parseTagsArray(req.body.tags);
        if (tags === null) {
          throw new BffError(`Tags must be an array of at most ${MAX_TAGS_PER_LOG} strings.`, 400, 'VALIDATION_ERROR');
        }
      }

      const pinned = typeof req.body?.pinned === 'boolean' ? req.body.pinned : null;

      const log = await rpc('lb_update_log', {
        p_token: token,
        p_id: req.params.id,
        p_message: message,
        p_category_id: categoryId,
        p_clear_category: hasCategoryField && categoryId === null,
        p_tags: tags,
        p_pinned: pinned,
      });
      res.json(log);
    } catch (err) {
      next(err);
    }
  });

  router.post('/logs/:id/toggle-pin', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid log ID.', 400, 'VALIDATION_ERROR');
      }
      const log = await rpc('lb_toggle_pin', { p_token: token, p_id: req.params.id });
      res.json(log);
    } catch (err) {
      next(err);
    }
  });

  router.delete('/logs/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid log ID.', 400, 'VALIDATION_ERROR');
      }
      await rpc('lb_delete_log', { p_token: token, p_id: req.params.id });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /* ---------------- API Tokens & Webhook ---------------- */
  router.get('/tokens', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const tokens = await rpc('lb_list_api_tokens', { p_token: token });
      res.json({ tokens });
    } catch (err) {
      next(err);
    }
  });

  router.post('/tokens', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'create_token_ip', ip, 15, 15 * 60_000)) return;

      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      if (!name || name.length > 64) {
        throw new BffError('Token name must be between 1 and 64 characters.', 400, 'VALIDATION_ERROR');
      }
      const created = await rpc('lb_create_api_token', { p_token: token, p_name: name });
      res.status(201).json(created);
    } catch (err) {
      next(err);
    }
  });

  router.delete('/tokens/:id', async (req, res, next) => {
    try {
      const token = requireSessionFromCookie(req);
      if (!isValidUuid(req.params.id)) {
        throw new BffError('Invalid token ID.', 400, 'VALIDATION_ERROR');
      }
      await rpc('lb_delete_api_token', { p_token: token, p_id: req.params.id });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.post('/webhook', async (req, res, next) => {
    try {
      const ip = getClientIp(req);
      if (!enforceLimit(req, res, 'webhook_ip', ip, 120, 60_000)) return;

      const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
      const bearerToken = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
      const headerKey = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'].trim() : '';
      const bodyToken = typeof req.body?.p_raw_token === 'string' ? req.body.p_raw_token.trim() : '';
      const rawToken = bearerToken || headerKey || bodyToken;

      if (!rawToken || !rawToken.startsWith('lbk_') || rawToken.length < 16 || rawToken.length > 128) {
        throw new BffError('Missing or invalid API token.', 401, 'UNAUTHORIZED');
      }

      const rawMsg = req.body?.message ?? req.body?.p_message;
      const message = typeof rawMsg === 'string' ? rawMsg.trim() : '';
      if (!message || message.length > MAX_LOG_MESSAGE_LENGTH) {
        throw new BffError(
          `Log message must be between 1 and ${MAX_LOG_MESSAGE_LENGTH.toLocaleString()} characters.`,
          400,
          'VALIDATION_ERROR'
        );
      }

      const rawCategory = req.body?.category ?? req.body?.p_category;
      const category =
        typeof rawCategory === 'string' && rawCategory.trim()
          ? rawCategory.trim().slice(0, MAX_CATEGORY_NAME_LENGTH)
          : 'Webhook';

      const rawTags = req.body?.tags ?? req.body?.p_tags ?? [];
      const tags = parseTagsArray(rawTags);
      if (tags === null) {
        throw new BffError(`Tags must be an array of at most ${MAX_TAGS_PER_LOG} strings.`, 400, 'VALIDATION_ERROR');
      }

      const pinned = Boolean(req.body?.pinned ?? req.body?.p_pinned ?? false);

      const data = await rpc('lb_ingest_webhook', {
        p_raw_token: rawToken,
        p_message: message,
        p_category: category,
        p_tags: tags,
        p_pinned: pinned,
      });

      res.status(201).json(data);
    } catch (err) {
      next(err);
    }
  });

  // Safe API error handler (never leaks stack traces or internal PG details)
  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof BffError) {
      res.status(err.status).json({ error: err.message, code: err.code });
      return;
    }

    if (err && typeof err === 'object') {
      const e = err as { type?: string; status?: number };
      if (e.type === 'entity.too.large' || e.status === 413) {
        res.status(413).json({ error: 'Request payload is too large.', code: 'PAYLOAD_TOO_LARGE' });
        return;
      }
      if (e.type === 'entity.parse.failed' || e.status === 400) {
        res.status(400).json({ error: 'Malformed JSON request body.', code: 'INVALID_JSON' });
        return;
      }
    }

    res.status(500).json({ error: 'Internal server error.', code: 'INTERNAL_ERROR' });
  });

  return router;
}

export function createApp(options: CreateAppOptions = {}): express.Express {
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';

  app.disable('x-powered-by');
  app.set('trust proxy', parseTrustProxy());

  const cfg = getSupabaseServerConfig();
  const supabaseOrigin = (() => {
    try {
      return cfg.supabaseUrl ? new URL(cfg.supabaseUrl).origin : '';
    } catch {
      return '';
    }
  })();

  app.use(
    helmet({
      // AI Studio preview runs inside an iframe on aistudio.google.com; frame-ancestors handles framing safely
      frameguard: false,
      hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: isProd ? ["'self'"] : ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: [
            "'self'",
            ...(!isProd ? ['ws://localhost:*', 'ws://127.0.0.1:*'] : []),
            ...(supabaseOrigin ? [supabaseOrigin] : []),
          ],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'self'", 'https://aistudio.google.com', 'https://*.google.com'],
          upgradeInsecureRequests: isProd ? [] : null,
        },
      },
    })
  );

  app.use('/api', createApiRouter(options));
  return app;
}

async function startServer() {
  const app = createApp();
  const PORT = Number(process.env.PORT || 3000);

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  // Periodic background session & rate-limit cleanup if server-side secret key is configured
  const cfg = getSupabaseServerConfig();
  if (cfg.supabaseConfigured && cfg.supabaseSecretKey) {
    const cleanupIntervalMs = 6 * 60 * 60 * 1000;
    const timer = setInterval(() => {
      callSupabaseRpc<number>('lb_cleanup_expired_sessions', { p_batch_size: 1000 }, { useServiceRole: true }).catch(
        () => {}
      );
    }, cleanupIntervalMs);
    timer.unref();
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Logbook server listening on http://0.0.0.0:${PORT}`);
  });
}

const isEntrypoint =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isEntrypoint) {
  startServer().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
