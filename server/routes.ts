import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express, { type Response } from 'express';
import multer from 'multer';
import {
  createSession,
  extractBearerToken,
  requireAuth,
  revokeSession,
  type AuthenticatedRequest,
} from './auth';
import {
  localBulkAction,
  localChangePassword,
  localCreateApiToken,
  localCreateCategory,
  localCreateLog,
  localCreateOrGetTag,
  localDeleteApiToken,
  localDeleteCategory,
  localDeleteLog,
  localDeleteTag,
  localFindOrCreateCategoryByName,
  localGetLog,
  localImportRecords,
  localListApiTokens,
  localListCategories,
  localListLogs,
  localListTags,
  localLogin,
  localResolveApiToken,
  localSetAttachment,
  localSignup,
  localTogglePin,
  localUpdateCategory,
  localUpdateLog,
  localUpdateTag,
} from './localStore';
import {
  isSupabaseConfigured,
  SUPABASE_SETUP_SQL,
  supabaseChangePassword,
  supabaseCreateApiToken,
  supabaseCreateCategory,
  supabaseCreateLog,
  supabaseCreateOrGetTag,
  supabaseDeleteApiToken,
  supabaseDeleteCategory,
  supabaseDeleteLog,
  supabaseDeleteTag,
  supabaseFindOrCreateCategoryByName,
  supabaseImportRecords,
  supabaseListApiTokens,
  supabaseListCategories,
  supabaseListLogs,
  supabaseListTags,
  supabaseLogin,
  supabaseResolveApiToken,
  supabaseSetAttachment,
  supabaseSignup,
  supabaseTogglePin,
  supabaseUpdateCategory,
  supabaseUpdateLog,
  supabaseUpdateTag,
} from './supabaseStore';
import {
  computeLogStats,
  filterAndSortLogs,
  parseImportCSV,
  parseImportJSON,
  parseTagInput,
  serializeLogsToCSV,
  serializeLogsToJSON,
} from '../src/utils/logFormatters';
import type { DbMode, LogFilters, TagMatchMode } from '../src/types/logbook';

const UPLOADS_ROOT = path.resolve(process.cwd(), 'uploads');
fs.mkdirSync(UPLOADS_ROOT, { recursive: true });

const uploadAttachment = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
});

const uploadImport = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

function getUserUploadDir(userId: string): string {
  const safeId = userId.replace(/[^a-zA-Z0-9_-]/g, '_');
  const dir = path.resolve(UPLOADS_ROOT, safeId);
  if (!dir.startsWith(UPLOADS_ROOT + path.sep)) {
    throw new Error('Invalid upload directory');
  }
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function resolveUserAttachmentPath(userId: string, storedName: string): string {
  const userDir = getUserUploadDir(userId);
  const safeName = path.basename(storedName);
  const resolved = path.resolve(userDir, safeName);
  if (!resolved.startsWith(userDir + path.sep)) {
    throw new Error('Invalid attachment path');
  }
  return resolved;
}

function removeAttachmentFile(userId: string, storedName?: string | null): void {
  if (!storedName) return;
  try {
    const p = resolveUserAttachmentPath(userId, storedName);
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
    }
  } catch {
    // Ignore missing files
  }
}

function sendError(res: Response, err: unknown, fallbackStatus = 400): void {
  const error = err as Error & { code?: string };
  const message = error?.message || 'Request failed';
  res.status(fallbackStatus).json({
    error: message,
    ...(error?.code ? { code: error.code } : {}),
  });
}

function parseFiltersFromQuery(query: Record<string, unknown>): LogFilters {
  const rawTags = typeof query.tags === 'string' ? query.tags : '';
  const selectedTags = rawTags
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);

  const tagMatchMode: TagMatchMode = query.tag_mode === 'all' ? 'all' : 'any';

  return {
    q: typeof query.q === 'string' ? query.q : '',
    categoryId: typeof query.category_id === 'string' ? query.category_id : '',
    selectedTags,
    tagMatchMode,
    dateFrom: typeof query.date_from === 'string' ? query.date_from : '',
    pinnedOnly: query.pinned === 'true',
    hasFileOnly: query.has_file === 'true',
  };
}

export function createApiRouter(): express.Router {
  const router = express.Router();

  router.get('/config', (_req, res) => {
    res.json({
      supabaseConfigured: isSupabaseConfigured(),
    });
  });

  router.get('/supabase-schema', (_req, res) => {
    res.json({ sql: SUPABASE_SETUP_SQL });
  });

  /* ---------------- Auth ---------------- */
  router.post('/auth/signup', async (req, res) => {
    try {
      const dbMode: DbMode = req.body?.db_mode === 'supabase' ? 'supabase' : 'local';
      const username = typeof req.body?.username === 'string' ? req.body.username : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (dbMode === 'local') {
        const user = localSignup(username, password);
        res.status(201).json({
          user: { id: user.id, username: user.username, db_mode: 'local' as DbMode },
        });
        return;
      }

      const sbUser = await supabaseSignup(username, password);
      res.status(201).json({
        user: { id: sbUser.id, username: sbUser.username, db_mode: 'supabase' as DbMode },
      });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/auth/login', async (req, res) => {
    try {
      const dbMode: DbMode = req.body?.db_mode === 'supabase' ? 'supabase' : 'local';
      const username = typeof req.body?.username === 'string' ? req.body.username : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!username.trim() || !password) {
        res.status(400).json({ error: 'Username and password are required' });
        return;
      }

      if (dbMode === 'local') {
        const user = localLogin(username, password);
        const { token } = createSession({
          userId: user.id,
          username: user.username,
          dbMode: 'local',
        });
        res.json({
          token,
          user: { id: user.id, username: user.username, db_mode: 'local' as DbMode },
        });
        return;
      }

      const sbUser = await supabaseLogin(username, password);
      const { token } = createSession({
        userId: sbUser.id,
        username: sbUser.username,
        dbMode: 'supabase',
      });
      res.json({
        token,
        user: { id: sbUser.id, username: sbUser.username, db_mode: 'supabase' as DbMode },
      });
    } catch (err) {
      sendError(res, err, 401);
    }
  });

  router.post('/auth/logout', (req, res) => {
    const token = extractBearerToken(req);
    if (token) revokeSession(token);
    res.json({ ok: true });
  });

  router.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
    const s = req.session!;
    res.json({
      id: s.userId,
      username: s.username,
      db_mode: s.dbMode,
    });
  });

  router.post('/auth/change-password', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const currentPassword = typeof req.body?.current_password === 'string' ? req.body.current_password : '';
      const newPassword = typeof req.body?.new_password === 'string' ? req.body.new_password : '';

      if (s.dbMode === 'local') {
        localChangePassword(s.userId, currentPassword, newPassword);
      } else {
        await supabaseChangePassword(s.userId, currentPassword, newPassword);
      }
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  /* ---------------- API Tokens & Webhook Ingestion ---------------- */
  router.get('/tokens', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        res.json(localListApiTokens(s.userId));
        return;
      }
      res.json(await supabaseListApiTokens(s.userId));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/tokens', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const name = typeof req.body?.name === 'string' ? req.body.name : '';
      if (s.dbMode === 'local') {
        res.status(201).json(localCreateApiToken(s.userId, name));
        return;
      }
      res.status(201).json(await supabaseCreateApiToken(s.userId, name));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.delete('/tokens/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        localDeleteApiToken(s.userId, req.params.id);
      } else {
        await supabaseDeleteApiToken(s.userId, req.params.id);
      }
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  const handleWebhookIngest = async (req: express.Request, res: Response) => {
    try {
      const headerApiKey =
        typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'].trim() : '';
      const bearer = extractBearerToken(req) || '';
      const rawToken = headerApiKey || bearer;

      if (!rawToken || !rawToken.startsWith('lbk_')) {
        res.status(401).json({ error: 'Valid API token required via Authorization: Bearer or X-API-Key' });
        return;
      }

      const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
      if (!message) {
        res.status(400).json({ error: 'Field "message" is required' });
        return;
      }

      const categoryName =
        typeof req.body?.category === 'string' && req.body.category.trim()
          ? req.body.category.trim()
          : 'General';
      const pinned = Boolean(req.body?.pinned);
      const rawTags = req.body?.tags;
      const tags: string[] = Array.isArray(rawTags)
        ? rawTags.filter((t): t is string => typeof t === 'string')
        : typeof rawTags === 'string'
          ? parseTagInput(rawTags)
          : [];

      const localMatch = localResolveApiToken(rawToken);
      if (localMatch) {
        const cat = localFindOrCreateCategoryByName(localMatch.userId, categoryName);
        const created = localCreateLog(localMatch.userId, {
          message,
          category_id: cat.id,
          tags,
          pinned,
        });
        res.status(201).json({ log: created });
        return;
      }

      const sbMatch = await supabaseResolveApiToken(rawToken);
      if (sbMatch) {
        const cat = await supabaseFindOrCreateCategoryByName(sbMatch.userId, categoryName);
        const created = await supabaseCreateLog(sbMatch.userId, {
          message,
          category_id: cat.id,
          tags,
          pinned,
        });
        res.status(201).json({ log: created });
        return;
      }

      res.status(401).json({ error: 'Invalid or revoked API token' });
    } catch (err) {
      sendError(res, err, 400);
    }
  };

  router.post('/webhook/logs', handleWebhookIngest);
  router.post('/v1/logs', handleWebhookIngest);

  /* ---------------- Categories ---------------- */
  router.get('/categories', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        res.json(localListCategories(s.userId));
        return;
      }
      const [cats, logs] = await Promise.all([
        supabaseListCategories(s.userId),
        supabaseListLogs(s.userId),
      ]);
      const counts = new Map<string, number>();
      for (const l of logs) {
        if (l.category_id) counts.set(l.category_id, (counts.get(l.category_id) || 0) + 1);
      }
      res.json(cats.map((c) => ({ ...c, log_count: counts.get(c.id) || 0 })));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/categories', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const name = typeof req.body?.name === 'string' ? req.body.name : '';
      const color = typeof req.body?.color === 'string' ? req.body.color : '#3b82f6';
      if (s.dbMode === 'local') {
        res.status(201).json(localCreateCategory(s.userId, name, color));
        return;
      }
      res.status(201).json(await supabaseCreateCategory(s.userId, name, color));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.put('/categories/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const name = typeof req.body?.name === 'string' ? req.body.name : '';
      const color = typeof req.body?.color === 'string' ? req.body.color : '#3b82f6';
      if (s.dbMode === 'local') {
        res.json(localUpdateCategory(s.userId, req.params.id, name, color));
        return;
      }
      res.json(await supabaseUpdateCategory(s.userId, req.params.id, name, color));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.delete('/categories/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        localDeleteCategory(s.userId, req.params.id);
      } else {
        await supabaseDeleteCategory(s.userId, req.params.id);
      }
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  /* ---------------- Tags ---------------- */
  router.get('/tags', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        res.json(localListTags(s.userId));
        return;
      }
      const [tags, logs] = await Promise.all([
        supabaseListTags(s.userId),
        supabaseListLogs(s.userId),
      ]);
      const counts = new Map<string, number>();
      for (const l of logs) {
        for (const t of l.tags) {
          counts.set(t.id, (counts.get(t.id) || 0) + 1);
        }
      }
      res.json(tags.map((t) => ({ ...t, usage_count: counts.get(t.id) || 0 })));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/tags', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const name = typeof req.body?.name === 'string' ? req.body.name : '';
      const color = typeof req.body?.color === 'string' ? req.body.color : undefined;
      if (s.dbMode === 'local') {
        res.status(201).json(localCreateOrGetTag(s.userId, name, color));
        return;
      }
      res.status(201).json(await supabaseCreateOrGetTag(s.userId, name, color));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.put('/tags/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const name = typeof req.body?.name === 'string' ? req.body.name : '';
      const color = typeof req.body?.color === 'string' ? req.body.color : '#64748b';
      if (s.dbMode === 'local') {
        res.json(localUpdateTag(s.userId, req.params.id, name, color));
        return;
      }
      res.json(await supabaseUpdateTag(s.userId, req.params.id, name, color));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.delete('/tags/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        localDeleteTag(s.userId, req.params.id);
      } else {
        await supabaseDeleteTag(s.userId, req.params.id);
      }
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  /* ---------------- Logs ---------------- */
  router.get('/logs', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const allLogs = s.dbMode === 'local' ? localListLogs(s.userId) : await supabaseListLogs(s.userId);
      const filters = parseFiltersFromQuery(req.query as Record<string, unknown>);
      const filtered = filterAndSortLogs(allLogs, filters);
      const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit || '20'), 10) || 20));
      const offset = Math.max(0, parseInt(String(req.query.offset || '0'), 10) || 0);

      res.json({
        logs: filtered.slice(offset, offset + limit),
        total: filtered.length,
        total_unfiltered: allLogs.length,
      });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/logs', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const input = {
        message: typeof req.body?.message === 'string' ? req.body.message : '',
        category_id:
          typeof req.body?.category_id === 'string' && req.body.category_id ? req.body.category_id : null,
        tags: Array.isArray(req.body?.tags) ? req.body.tags.filter((t: unknown) => typeof t === 'string') : [],
        pinned: Boolean(req.body?.pinned),
      };
      if (s.dbMode === 'local') {
        res.status(201).json(localCreateLog(s.userId, input));
        return;
      }
      res.status(201).json(await supabaseCreateLog(s.userId, input));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.put('/logs/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const input: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean } = {};
      if (typeof req.body?.message === 'string') input.message = req.body.message;
      if (req.body?.category_id !== undefined) {
        input.category_id =
          typeof req.body.category_id === 'string' && req.body.category_id ? req.body.category_id : null;
      }
      if (Array.isArray(req.body?.tags)) {
        input.tags = req.body.tags.filter((t: unknown) => typeof t === 'string');
      }
      if (typeof req.body?.pinned === 'boolean') input.pinned = req.body.pinned;

      if (s.dbMode === 'local') {
        res.json(localUpdateLog(s.userId, req.params.id, input));
        return;
      }
      res.json(await supabaseUpdateLog(s.userId, req.params.id, input));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/logs/:id/pin', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        res.json(localTogglePin(s.userId, req.params.id));
        return;
      }
      res.json(await supabaseTogglePin(s.userId, req.params.id));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.delete('/logs/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const removed =
        s.dbMode === 'local'
          ? localDeleteLog(s.userId, req.params.id)
          : await supabaseDeleteLog(s.userId, req.params.id);

      if (!removed) {
        res.status(404).json({ error: 'Log not found' });
        return;
      }
      removeAttachmentFile(s.userId, removed.attachment_path);
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post('/logs/bulk', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((x: unknown) => typeof x === 'string') : [];
      const type = req.body?.type;
      if (ids.length === 0) {
        res.status(400).json({ error: 'No logs selected' });
        return;
      }
      if (!['pin', 'unpin', 'delete', 'category', 'add_tag'].includes(type)) {
        res.status(400).json({ error: 'Invalid bulk action' });
        return;
      }

      if (s.dbMode === 'local') {
        if (type === 'delete') {
          for (const id of ids) {
            const existing = localGetLog(s.userId, id);
            if (existing?.attachment_path) removeAttachmentFile(s.userId, existing.attachment_path);
          }
        }
        const affected = localBulkAction(s.userId, ids, {
          type,
          category_id: typeof req.body?.category_id === 'string' ? req.body.category_id : null,
          tag: typeof req.body?.tag === 'string' ? req.body.tag : undefined,
        });
        res.json({ affected });
        return;
      }

      let affected = 0;
      for (const id of ids) {
        if (type === 'pin') {
          await supabaseUpdateLog(s.userId, id, { pinned: true });
          affected += 1;
        } else if (type === 'unpin') {
          await supabaseUpdateLog(s.userId, id, { pinned: false });
          affected += 1;
        } else if (type === 'delete') {
          const removed = await supabaseDeleteLog(s.userId, id);
          if (removed?.attachment_path) removeAttachmentFile(s.userId, removed.attachment_path);
          affected += 1;
        } else if (type === 'category') {
          await supabaseUpdateLog(s.userId, id, {
            category_id: typeof req.body?.category_id === 'string' ? req.body.category_id : null,
          });
          affected += 1;
        } else if (type === 'add_tag' && typeof req.body?.tag === 'string') {
          const all = await supabaseListLogs(s.userId);
          const target = all.find((l) => l.id === id);
          if (target) {
            const merged = Array.from(new Set([...target.tags.map((t) => t.name), req.body.tag]));
            await supabaseUpdateLog(s.userId, id, { tags: merged });
            affected += 1;
          }
        }
      }
      res.json({ affected });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  /* ---------------- Attachments ---------------- */
  router.post(
    '/logs/:id/attachment',
    requireAuth,
    uploadAttachment.single('file'),
    async (req: AuthenticatedRequest, res) => {
      try {
        const s = req.session!;
        const file = req.file;
        if (!file) {
          res.status(400).json({ error: 'File is required' });
          return;
        }

        const existing =
          s.dbMode === 'local'
            ? localGetLog(s.userId, req.params.id)
            : (await supabaseListLogs(s.userId)).find((l) => l.id === req.params.id) || null;

        if (!existing) {
          res.status(404).json({ error: 'Log not found' });
          return;
        }

        removeAttachmentFile(s.userId, existing.attachment_path);

        const ext = path.extname(file.originalname).replace(/[^a-zA-Z0-9.]/g, '').slice(0, 12);
        const storedName = `${crypto.randomUUID()}${ext}`;
        const destPath = resolveUserAttachmentPath(s.userId, storedName);
        fs.writeFileSync(destPath, file.buffer);

        const originalName = path.basename(file.originalname).slice(0, 180) || 'attachment';
        const updated =
          s.dbMode === 'local'
            ? localSetAttachment(s.userId, req.params.id, {
                name: originalName,
                path: storedName,
                size: file.size,
              })
            : await supabaseSetAttachment(s.userId, req.params.id, {
                name: originalName,
                path: storedName,
                size: file.size,
              });

        res.json({ log: updated });
      } catch (err) {
        sendError(res, err, 400);
      }
    }
  );

  router.delete('/logs/:id/attachment', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const existing =
        s.dbMode === 'local'
          ? localGetLog(s.userId, req.params.id)
          : (await supabaseListLogs(s.userId)).find((l) => l.id === req.params.id) || null;

      if (!existing) {
        res.status(404).json({ error: 'Log not found' });
        return;
      }

      removeAttachmentFile(s.userId, existing.attachment_path);
      const updated =
        s.dbMode === 'local'
          ? localSetAttachment(s.userId, req.params.id, { name: null, path: null, size: null })
          : await supabaseSetAttachment(s.userId, req.params.id, { name: null, path: null, size: null });

      res.json({ log: updated });
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.get('/logs/:id/attachment', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const existing =
        s.dbMode === 'local'
          ? localGetLog(s.userId, req.params.id)
          : (await supabaseListLogs(s.userId)).find((l) => l.id === req.params.id) || null;

      if (!existing || !existing.attachment_path || !existing.attachment_name) {
        res.status(404).json({ error: 'Attachment not found' });
        return;
      }

      const filePath = resolveUserAttachmentPath(s.userId, existing.attachment_path);
      if (!fs.existsSync(filePath)) {
        res.status(404).json({ error: 'Attachment file missing' });
        return;
      }

      const safeDownloadName = existing.attachment_name.replace(/["\r\n\\]/g, '_');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName}"`);
      res.sendFile(filePath);
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  /* ---------------- Statistics & Import/Export ---------------- */
  router.get('/stats', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      if (s.dbMode === 'local') {
        res.json(computeLogStats(localListLogs(s.userId), localListCategories(s.userId)));
        return;
      }
      const [logs, categories] = await Promise.all([
        supabaseListLogs(s.userId),
        supabaseListCategories(s.userId),
      ]);
      res.json(computeLogStats(logs, categories));
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.get('/export', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const s = req.session!;
      const format = req.query.format === 'csv' ? 'csv' : 'json';
      const filters = parseFiltersFromQuery(req.query as Record<string, unknown>);

      const [allLogs, categories] =
        s.dbMode === 'local'
          ? [localListLogs(s.userId), localListCategories(s.userId)]
          : await Promise.all([supabaseListLogs(s.userId), supabaseListCategories(s.userId)]);

      const filtered = filterAndSortLogs(allLogs, filters);
      const stamp = new Date().toISOString().slice(0, 10);

      if (format === 'csv') {
        const csv = serializeLogsToCSV(filtered);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="logbook-${stamp}.csv"`);
        res.send('\uFEFF' + csv);
        return;
      }

      const json = serializeLogsToJSON(filtered, categories);
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="logbook-${stamp}.json"`);
      res.send(json);
    } catch (err) {
      sendError(res, err, 400);
    }
  });

  router.post(
    '/import',
    requireAuth,
    uploadImport.single('file'),
    async (req: AuthenticatedRequest, res) => {
      try {
        const s = req.session!;
        const format = req.query.format === 'csv' ? 'csv' : 'json';
        let content = '';
        if (req.file) {
          content = req.file.buffer.toString('utf8');
        } else if (typeof req.body?.content === 'string') {
          content = req.body.content;
        }

        if (!content.trim()) {
          res.status(400).json({ error: 'Import file or content is empty' });
          return;
        }

        const parsed = format === 'csv' ? parseImportCSV(content) : parseImportJSON(content);
        if (parsed.records.length === 0 && parsed.errors.length > 0) {
          res.status(400).json({ error: parsed.errors[0], details: parsed.errors });
          return;
        }

        const result =
          s.dbMode === 'local'
            ? localImportRecords(s.userId, parsed.records)
            : await supabaseImportRecords(s.userId, parsed.records);

        res.json({
          imported: result.imported,
          skipped: result.skipped,
          failed: result.failed + parsed.errors.length,
          errors: [...parsed.errors, ...result.errors].slice(0, 20),
        });
      } catch (err) {
        sendError(res, err, 400);
      }
    }
  );

  return router;
}
