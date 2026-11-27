import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

export const SESSION_COOKIE_NAME = 'lb_session';
export const MAX_LOG_MESSAGE_LENGTH = 10_000;
export const MAX_CATEGORY_NAME_LENGTH = 64;
export const MAX_TAG_NAME_LENGTH = 32;
export const MAX_TAGS_PER_LOG = 25;
export const MAX_BULK_IDS = 200;
export const MAX_IMPORT_RECORDS = 500;
export const MAX_SEARCH_QUERY_LENGTH = 200;
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_COLOR_REGEX = /^#[0-9a-fA-F]{6}$/;
const USERNAME_REGEX = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const DATE_YYYY_MM_DD_REGEX = /^\d{4}-\d{2}-\d{2}$/;

export function isValidUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_REGEX.test(value.trim());
}

export function isValidHexColor(value: unknown): value is string {
  return typeof value === 'string' && HEX_COLOR_REGEX.test(value.trim());
}

export function normalizeUsername(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function isValidUsername(value: string): boolean {
  return USERNAME_REGEX.test(value);
}

export function validatePassword(value: unknown): string | null {
  if (typeof value !== 'string') {
    return `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters.`;
  }
  if (value.length < MIN_PASSWORD_LENGTH || value.length > MAX_PASSWORD_LENGTH) {
    return `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

export function isValidDateString(value: unknown): value is string {
  if (typeof value !== 'string' || !DATE_YYYY_MM_DD_REGEX.test(value.trim())) return false;
  const parsed = new Date(`${value.trim()}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value.trim();
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = pair.slice(0, eqIdx).trim();
    const val = pair.slice(eqIdx + 1).trim();
    if (!key) continue;
    try {
      result[key] = decodeURIComponent(val);
    } catch {
      result[key] = val;
    }
  }
  return result;
}

export function isHttpsRequest(req: Request): boolean {
  if (req.secure) return true;
  const forwardedProto = req.headers['x-forwarded-proto'];
  if (typeof forwardedProto === 'string') {
    const first = forwardedProto.split(',')[0].trim().toLowerCase();
    return first === 'https';
  }
  return false;
}

export function buildSessionCookieAttributes(req: Request, clear = false): string[] {
  const isHttps = isHttpsRequest(req);
  const envSameSite = (process.env.COOKIE_SAME_SITE || '').trim().toLowerCase();

  const attrs = ['Path=/', 'HttpOnly'];
  if (clear) {
    attrs.push('Max-Age=0');
  } else {
    attrs.push('Max-Age=604800'); // 7 days
  }

  if (isHttps) {
    attrs.push('Secure');
    if (envSameSite === 'strict') {
      attrs.push('SameSite=Strict');
    } else if (envSameSite === 'lax') {
      attrs.push('SameSite=Lax');
    } else {
      // SameSite=None + Partitioned supports both standalone HTTPS and embedded iframe previews
      attrs.push('SameSite=None');
      attrs.push('Partitioned');
    }
  } else {
    attrs.push('SameSite=Lax');
  }

  return attrs;
}

export function setSessionCookie(res: Response, req: Request, token: string): void {
  const attrs = buildSessionCookieAttributes(req, false);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; ${attrs.join('; ')}`);
}

export function clearSessionCookie(res: Response, req: Request): void {
  const attrs = buildSessionCookieAttributes(req, true);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE_NAME}=; ${attrs.join('; ')}`);
}

export function getSessionCookie(req: Request): string | null {
  const cookies = parseCookies(req.headers.cookie);
  const raw = cookies[SESSION_COOKIE_NAME];
  if (!raw || raw.length > 256) return null;
  return raw;
}

export function getAllowedOrigins(): Set<string> {
  const raw = (process.env.ALLOWED_ORIGINS || '').trim();
  const origins = new Set<string>();
  if (raw) {
    for (const part of raw.split(',')) {
      const trimmed = part.trim().replace(/\/+$/, '');
      if (trimmed) origins.add(trimmed.toLowerCase());
    }
  }
  const appUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (appUrl && !appUrl.startsWith('MY_')) {
    origins.add(appUrl.toLowerCase());
  }
  return origins;
}

export function isOriginAllowed(origin: string | undefined, req: Request): boolean {
  if (!origin) return true;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  const normalizedOrigin = `${parsed.protocol}//${parsed.host}`.toLowerCase();

  const configured = getAllowedOrigins();
  if (configured.has(normalizedOrigin)) {
    return true;
  }

  // Allow exact same-origin match against request Host / X-Forwarded-Host
  const forwardedHost =
    typeof req.headers['x-forwarded-host'] === 'string'
      ? req.headers['x-forwarded-host'].split(',')[0].trim().toLowerCase()
      : '';
  const host = (forwardedHost || req.headers.host || '').trim().toLowerCase();
  if (host && parsed.host.toLowerCase() === host) {
    return true;
  }

  return false;
}

export function csrfProtectionMiddleware(req: Request, res: Response, next: NextFunction): void {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    next();
    return;
  }

  // Webhook endpoint uses API key authentication, not browser session cookies
  const cleanPath = req.originalUrl.split('?')[0];
  if (req.path === '/webhook' || cleanPath === '/api/webhook') {
    next();
    return;
  }

  const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
  if (origin && !isOriginAllowed(origin, req)) {
    res.status(403).json({ error: 'Forbidden origin.', code: 'FORBIDDEN_ORIGIN' });
    return;
  }

  if (!origin && typeof req.headers.referer === 'string') {
    try {
      const refUrl = new URL(req.headers.referer);
      if (!isOriginAllowed(`${refUrl.protocol}//${refUrl.host}`, req)) {
        res.status(403).json({ error: 'Forbidden referer.', code: 'FORBIDDEN_ORIGIN' });
        return;
      }
    } catch {
      res.status(403).json({ error: 'Invalid referer header.', code: 'FORBIDDEN_ORIGIN' });
      return;
    }
  }

  const requestedWith = req.headers['x-requested-with'];
  if (requestedWith !== 'XMLHttpRequest') {
    res.status(403).json({ error: 'Missing required CSRF verification header.', code: 'CSRF_REQUIRED' });
    return;
  }

  next();
}

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export class SlidingWindowRateLimiter {
  private readonly store = new Map<string, RateLimitEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    this.maxEntries = maxEntries;
  }

  check(
    scope: string,
    key: string,
    maxRequests: number,
    windowMs: number,
    nowMs = Date.now()
  ): { allowed: boolean; remaining: number; retryAfterSec: number } {
    const hash = crypto.createHash('sha256').update(`${scope}:${key}`).digest('hex');
    const existing = this.store.get(hash);

    if (!existing || existing.resetAt <= nowMs) {
      if (this.store.size >= this.maxEntries) {
        this.prune(nowMs);
      }
      this.store.set(hash, { count: 1, resetAt: nowMs + windowMs });
      return {
        allowed: true,
        remaining: Math.max(0, maxRequests - 1),
        retryAfterSec: Math.ceil(windowMs / 1000),
      };
    }

    existing.count += 1;
    const retryAfterSec = Math.max(1, Math.ceil((existing.resetAt - nowMs) / 1000));
    if (existing.count > maxRequests) {
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    return {
      allowed: true,
      remaining: Math.max(0, maxRequests - existing.count),
      retryAfterSec,
    };
  }

  prune(nowMs = Date.now()): void {
    for (const [k, entry] of this.store.entries()) {
      if (entry.resetAt <= nowMs) {
        this.store.delete(k);
      }
    }
  }
}

export function getClientIp(req: Request): string {
  return (req.ip || req.socket.remoteAddress || 'unknown').trim();
}
