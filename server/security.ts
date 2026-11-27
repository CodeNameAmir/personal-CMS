import crypto from 'node:crypto';
import net from 'node:net';
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
const HOST_HEADER_REGEX = /^[a-z0-9.-]+(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$/i;

export type TrustProxyConfig = boolean | number | string | string[];

function isValidIpOrCidr(entry: string): boolean {
  const slashIdx = entry.indexOf('/');
  if (slashIdx === -1) {
    return net.isIP(entry) !== 0;
  }
  const ip = entry.slice(0, slashIdx);
  const prefixRaw = entry.slice(slashIdx + 1);
  if (!/^\d{1,3}$/.test(prefixRaw)) return false;
  const prefix = Number(prefixRaw);
  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) return prefix >= 0 && prefix <= 32;
  if (ipVersion === 6) return prefix >= 0 && prefix <= 128;
  return false;
}

/**
 * Validates and parses TRUST_PROXY strictly.
 * Defaults to `false` (no proxy headers trusted) unless an explicit hop count (1..10),
 * Express named subnet preset (loopback/linklocal/uniquelocal), or valid IP/CIDR allowlist is set.
 * Never returns arbitrary `true`.
 */
export function validateTrustProxy(rawInput: string | undefined): {
  valid: boolean;
  value: TrustProxyConfig;
  error?: string;
} {
  const raw = (rawInput || '').trim();
  if (!raw) {
    return { valid: true, value: false };
  }

  const lower = raw.toLowerCase();
  if (lower === 'false' || lower === '0') {
    return { valid: true, value: false };
  }

  if (lower === 'true') {
    return {
      valid: false,
      value: false,
      error: 'TRUST_PROXY="true" is unsafe and rejected; specify "false", hop count (1..10), preset, or IP/CIDR list.',
    };
  }

  if (lower === 'loopback' || lower === 'linklocal' || lower === 'uniquelocal') {
    return { valid: true, value: lower };
  }

  if (/^\d+$/.test(raw)) {
    const hops = Number(raw);
    if (Number.isInteger(hops) && hops >= 1 && hops <= 10) {
      return { valid: true, value: hops };
    }
    return {
      valid: false,
      value: false,
      error: 'TRUST_PROXY hop count must be an integer between 1 and 10.',
    };
  }

  const parts = raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);

  if (parts.length > 0 && parts.every((p) => p === 'loopback' || p === 'linklocal' || p === 'uniquelocal' || isValidIpOrCidr(p))) {
    return { valid: true, value: parts };
  }

  return {
    valid: false,
    value: false,
    error: `Invalid TRUST_PROXY value "${raw}"; defaulting to false.`,
  };
}

export function parseTrustProxy(rawInput = process.env.TRUST_PROXY): TrustProxyConfig {
  const result = validateTrustProxy(rawInput);
  if (!result.valid && result.error) {
    console.warn(`[security] ${result.error}`);
  }
  return result.value;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function parseStrictBoolean(
  value: unknown,
  defaultValue?: boolean
): { ok: true; value: boolean } | { ok: false } {
  if (value === undefined) {
    return defaultValue !== undefined ? { ok: true, value: defaultValue } : { ok: false };
  }
  if (typeof value === 'boolean') {
    return { ok: true, value };
  }
  return { ok: false };
}

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

function isProxyTrusted(req: Request): boolean {
  const trustSetting = req.app?.get('trust proxy');
  if (!trustSetting) return false;
  if (typeof trustSetting === 'function') {
    return Boolean(req.socket?.remoteAddress && trustSetting(req.socket.remoteAddress, 0));
  }
  return true;
}

export function isHttpsRequest(req: Request): boolean {
  if (req.secure) return true;
  if (!isProxyTrusted(req)) {
    return false;
  }
  // When trust proxy is enabled, Express evaluates req.protocol using trusted hops/IPs
  if (req.protocol === 'https') return true;
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
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }
  const normalizedOrigin = `${parsed.protocol}//${parsed.host}`.toLowerCase();

  const configured = getAllowedOrigins();
  if (configured.has(normalizedOrigin)) {
    return true;
  }

  // Only consider X-Forwarded-Host when Express trust proxy is explicitly enabled
  const trustedProxy = isProxyTrusted(req);
  const rawForwardedHost =
    trustedProxy && typeof req.headers['x-forwarded-host'] === 'string'
      ? req.headers['x-forwarded-host'].split(',')[0].trim().toLowerCase()
      : '';
  const rawHost = typeof req.headers.host === 'string' ? req.headers.host.trim().toLowerCase() : '';
  const effectiveHost = rawForwardedHost || rawHost;

  if (effectiveHost && HOST_HEADER_REGEX.test(effectiveHost) && parsed.host.toLowerCase() === effectiveHost) {
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

export function requireJsonContentType(req: Request, res: Response, next: NextFunction): void {
  if (!req.is('application/json')) {
    res.status(415).json({ error: 'Content-Type must be application/json.', code: 'UNSUPPORTED_MEDIA_TYPE' });
    return;
  }
  next();
}

export interface RateLimitConfig {
  signupIpMax: number;
  signupIpWindowMs: number;
  signupUserMax: number;
  signupUserWindowMs: number;
  signupGlobalMax: number;
  signupGlobalWindowMs: number;
  loginIpMax: number;
  loginUserMax: number;
  webhookIpMax: number;
}

function readBoundedIntEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return fallback;
  const parsed = Number(raw.trim());
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

export function getRateLimitConfig(): RateLimitConfig {
  return {
    signupIpMax: readBoundedIntEnv('SIGNUP_RATE_LIMIT_IP_MAX', 10, 1, 1_000),
    signupIpWindowMs: readBoundedIntEnv('SIGNUP_RATE_LIMIT_IP_WINDOW_SEC', 900, 10, 86_400) * 1000,
    signupUserMax: readBoundedIntEnv('SIGNUP_RATE_LIMIT_USER_MAX', 5, 1, 100),
    signupUserWindowMs: readBoundedIntEnv('SIGNUP_RATE_LIMIT_USER_WINDOW_SEC', 900, 10, 86_400) * 1000,
    signupGlobalMax: readBoundedIntEnv('SIGNUP_RATE_LIMIT_GLOBAL_MAX', 60, 1, 10_000),
    signupGlobalWindowMs: readBoundedIntEnv('SIGNUP_RATE_LIMIT_GLOBAL_WINDOW_SEC', 3600, 60, 604_800) * 1000,
    loginIpMax: readBoundedIntEnv('LOGIN_RATE_LIMIT_IP_MAX', 20, 1, 1_000),
    loginUserMax: readBoundedIntEnv('LOGIN_RATE_LIMIT_USER_MAX', 12, 1, 100),
    webhookIpMax: readBoundedIntEnv('WEBHOOK_RATE_LIMIT_IP_MAX', 120, 1, 10_000),
  };
}

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
}

export interface RateLimitStore {
  check(
    scope: string,
    key: string,
    maxRequests: number,
    windowMs: number,
    nowMs?: number
  ): RateLimitResult | Promise<RateLimitResult>;
}

/**
 * Memory-bounded LRU rate limiter.
 * Strictly enforces `store.size <= maxEntries`:
 *   1. Evicts expired entries first in a bounded scan.
 *   2. If still at capacity (e.g. distributed IP flood within an active window),
 *      evicts the least-recently-used entry before inserting.
 */
export class SlidingWindowRateLimiter implements RateLimitStore {
  private readonly store = new Map<string, RateLimitEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    this.maxEntries = Math.max(1, Math.floor(maxEntries));
  }

  get size(): number {
    return this.store.size;
  }

  private evictForCapacity(nowMs: number): void {
    if (this.store.size < this.maxEntries) return;

    // Bounded sweep from oldest entries to drop expired windows first
    let inspected = 0;
    const maxScan = Math.min(this.store.size, 256);
    for (const [k, entry] of this.store.entries()) {
      if (entry.resetAt <= nowMs) {
        this.store.delete(k);
      }
      inspected += 1;
      if (inspected >= maxScan && this.store.size < this.maxEntries) {
        break;
      }
    }

    // Hard LRU cap: evict oldest remaining entries until strictly below maxEntries
    while (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey === undefined) break;
      this.store.delete(oldestKey);
    }
  }

  check(
    scope: string,
    key: string,
    maxRequests: number,
    windowMs: number,
    nowMs = Date.now()
  ): RateLimitResult {
    const hash = crypto.createHash('sha256').update(`${scope}:${key}`).digest('hex');
    const existing = this.store.get(hash);

    if (!existing || existing.resetAt <= nowMs) {
      if (existing) {
        this.store.delete(hash);
      }
      this.evictForCapacity(nowMs);
      this.store.set(hash, { count: 1, resetAt: nowMs + windowMs });
      return {
        allowed: true,
        remaining: Math.max(0, maxRequests - 1),
        retryAfterSec: Math.ceil(windowMs / 1000),
      };
    }

    // Refresh LRU position on active entry
    this.store.delete(hash);
    existing.count += 1;
    this.store.set(hash, existing);

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
  return (req.ip || req.socket?.remoteAddress || 'unknown').trim();
}
