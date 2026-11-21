import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { DbMode } from '../src/types/logbook';

export interface ServerSession {
  sid: string;
  userId: string;
  username: string;
  dbMode: DbMode;
  supabaseUrl?: string;
  supabaseKey?: string;
  supabaseAccessToken?: string;
  expiresAt: number;
}

export interface AuthenticatedRequest extends Request {
  session?: ServerSession;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sessions = new Map<string, ServerSession>();

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function signSessionId(sid: string): string {
  return crypto.createHmac('sha256', SESSION_SECRET).update(sid).digest('hex');
}

export function createSession(data: Omit<ServerSession, 'sid' | 'expiresAt'>): {
  token: string;
  session: ServerSession;
} {
  const sid = crypto.randomUUID();
  const session: ServerSession = {
    ...data,
    sid,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
  sessions.set(sid, session);
  const sig = signSessionId(sid);
  return { token: `${sid}.${sig}`, session };
}

export function getSessionFromToken(token: string): ServerSession | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [sid, sig] = parts;
  if (!sid || !sig) return null;

  const expectedSig = signSessionId(sid);
  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  const session = sessions.get(sid);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sid);
    return null;
  }
  return session;
}

export function revokeSession(token: string): void {
  const parts = token.split('.');
  if (parts.length === 2 && parts[0]) {
    sessions.delete(parts[0]);
  }
}

export function extractBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  const queryToken = typeof req.query.token === 'string' ? req.query.token.trim() : '';
  return queryToken || null;
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  const session = getSessionFromToken(token);
  if (!session) {
    res.status(401).json({ error: 'Invalid or expired session' });
    return;
  }
  req.session = session;
  next();
}
