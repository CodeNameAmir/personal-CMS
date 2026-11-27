import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../server';
import { BffError } from './supabaseProxy';
import { SlidingWindowRateLimiter } from './security';

type RpcCall = { fn: string; params: Record<string, unknown> };

async function withTestServer(
  handler: (fn: string, params: Record<string, unknown>) => unknown | Promise<unknown>,
  run: (baseUrl: string, calls: RpcCall[]) => Promise<void>
) {
  const calls: RpcCall[] = [];
  const app = createApp({
    rateLimiter: new SlidingWindowRateLimiter(1000),
    rpcCaller: async <T>(fn: string, params: Record<string, unknown>) => {
      calls.push({ fn, params });
      return (await handler(fn, params)) as T;
    },
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    await run(baseUrl, calls);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
}

test('HttpOnly session cookie lifecycle: signup, login, me, change-password rotation, and logout', async () => {
  await withTestServer(
    (fn, params) => {
      if (fn === 'lb_signup') {
        return { token: 'raw_signup_token_secret', user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
      }
      if (fn === 'lb_login') {
        return { token: 'raw_login_token_secret', user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
      }
      if (fn === 'lb_me') {
        assert.equal(params.p_token, 'raw_login_token_secret');
        return { id: '11111111-1111-4111-8111-111111111111', username: 'alice' };
      }
      if (fn === 'lb_change_password') {
        assert.equal(params.p_token, 'raw_login_token_secret');
        return { ok: true, token: 'rotated_token_secret' };
      }
      if (fn === 'lb_logout') {
        return true;
      }
      return null;
    },
    async (baseUrl, calls) => {
      // Signup sets HttpOnly cookie and omits raw token from JSON body
      const signupRes = await fetch(`${baseUrl}/api/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify({ username: 'Alice', password: 'correct-horse-battery' }),
      });
      assert.equal(signupRes.status, 201);
      const signupBody = await signupRes.json();
      assert.equal(signupBody.user.username, 'alice');
      assert.equal('token' in signupBody, false);
      const signupCookie = signupRes.headers.get('set-cookie') || '';
      assert.match(signupCookie, /lb_session=raw_signup_token_secret/);
      assert.match(signupCookie, /HttpOnly/i);
      assert.match(signupCookie, /SameSite=Lax/i);

      // HTTPS proxy sets Secure + SameSite=None + Partitioned cookie
      const loginHttpsRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-Forwarded-Proto': 'https',
        },
        body: JSON.stringify({ username: 'alice', password: 'legacy' }),
      });
      assert.equal(loginHttpsRes.status, 200);
      const loginCookie = loginHttpsRes.headers.get('set-cookie') || '';
      assert.match(loginCookie, /lb_session=raw_login_token_secret/);
      assert.match(loginCookie, /Secure/i);
      assert.match(loginCookie, /SameSite=None/i);
      assert.match(loginCookie, /Partitioned/i);

      // /api/auth/me reads session cookie
      const meRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: 'lb_session=raw_login_token_secret' },
      });
      assert.equal(meRes.status, 200);
      const meBody = await meRes.json();
      assert.equal(meBody.user.username, 'alice');

      // /api/auth/change-password rotates session cookie
      const cpRes = await fetch(`${baseUrl}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          Cookie: 'lb_session=raw_login_token_secret',
        },
        body: JSON.stringify({
          currentPassword: 'old-password-value',
          newPassword: 'new-strong-password-123',
        }),
      });
      assert.equal(cpRes.status, 200);
      const cpCookie = cpRes.headers.get('set-cookie') || '';
      assert.match(cpCookie, /lb_session=rotated_token_secret/);

      // /api/auth/logout clears cookie and revokes session server-side
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          Cookie: 'lb_session=rotated_token_secret',
        },
      });
      assert.equal(logoutRes.status, 200);
      const logoutCookie = logoutRes.headers.get('set-cookie') || '';
      assert.match(logoutCookie, /Max-Age=0/i);
      assert.equal(calls.at(-1)?.fn, 'lb_logout');
    }
  );
});

test('CSRF protection blocks missing X-Requested-With or foreign Origin, while allowing webhook bearer API key', async () => {
  await withTestServer(
    (fn) => {
      if (fn === 'lb_ingest_webhook') {
        return { log: { id: '22222222-2222-4222-8222-222222222222', message: 'ok' } };
      }
      return null;
    },
    async (baseUrl) => {
      // Missing X-Requested-With on mutating cookie route -> 403
      const noHeader = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'lb_session=abc',
        },
        body: JSON.stringify({ message: 'test' }),
      });
      assert.equal(noHeader.status, 403);
      assert.equal((await noHeader.json()).code, 'CSRF_REQUIRED');

      // Disallowed Origin -> 403
      const badOrigin = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          Origin: 'https://attacker.example',
          Cookie: 'lb_session=abc',
        },
        body: JSON.stringify({ message: 'test' }),
      });
      assert.equal(badOrigin.status, 403);
      assert.equal((await badOrigin.json()).code, 'FORBIDDEN_ORIGIN');

      // Disallowed Referer -> 403
      const badReferer = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          Referer: 'https://evil.example/form.html',
          Cookie: 'lb_session=abc',
        },
        body: JSON.stringify({ message: 'test' }),
      });
      assert.equal(badReferer.status, 403);
      assert.equal((await badReferer.json()).code, 'FORBIDDEN_ORIGIN');

      // /api/webhook uses Bearer token and does not require X-Requested-With
      const webhookRes = await fetch(`${baseUrl}/api/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer lbk_test_token_1234567890abcdef',
        },
        body: JSON.stringify({ message: 'Deployment finished' }),
      });
      assert.equal(webhookRes.status, 201);
    }
  );
});

test('Security headers, strict CORS, and bounded trust proxy are applied', async () => {
  const app = createApp();
  assert.equal(app.get('trust proxy'), 1);

  await withTestServer(
    () => null,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/config`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-powered-by'), null);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
      assert.equal(res.headers.get('access-control-allow-origin'), null);
      const csp = res.headers.get('content-security-policy') || '';
      assert.match(csp, /object-src 'none'/);
      assert.match(csp, /base-uri 'self'/);
      assert.match(csp, /frame-ancestors/);

      const body = await res.json();
      assert.equal(body.bffEnabled, true);
      assert.equal('supabaseSecretKey' in body, false);
    }
  );
});

test('Rate limiting enforces HTTP 429 with Retry-After on repeated login attempts', async () => {
  await withTestServer(
    () => {
      throw new BffError('Invalid username or password.', 401, 'UNAUTHORIZED');
    },
    async (baseUrl) => {
      let lastStatus = 0;
      let retryAfter = '';
      // Login user limit is 12 per 15 min window
      for (let i = 0; i < 13; i += 1) {
        const res = await fetch(`${baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
          },
          body: JSON.stringify({ username: 'victim', password: 'wrong-password-attempt' }),
        });
        lastStatus = res.status;
        retryAfter = res.headers.get('retry-after') || '';
      }
      assert.equal(lastStatus, 429);
      assert.ok(Number(retryAfter) > 0);
    }
  );
});

test('Input validation rejects invalid UUIDs, invalid colors, oversized payloads, and sanitizes internal errors', async () => {
  await withTestServer(
    (fn) => {
      if (fn === 'lb_get_workspace') {
        throw new Error('relation "public.secret_table" at character 42 stack trace leak');
      }
      return null;
    },
    async (baseUrl) => {
      const headers = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: 'lb_session=valid_cookie_token',
      };

      // Weak signup password (< 12 chars)
      const weakPw = await fetch(`${baseUrl}/api/auth/signup`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ username: 'newuser', password: 'short' }),
      });
      assert.equal(weakPw.status, 400);

      // Invalid username
      const badUser = await fetch(`${baseUrl}/api/auth/signup`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ username: '../admin', password: 'strong-password-123' }),
      });
      assert.equal(badUser.status, 400);

      // Invalid UUID on category update
      const badUuid = await fetch(`${baseUrl}/api/categories/not-a-uuid`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ name: 'Test', color: '#3b82f6' }),
      });
      assert.equal(badUuid.status, 400);

      // Invalid hex color
      const badColor = await fetch(`${baseUrl}/api/categories`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ name: 'Test', color: 'javascript:alert(1)' }),
      });
      assert.equal(badColor.status, 400);

      // Oversized message (> 10,000 chars)
      const bigLog = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: 'x'.repeat(10_001), tags: [] }),
      });
      assert.equal(bigLog.status, 400);

      // > 25 tags
      const tooManyTags = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          message: 'hello',
          tags: Array.from({ length: 26 }, (_, i) => `t${i}`),
        }),
      });
      assert.equal(tooManyTags.status, 400);

      // > 200 bulk IDs
      const validUuid = '11111111-1111-4111-8111-111111111111';
      const tooManyBulk = await fetch(`${baseUrl}/api/logs/bulk`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ids: Array.from({ length: 201 }, () => validUuid),
          type: 'pin',
        }),
      });
      assert.equal(tooManyBulk.status, 400);

      // Malformed JSON
      const badJson = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers,
        body: '{not valid json',
      });
      assert.equal(badJson.status, 400);
      assert.equal((await badJson.json()).code, 'INVALID_JSON');

      // Sanitized internal error (never leaks SQL/table names)
      const internalErr = await fetch(`${baseUrl}/api/workspace`, {
        headers: { Cookie: 'lb_session=valid_cookie_token' },
      });
      assert.equal(internalErr.status, 500);
      const errBody = await internalErr.json();
      assert.equal(errBody.error, 'Internal server error.');
      assert.equal(errBody.code, 'INTERNAL_ERROR');
    }
  );
});
