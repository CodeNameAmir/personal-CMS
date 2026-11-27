import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp, type CreateAppOptions } from '../server';
import { BffError } from './supabaseProxy';
import { SlidingWindowRateLimiter, validatePassword, validateTrustProxy } from './security';

type RpcCall = { fn: string; params: Record<string, unknown> };

async function withTestServer(
  handler: (fn: string, params: Record<string, unknown>) => unknown | Promise<unknown>,
  run: (baseUrl: string, calls: RpcCall[]) => Promise<void>,
  extraOptions: Partial<CreateAppOptions> = {}
) {
  const calls: RpcCall[] = [];
  const app = createApp({
    rateLimiter: new SlidingWindowRateLimiter(1000),
    rpcCaller: async <T>(fn: string, params: Record<string, unknown>) => {
      calls.push({ fn, params });
      return (await handler(fn, params)) as T;
    },
    ...extraOptions,
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
        return { token: 'lbs_signup_token_secret_123456', user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
      }
      if (fn === 'lb_login') {
        return { token: 'lbs_login_token_secret_123456', user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
      }
      if (fn === 'lb_me') {
        assert.equal(params.p_token, 'lbs_login_token_secret_123456');
        return { id: '11111111-1111-4111-8111-111111111111', username: 'alice' };
      }
      if (fn === 'lb_change_password') {
        assert.equal(params.p_token, 'lbs_login_token_secret_123456');
        return { ok: true, token: 'lbs_rotated_token_secret_123456' };
      }
      if (fn === 'lb_logout') {
        return true;
      }
      return null;
    },
    async (baseUrl, calls) => {
      // Public signup sets HttpOnly cookie and omits raw token from JSON body
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
      assert.match(signupCookie, /lb_session=lbs_signup_token_secret_123456/);
      assert.match(signupCookie, /HttpOnly/i);
      assert.match(signupCookie, /SameSite=Lax/i);

      // With trustProxy='1', HTTPS proxy header sets Secure + SameSite=None + Partitioned cookie
      const loginHttpsRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-Forwarded-Proto': 'https',
        },
        body: JSON.stringify({ username: 'alice', password: 'legacy-password-value' }),
      });
      assert.equal(loginHttpsRes.status, 200);
      const loginCookie = loginHttpsRes.headers.get('set-cookie') || '';
      assert.match(loginCookie, /lb_session=lbs_login_token_secret_123456/);
      assert.match(loginCookie, /Secure/i);
      assert.match(loginCookie, /SameSite=None/i);
      assert.match(loginCookie, /Partitioned/i);

      // /api/auth/me reads session cookie
      const meRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: 'lb_session=lbs_login_token_secret_123456' },
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
          Cookie: 'lb_session=lbs_login_token_secret_123456',
        },
        body: JSON.stringify({
          currentPassword: 'old-password-value',
          newPassword: 'new-strong-password-123',
        }),
      });
      assert.equal(cpRes.status, 200);
      const cpCookie = cpRes.headers.get('set-cookie') || '';
      assert.match(cpCookie, /lb_session=lbs_rotated_token_secret_123456/);

      // /api/auth/logout clears cookie and revokes session server-side
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          Cookie: 'lb_session=lbs_rotated_token_secret_123456',
        },
      });
      assert.equal(logoutRes.status, 200);
      const logoutCookie = logoutRes.headers.get('set-cookie') || '';
      assert.match(logoutCookie, /Max-Age=0/i);
      assert.equal(calls.at(-1)?.fn, 'lb_logout');
    },
    { trustProxy: '1' }
  );
});

test('TRUST_PROXY defaults to false, ignores spoofed forwarded headers, and rejects unsafe "true"', async () => {
  assert.equal(validateTrustProxy(undefined).value, false);
  assert.equal(validateTrustProxy('').value, false);
  assert.equal(validateTrustProxy('false').value, false);

  const unsafeTrue = validateTrustProxy('true');
  assert.equal(unsafeTrue.valid, false);
  assert.equal(unsafeTrue.value, false);

  assert.equal(validateTrustProxy('loopback').value, 'loopback');
  assert.deepEqual(validateTrustProxy('127.0.0.1, 10.0.0.0/8').value, ['127.0.0.1', '10.0.0.0/8']);

  const defaultApp = createApp();
  assert.equal(defaultApp.get('trust proxy'), false);

  await withTestServer(
    (fn, params) => {
      if (fn === 'lb_login') {
        return { token: 'lbs_login_token_default_1234', user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
      }
      return null;
    },
    async (baseUrl) => {
      // Spoofed X-Forwarded-Proto & X-Forwarded-Host are ignored when trust proxy is false
      const spoofedRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-Forwarded-Proto': 'https',
          'X-Forwarded-Host': 'attacker.example',
          Origin: 'https://attacker.example',
        },
        body: JSON.stringify({ username: 'alice', password: 'password-value-123' }),
      });
      assert.equal(spoofedRes.status, 403);
      assert.equal((await spoofedRes.json()).code, 'FORBIDDEN_ORIGIN');

      // Spoofed X-Forwarded-Proto without foreign Origin does NOT set Secure cookie over plain HTTP
      const loginHttp = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-Forwarded-Proto': 'https',
        },
        body: JSON.stringify({ username: 'alice', password: 'password-value-123' }),
      });
      assert.equal(loginHttp.status, 200);
      const cookie = loginHttp.headers.get('set-cookie') || '';
      assert.doesNotMatch(cookie, /;\s*Secure/i);
      assert.match(cookie, /SameSite=Lax/i);
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

test('Security headers including Permissions-Policy, strict CORS, and config safety are applied', async () => {
  await withTestServer(
    () => null,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/config`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-powered-by'), null);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
      assert.match(res.headers.get('permissions-policy') || '', /camera=\(\)/);
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

test('Rate limiting enforces HTTP 429 on login, configurable signup IP/username/global anti-abuse limits, and X-Forwarded-For spoofing defense', async () => {
  const prevIpMax = process.env.SIGNUP_RATE_LIMIT_IP_MAX;
  const prevUserMax = process.env.SIGNUP_RATE_LIMIT_USER_MAX;
  const prevGlobalMax = process.env.SIGNUP_RATE_LIMIT_GLOBAL_MAX;

  process.env.SIGNUP_RATE_LIMIT_IP_MAX = '3';
  process.env.SIGNUP_RATE_LIMIT_USER_MAX = '2';
  process.env.SIGNUP_RATE_LIMIT_GLOBAL_MAX = '5';

  try {
    await withTestServer(
      (fn, params) => {
        if (fn === 'lb_signup') {
          return { token: `lbs_${params.p_username}`, user: { id: '11111111-1111-4111-8111-111111111111', username: params.p_username } };
        }
        throw new BffError('Invalid username or password.', 401, 'UNAUTHORIZED');
      },
      async (baseUrl) => {
        // Signup works for distinct valid users until IP limit (3) triggers even when X-Forwarded-For is rotated
        for (let i = 1; i <= 3; i += 1) {
          const ok = await fetch(`${baseUrl}/api/auth/signup`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
              'X-Forwarded-For': `198.51.100.${i}`,
            },
            body: JSON.stringify({ username: `friend_${i}`, password: 'strong-password-123' }),
          });
          assert.equal(ok.status, 201);
        }

        const blockedSignup = await fetch(`${baseUrl}/api/auth/signup`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Forwarded-For': '203.0.113.99',
          },
          body: JSON.stringify({ username: 'friend_4', password: 'strong-password-123' }),
        });
        assert.equal(blockedSignup.status, 429);
        assert.ok(Number(blockedSignup.headers.get('retry-after')) > 0);

        // Login user limit is 12 per 15 min window
        let lastStatus = 0;
        let retryAfter = '';
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
  } finally {
    if (prevIpMax === undefined) delete process.env.SIGNUP_RATE_LIMIT_IP_MAX;
    else process.env.SIGNUP_RATE_LIMIT_IP_MAX = prevIpMax;
    if (prevUserMax === undefined) delete process.env.SIGNUP_RATE_LIMIT_USER_MAX;
    else process.env.SIGNUP_RATE_LIMIT_USER_MAX = prevUserMax;
    if (prevGlobalMax === undefined) delete process.env.SIGNUP_RATE_LIMIT_GLOBAL_MAX;
    else process.env.SIGNUP_RATE_LIMIT_GLOBAL_MAX = prevGlobalMax;
  }
});

test('SlidingWindowRateLimiter strictly bounds memory under distributed key floods via LRU eviction', () => {
  const limiter = new SlidingWindowRateLimiter(100);
  const now = 1_700_000_000_000;
  for (let i = 0; i < 2500; i += 1) {
    limiter.check('signup_ip', `198.51.${Math.floor(i / 256)}.${i % 256}`, 10, 60_000, now);
  }
  assert.ok(limiter.size <= 100, `Expected limiter size <= 100, got ${limiter.size}`);
});

test('Input validation rejects invalid types, non-JSON Content-Type, strict booleans, invalid UUIDs, oversized payloads, and sanitizes internal errors', async () => {
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

      // Reject non-JSON Content-Type -> 415
      const wrongContentType = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'X-Requested-With': 'XMLHttpRequest',
          Cookie: 'lb_session=valid_cookie_token',
        },
        body: JSON.stringify({ message: 'hello' }),
      });
      assert.equal(wrongContentType.status, 415);

      // Reject JSON array instead of object -> 400
      const arrayBody = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers,
        body: JSON.stringify(['not', 'an', 'object']),
      });
      assert.equal(arrayBody.status, 400);

      // Reject string "false" for boolean pinned (was coerced to true by Boolean("false")!)
      const stringPinned = await fetch(`${baseUrl}/api/logs`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: 'hello', pinned: 'false' }),
      });
      assert.equal(stringPinned.status, 400);

      const stringPinnedWebhook = await fetch(`${baseUrl}/api/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer lbk_test_token_1234567890abcdef',
        },
        body: JSON.stringify({ message: 'hello', pinned: 'false' }),
      });
      assert.equal(stringPinnedWebhook.status, 400);

      // Weak signup password (< 6 chars)
      const weakPw = await fetch(`${baseUrl}/api/auth/signup`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ username: 'newuser', password: 'short' }),
      });
      assert.equal(weakPw.status, 400);

      // 6-character signup password is accepted
      assert.equal(validatePassword('12345'), 'Password must be between 6 and 128 characters.');
      assert.equal(validatePassword('123456'), null);
      const validShortPw = await fetch(`${baseUrl}/api/auth/signup`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ username: 'newuser6', password: 'abc123' }),
      });
      assert.notEqual(validShortPw.status, 400);

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

      // > 200 bulk IDs & stray category_id on non-category action
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

      const strayBulkCategory = await fetch(`${baseUrl}/api/logs/bulk`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ids: [validUuid],
          type: 'pin',
          category_id: validUuid,
        }),
      });
      assert.equal(strayBulkCategory.status, 400);

      const emptyBulkTag = await fetch(`${baseUrl}/api/logs/bulk`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ids: [validUuid],
          type: 'add_tag',
          tag: '   ',
        }),
      });
      assert.equal(emptyBulkTag.status, 400);

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
