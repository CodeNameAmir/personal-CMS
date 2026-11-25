async page => {
  const ctx = page.context();
  const activeTokens = new Set();
  const rpcCalls = [];
  let simulateMissingLbMe = false;

  const sampleWorkspace = {
    categories: [
      { id: 'cat-1', name: 'General', color: '#3b82f6', log_count: 1 },
      { id: 'cat-2', name: 'API', color: '#8b5cf6', log_count: 1 },
    ],
    tags: [
      { id: 'tag-1', name: 'deploy', color: '#10b981', log_count: 1 },
      { id: 'tag-2', name: 'prod', color: '#f59e0b', log_count: 1 },
    ],
    logs: [
      {
        id: 'log-1',
        message: 'Deployed build to log.codenameamir.ir',
        category_id: 'cat-1',
        category_name: 'General',
        category_color: '#3b82f6',
        tags: [{ id: 'tag-1', name: 'deploy', color: '#10b981' }],
        pinned: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: 'log-2',
        message: 'Supabase session persistence check passed',
        category_id: 'cat-2',
        category_name: 'API',
        category_color: '#8b5cf6',
        tags: [{ id: 'tag-2', name: 'prod', color: '#f59e0b' }],
        pinned: false,
        created_at: new Date(Date.now() - 60000).toISOString(),
        updated_at: new Date(Date.now() - 60000).toISOString(),
      },
    ],
  };

  await ctx.route('**/api/config', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        supabaseUrl: 'https://demo.supabase.co',
        supabasePublishableKey: 'sb_publishable_demo_key',
        supabaseConfigured: true,
      }),
    });
  });

  await ctx.route('**/*.supabase.co/rest/v1/rpc/*', async route => {
    const fn = route.request().url().split('/rpc/')[1]?.split('?')[0];
    const body = route.request().postDataJSON() || {};
    rpcCalls.push(fn);

    if (fn === 'lb_login') {
      const token = 'lbs_test_token_123';
      activeTokens.add(token);
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          token,
          user: { id: 'user-1', username: body.p_username || 'amir' },
        }),
      });
    }

    if (fn === 'lb_me') {
      if (simulateMissingLbMe) {
        return route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'PGRST202', message: 'Could not find the function public.lb_me' }),
        });
      }
      if (!activeTokens.has(body.p_token)) {
        return route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'UNAUTHORIZED: Session expired or invalid' }),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ id: 'user-1', username: 'amir' }),
      });
    }

    if (fn === 'lb_get_workspace') {
      if (!activeTokens.has(body.p_token)) {
        return route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'UNAUTHORIZED: Session expired or invalid' }),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(sampleWorkspace),
      });
    }

    if (fn === 'lb_logout') {
      activeTokens.delete(body.p_token);
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(true),
      });
    }

    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(true),
    });
  });

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('http://localhost:3000');
  await page.evaluate(() => localStorage.clear());
  await page.reload();

  // 1. Login
  await page.getByLabel('Username').fill('amir');
  await page.getByLabel('Password', { exact: true }).fill('secret123');
  await page.getByRole('button', { name: 'Sign In' }).click();
  await page.getByText('Deployed build to log.codenameamir.ir').first().waitFor({ timeout: 5000 });
  const tokenAfterLogin = await page.evaluate(() => localStorage.getItem('logbook_session_token'));
  await page.screenshot({ path: '.playwright-cli/verify-logged-in.png' });

  // 2. Reload same tab
  await page.reload();
  await page.getByText('Deployed build to log.codenameamir.ir').first().waitFor({ timeout: 5000 });
  const headingAfterReload = await page.getByRole('heading', { level: 1 }).textContent();
  await page.screenshot({ path: '.playwright-cli/verify-after-reload.png' });

  // 3. Open brand-new tab in same context (simulates closing/reopening tab)
  const page2 = await ctx.newPage();
  await page2.setViewportSize({ width: 1280, height: 800 });
  await page2.goto('http://localhost:3000');
  await page2.getByText('Deployed build to log.codenameamir.ir').first().waitFor({ timeout: 5000 });
  await page2.screenshot({ path: '.playwright-cli/verify-new-tab.png' });

  // 4. Backward-compatibility check when lb_me is not yet deployed in DB
  simulateMissingLbMe = true;
  const page3 = await ctx.newPage();
  await page3.setViewportSize({ width: 1280, height: 800 });
  await page3.goto('http://localhost:3000');
  await page3.getByText('Deployed build to log.codenameamir.ir').first().waitFor({ timeout: 5000 });
  simulateMissingLbMe = false;

  // 5. Sign out on page2 and verify cross-tab sync + persistence of logout
  await page2.getByRole('button', { name: 'amir', exact: true }).click();
  await page2.getByRole('button', { name: 'Sign Out' }).click();
  await page2.getByRole('heading', { name: 'Sign in to Logbook' }).waitFor({ timeout: 5000 });
  await page.getByRole('heading', { name: 'Sign in to Logbook' }).waitFor({ timeout: 5000 });
  const tokenAfterLogout = await page2.evaluate(() => localStorage.getItem('logbook_session_token'));

  await page2.reload();
  await page2.getByRole('heading', { name: 'Sign in to Logbook' }).waitFor({ timeout: 5000 });

  await page2.close();
  await page3.close();

  return {
    tokenAfterLogin,
    headingAfterReload,
    tokenAfterLogout,
    rpcCalls,
  };
}
