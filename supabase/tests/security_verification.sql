-- =============================================================================
-- Logbook PostgreSQL / Supabase Security Verification Script
-- Run against a PostgreSQL / Supabase database (inside a rolled-back transaction
-- or staging DB) to verify privilege lockdown, tenant isolation, FK behavior,
-- rate limiting, and hardened RPC input validation.
-- =============================================================================

begin;

-- 1. Verify internal helper functions are NOT executable by anon/authenticated/PUBLIC
do $$
declare
  v_fn text;
  v_private_fns text[] := array[
    'public.lb_hash_token(text)',
    'public.lb_is_valid_hex_color(text)',
    'public.lb_normalize_username(text)',
    'public.lb_normalize_tag(text)',
    'public.lb_default_tag_color(text)',
    'public.lb_hash_password(text)',
    'public.lb_verify_password(text, text)',
    'public.lb_check_rate_limit(text, text, integer, integer)',
    'public.lb_cleanup_expired_sessions(integer)',
    'public.lb_require_session(text)',
    'public.lb_hydrate_log(uuid, uuid)',
    'public.lb_find_or_create_category(uuid, text)',
    'public.lb_sync_log_tags(uuid, uuid, text[])'
  ];
begin
  foreach v_fn in array v_private_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'SECURITY_FAIL: anon has EXECUTE on internal function %', v_fn;
    end if;
    if has_function_privilege('authenticated', v_fn, 'EXECUTE') then
      raise exception 'SECURITY_FAIL: authenticated has EXECUTE on internal function %', v_fn;
    end if;
    if has_function_privilege('public', v_fn, 'EXECUTE') then
      raise exception 'SECURITY_FAIL: PUBLIC has EXECUTE on internal function %', v_fn;
    end if;
  end loop;
end $$;

-- 2. Verify schema CREATE is revoked and direct table privileges are denied
do $$
declare
  v_tbl text;
  v_tables text[] := array[
    'public.users',
    'public.sessions',
    'public.api_tokens',
    'public.categories',
    'public.tags',
    'public.logs',
    'public.log_tags',
    'public.lb_rate_limits'
  ];
begin
  if has_schema_privilege('anon', 'public', 'CREATE')
     or has_schema_privilege('authenticated', 'public', 'CREATE')
     or has_schema_privilege('public', 'public', 'CREATE') then
    raise exception 'SECURITY_FAIL: CREATE privilege on schema public is still granted';
  end if;

  foreach v_tbl in array v_tables loop
    if has_table_privilege('anon', v_tbl, 'SELECT')
       or has_table_privilege('authenticated', v_tbl, 'SELECT') then
      raise exception 'SECURITY_FAIL: Direct SELECT granted on %', v_tbl;
    end if;
  end loop;
end $$;

-- 3. Verify all public SECURITY DEFINER functions pin search_path to pg_catalog first
do $$
declare
  v_bad_count int;
begin
  select count(*) into v_bad_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname like 'lb_%'
    and p.prosecdef = true
    and (
      p.proconfig is null
      or not exists (
        select 1
        from unnest(p.proconfig) cfg
        where cfg like 'search_path=pg_catalog, public%'
      )
    );

  if v_bad_count > 0 then
    raise exception 'SECURITY_FAIL: % SECURITY DEFINER lb_* functions missing search_path starting with pg_catalog, public', v_bad_count;
  end if;
end $$;

-- 4. Functional & multi-tenant IDOR verification
do $$
declare
  v_alice jsonb;
  v_bob jsonb;
  v_alice_token text;
  v_bob_token text;
  v_alice_cat jsonb;
  v_alice_log jsonb;
  v_alice_cat_id uuid;
  v_alice_log_id uuid;
  v_import_res jsonb;
  v_api_token jsonb;
  v_webhook_res jsonb;
  v_cp_res jsonb;
  v_dup_failed boolean := false;
  v_idor_blocked boolean := false;
  v_old_session_blocked boolean := false;
  v_bad_webhook_blocked boolean := false;
  v_flood_blocked boolean := false;
  v_i int;
begin
  -- 4a. Public registration creates independent users
  v_alice := public.lb_signup('sec_alice_01', 'Correct-Horse-Battery-1!');
  v_bob := public.lb_signup('sec_bob_01', 'Correct-Horse-Battery-2!');
  v_alice_token := v_alice->>'token';
  v_bob_token := v_bob->>'token';

  -- 4b. Case-insensitive username uniqueness rejects mixed-case duplicate
  begin
    perform public.lb_signup('SEC_ALICE_01', 'Correct-Horse-Battery-3!');
  exception when others then
    v_dup_failed := true;
  end;
  if not v_dup_failed then
    raise exception 'SECURITY_FAIL: Case-insensitive duplicate username was allowed';
  end if;

  -- 4c. Create category & log under Alice, then verify Bob cannot update/delete or attach it
  v_alice_cat := public.lb_create_category(v_alice_token, 'OpsVerify', '#3b82f6');
  v_alice_cat_id := (v_alice_cat->>'id')::uuid;
  v_alice_log := public.lb_create_log(v_alice_token, 'Alice private entry', v_alice_cat_id, array['ops', 'prod'], true, null);
  v_alice_log_id := (v_alice_log->>'id')::uuid;

  begin
    perform public.lb_create_log(v_bob_token, 'Bob cross-tenant category attempt', v_alice_cat_id, array[], false, null);
  exception when others then
    v_idor_blocked := true;
  end;
  if not v_idor_blocked then
    raise exception 'SECURITY_FAIL: Bob was able to attach Alice category';
  end if;

  if public.lb_delete_log(v_bob_token, v_alice_log_id) then
    raise exception 'SECURITY_FAIL: Bob was able to delete Alice log';
  end if;

  -- 4d. Non-empty category deletion succeeds and preserves log with NULL category_id
  if not public.lb_delete_category(v_alice_token, v_alice_cat_id) then
    raise exception 'FUNCTIONAL_FAIL: Deleting non-empty category returned false';
  end if;
  if exists (
    select 1 from public.logs where id = v_alice_log_id and category_id is not null
  ) then
    raise exception 'FUNCTIONAL_FAIL: Log category_id was not cleared on category deletion';
  end if;

  -- 4e. Import tolerates bad rows (invalid pinned / invalid created_at / non-array tags) without aborting valid rows
  v_import_res := public.lb_import_logs(
    v_alice_token,
    jsonb_build_array(
      jsonb_build_object('message', 'Valid imported entry', 'pinned', true, 'tags', jsonb_build_array('import')),
      jsonb_build_object('message', 'Bad pinned entry', 'pinned', 'definitely_not_bool'),
      jsonb_build_object('message', 'Bad timestamp entry', 'created_at', 'not-a-timestamp'),
      jsonb_build_object('message', 'Bad tags entry', 'tags', 'not-an-array')
    )
  );
  if (v_import_res->>'imported')::int <> 1 or (v_import_res->>'failed')::int <> 3 then
    raise exception 'FUNCTIONAL_FAIL: Unexpected import summary %', v_import_res;
  end if;

  -- 4f. Webhook valid token succeeds & invalid token fails
  v_api_token := public.lb_create_api_token(v_alice_token, 'ci-verify');
  v_webhook_res := public.lb_ingest_webhook(v_api_token->>'raw_token', 'Webhook ok', 'Deployment', array['ci'], false);
  if v_webhook_res->'log'->>'message' <> 'Webhook ok' then
    raise exception 'FUNCTIONAL_FAIL: Webhook ingestion failed';
  end if;

  begin
    perform public.lb_ingest_webhook('lbk_invalid_00000000000000000000000000', 'Should fail', 'Deployment', array[], false);
  exception when others then
    v_bad_webhook_blocked := true;
  end;
  if not v_bad_webhook_blocked then
    raise exception 'SECURITY_FAIL: Invalid webhook token was accepted';
  end if;

  -- 4g. Session rotation invalidates old session token after password change
  v_cp_res := public.lb_change_password(v_alice_token, 'Correct-Horse-Battery-1!', 'Rotated-Strong-Pass-9!');
  begin
    perform public.lb_me(v_alice_token);
  exception when others then
    v_old_session_blocked := true;
  end;
  if not v_old_session_blocked then
    raise exception 'SECURITY_FAIL: Old session remained valid after password change';
  end if;
  if (public.lb_me(v_cp_res->>'token')->>'username') <> 'sec_alice_01' then
    raise exception 'FUNCTIONAL_FAIL: Rotated session token failed lb_me';
  end if;

  -- 4h. DB-level global signup anti-flood blocks burst > 30 within window
  for v_i in 1..35 loop
    begin
      perform public.lb_signup('flood_user_' || v_i::text, 'Strong-Flood-Password-123!');
    exception when others then
      if sqlerrm like 'RATE_LIMITED:%' then
        v_flood_blocked := true;
        exit;
      end if;
    end;
  end loop;
  if not v_flood_blocked then
    raise exception 'SECURITY_FAIL: DB-level global signup anti-flood limit did not trigger';
  end if;
end $$;

rollback;
