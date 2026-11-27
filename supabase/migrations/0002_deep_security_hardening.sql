-- =============================================================================
-- Migration: 0002_deep_security_hardening.sql
-- Purpose:
--   1. Revoke CREATE on schema public from PUBLIC, anon, authenticated.
--   2. Harden search_path across all functions to pg_catalog, public(, extensions).
--   3. Fix non-empty category deletion under composite tenant FK logs_user_category_fkey
--      (PG 15+ ON DELETE SET NULL (category_id) + pre-nullification in lb_delete_category).
--   4. Add DB-level global signup flood rate limits while keeping public signup enabled,
--      plus probabilistic bounded stale rate-limit cleanup for static hosting mode.
--   5. Fix tag upsert race conditions (lb_create_or_get_tag, lb_bulk_logs_action) and
--      harden lb_import_logs per-row type/timestamp/boolean error handling.
--   6. Re-verify exact-signature REVOKE / GRANT function privileges.
-- Safety: Idempotent & non-destructive to existing user data.
-- =============================================================================

begin;

-- -----------------------------------------------------------------------------
-- 1. Schema-level privilege hardening
-- -----------------------------------------------------------------------------
revoke create on schema public from public, anon, authenticated;
grant usage on schema public to anon, authenticated;

alter default privileges in schema public
  revoke execute on functions from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- 2. Fix logs_user_category_fkey deletion behavior without losing tenant check
-- -----------------------------------------------------------------------------
do $$
begin
  -- Clean up any dangling cross-user category references defensively
  update public.logs l
  set category_id = null
  where l.category_id is not null
    and not exists (
      select 1
      from public.categories c
      where c.id = l.category_id
        and c.user_id = l.user_id
    );

  if current_setting('server_version_num')::int >= 150000 then
    alter table public.logs drop constraint if exists logs_user_category_fkey;
    alter table public.logs
      add constraint logs_user_category_fkey
      foreign key (user_id, category_id)
      references public.categories(user_id, id)
      on delete set null (category_id);

    -- Redundant single-column FK would conflict or duplicate work on PG 15+
    alter table public.logs drop constraint if exists logs_category_id_fkey;
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- 3. Harden internal helper search_paths & maintenance cleanup
-- -----------------------------------------------------------------------------
create or replace function public.lb_hash_token(p_raw text)
returns text
language sql
immutable
strict
set search_path = pg_catalog, public, extensions
as $$
  select encode(digest(convert_to(p_raw, 'UTF8'), 'sha256'), 'hex');
$$;

create or replace function public.lb_is_valid_hex_color(p_color text)
returns boolean
language sql
immutable
set search_path = pg_catalog, public
as $$
  select coalesce(p_color, '') ~ '^#[0-9a-fA-F]{6}$';
$$;

create or replace function public.lb_normalize_username(p_raw text)
returns text
language sql
immutable
set search_path = pg_catalog, public
as $$
  select lower(trim(coalesce(p_raw, '')));
$$;

create or replace function public.lb_normalize_tag(p_raw text)
returns text
language sql
immutable
set search_path = pg_catalog, public
as $$
  select left(
    regexp_replace(
      regexp_replace(
        lower(regexp_replace(trim(coalesce(p_raw, '')), '^#+', '')),
        '\s+',
        '-',
        'g'
      ),
      '[!"#$%&''()*+,./:;<=>?@\[\\\]^`{|}~،؛؟]+',
      '',
      'g'
    ),
    32
  );
$$;

create or replace function public.lb_default_tag_color(p_name text)
returns text
language plpgsql
immutable
set search_path = pg_catalog, public
as $$
declare
  v_palette text[] := array['#64748b', '#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#f97316'];
  v_idx int;
begin
  v_idx := (abs(hashtext(coalesce(p_name, ''))) % array_length(v_palette, 1)) + 1;
  return v_palette[v_idx];
end;
$$;

create or replace function public.lb_hash_password(p_password text)
returns text
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_digest text;
begin
  v_digest := encode(digest(convert_to(p_password, 'UTF8'), 'sha256'), 'hex');
  return 'v2:' || crypt(v_digest, gen_salt('bf', 12));
end;
$$;

create or replace function public.lb_verify_password(p_password text, p_stored_hash text)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_digest text;
  v_bcrypt_part text;
begin
  if p_password is null or p_stored_hash is null or char_length(p_password) = 0 then
    return false;
  end if;

  if left(p_stored_hash, 3) = 'v2:' then
    v_bcrypt_part := substr(p_stored_hash, 4);
    v_digest := encode(digest(convert_to(p_password, 'UTF8'), 'sha256'), 'hex');
    return v_bcrypt_part = crypt(v_digest, v_bcrypt_part);
  end if;

  return p_stored_hash = crypt(p_password, p_stored_hash);
end;
$$;

create or replace function public.lb_check_rate_limit(
  p_scope text,
  p_key text,
  p_max_attempts integer,
  p_window_seconds integer
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_key_hash text := public.lb_hash_token(coalesce(p_scope, '') || ':' || coalesce(p_key, ''));
  v_now timestamptz := now();
  v_attempts integer;
begin
  insert into public.lb_rate_limits (scope, key_hash, window_start, attempts)
  values (p_scope, v_key_hash, v_now, 1)
  on conflict (scope, key_hash) do update
  set
    attempts = case
      when public.lb_rate_limits.window_start + make_interval(secs => p_window_seconds) <= v_now then 1
      else public.lb_rate_limits.attempts + 1
    end,
    window_start = case
      when public.lb_rate_limits.window_start + make_interval(secs => p_window_seconds) <= v_now then v_now
      else public.lb_rate_limits.window_start
    end
  returning attempts into v_attempts;

  if v_attempts > p_max_attempts then
    raise exception 'RATE_LIMITED: Too many requests. Please try again later.';
  end if;
end;
$$;

create or replace function public.lb_cleanup_expired_sessions(p_batch_size integer default 1000)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_limit int := least(10000, greatest(1, coalesce(p_batch_size, 1000)));
  v_deleted int := 0;
begin
  delete from public.sessions
  where id in (
    select id
    from public.sessions
    where expires_at <= now()
    order by expires_at asc
    limit v_limit
  );
  get diagnostics v_deleted = row_count;

  delete from public.lb_rate_limits
  where window_start < now() - interval '24 hours';

  return v_deleted;
end;
$$;

create or replace function public.lb_require_session(p_token text)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_trimmed text := trim(coalesce(p_token, ''));
  v_user_id uuid;
begin
  if length(v_trimmed) < 16 or length(v_trimmed) > 256 or left(v_trimmed, 4) <> 'lbs_' then
    raise exception 'UNAUTHORIZED: Missing or invalid session token';
  end if;

  select s.user_id into v_user_id
  from public.sessions s
  where s.token_hash = public.lb_hash_token(v_trimmed)
    and s.expires_at > now()
  limit 1;

  if v_user_id is null then
    raise exception 'UNAUTHORIZED: Session expired or invalid';
  end if;

  return v_user_id;
end;
$$;

create or replace function public.lb_hydrate_log(p_user_id uuid, p_log_id uuid)
returns jsonb
language sql
security definer
set search_path = pg_catalog, public, extensions
as $$
  select jsonb_build_object(
    'id', l.id,
    'message', l.message,
    'category_id', l.category_id,
    'category_name', coalesce(c.name, 'Uncategorized'),
    'category_color', coalesce(c.color, '#64748b'),
    'tags', coalesce((
      select jsonb_agg(
        jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color)
        order by t.name asc
      )
      from public.log_tags lt
      join public.tags t on t.id = lt.tag_id and t.user_id = l.user_id
      where lt.log_id = l.id and lt.user_id = l.user_id
    ), '[]'::jsonb),
    'pinned', l.pinned,
    'created_at', l.created_at,
    'updated_at', l.updated_at
  )
  from public.logs l
  left join public.categories c on c.id = l.category_id and c.user_id = l.user_id
  where l.id = p_log_id
    and l.user_id = p_user_id;
$$;

create or replace function public.lb_find_or_create_category(p_user_id uuid, p_name text)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_clean text := left(coalesce(nullif(trim(p_name), ''), 'General'), 64);
  v_id uuid;
begin
  if p_user_id is null or not exists (select 1 from public.users where id = p_user_id) then
    raise exception 'UNAUTHORIZED: Invalid user context';
  end if;

  select id into v_id
  from public.categories
  where user_id = p_user_id and lower(name) = lower(v_clean)
  limit 1;

  if v_id is not null then
    return v_id;
  end if;

  insert into public.categories (user_id, name, color)
  values (p_user_id, v_clean, '#3b82f6')
  on conflict (user_id, name) do update set name = excluded.name
  returning id into v_id;

  return v_id;
end;
$$;

create or replace function public.lb_sync_log_tags(p_user_id uuid, p_log_id uuid, p_tags text[])
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_raw text;
  v_clean text;
  v_tag_id uuid;
begin
  if p_user_id is null or not exists (
    select 1 from public.logs where id = p_log_id and user_id = p_user_id
  ) then
    raise exception 'UNAUTHORIZED: Log ownership check failed';
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'Too many tags per log (maximum 25).';
  end if;

  delete from public.log_tags where log_id = p_log_id and user_id = p_user_id;

  if p_tags is null then
    return;
  end if;

  foreach v_raw in array p_tags loop
    v_clean := public.lb_normalize_tag(v_raw);
    if length(v_clean) = 0 then
      continue;
    end if;

    select id into v_tag_id
    from public.tags
    where user_id = p_user_id and name = v_clean
    limit 1;

    if v_tag_id is null then
      insert into public.tags (user_id, name, color)
      values (p_user_id, v_clean, public.lb_default_tag_color(v_clean))
      on conflict (user_id, name) do update set name = excluded.name
      returning id into v_tag_id;
    end if;

    insert into public.log_tags (user_id, log_id, tag_id)
    values (p_user_id, p_log_id, v_tag_id)
    on conflict do nothing;
  end loop;
end;
$$;

-- -----------------------------------------------------------------------------
-- 4. Harden Authentication RPCs (keep public signup enabled + DB anti-flood)
-- -----------------------------------------------------------------------------
create or replace function public.lb_signup(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_username text := public.lb_normalize_username(p_username);
  v_user_id uuid;
  v_raw_token text;
begin
  if char_length(v_username) < 2 or char_length(v_username) > 64 then
    raise exception 'Username must be between 2 and 64 characters.';
  end if;
  if v_username !~ '^[a-z0-9][a-z0-9._-]{1,63}$' then
    raise exception 'Username may only contain lowercase letters, numbers, dots, underscores, and hyphens.';
  end if;

  -- DB-level anti-flood limits protect static mode against arbitrary-username signup floods
  -- while keeping public user registration enabled.
  perform public.lb_check_rate_limit('signup_global', 'all', 30, 900);
  perform public.lb_check_rate_limit('signup_global_daily', 'all', 200, 86400);
  perform public.lb_check_rate_limit('signup', v_username, 5, 900);

  if random() < 0.02 then
    delete from public.lb_rate_limits
    where (scope, key_hash) in (
      select scope, key_hash
      from public.lb_rate_limits
      where window_start < now() - interval '24 hours'
      limit 50
    );
  end if;

  if p_password is null or char_length(p_password) < 12 or char_length(p_password) > 128 then
    raise exception 'Password must be between 12 and 128 characters.';
  end if;

  if exists (select 1 from public.users where lower(username) = v_username) then
    raise exception 'Username is already registered.';
  end if;

  begin
    insert into public.users (username, password_hash)
    values (v_username, public.lb_hash_password(p_password))
    returning id into v_user_id;
  exception when unique_violation then
    raise exception 'Username is already registered.';
  end;

  insert into public.categories (user_id, name, color) values
    (v_user_id, 'General', '#3b82f6'),
    (v_user_id, 'API', '#8b5cf6'),
    (v_user_id, 'Notes', '#10b981')
  on conflict (user_id, name) do nothing;

  v_raw_token := 'lbs_' || encode(gen_random_bytes(32), 'hex');
  insert into public.sessions (user_id, token_hash, expires_at)
  values (v_user_id, public.lb_hash_token(v_raw_token), now() + interval '7 days');

  return jsonb_build_object(
    'token', v_raw_token,
    'user', jsonb_build_object('id', v_user_id, 'username', v_username)
  );
end;
$$;

create or replace function public.lb_login(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_username text := public.lb_normalize_username(p_username);
  v_user record;
  v_raw_token text;
begin
  if char_length(v_username) = 0 or char_length(v_username) > 64 then
    raise exception 'Invalid username or password.';
  end if;

  perform public.lb_check_rate_limit('login', v_username, 12, 900);

  if random() < 0.02 then
    delete from public.lb_rate_limits
    where (scope, key_hash) in (
      select scope, key_hash
      from public.lb_rate_limits
      where window_start < now() - interval '24 hours'
      limit 50
    );
  end if;

  if p_password is null or char_length(p_password) = 0 or char_length(p_password) > 128 then
    raise exception 'Invalid username or password.';
  end if;

  select id, username, password_hash into v_user
  from public.users
  where lower(username) = v_username
  limit 1;

  if v_user.id is null or not public.lb_verify_password(p_password, v_user.password_hash) then
    raise exception 'Invalid username or password.';
  end if;

  if left(v_user.password_hash, 3) <> 'v2:' then
    update public.users
    set password_hash = public.lb_hash_password(p_password)
    where id = v_user.id;
  end if;

  v_raw_token := 'lbs_' || encode(gen_random_bytes(32), 'hex');
  insert into public.sessions (user_id, token_hash, expires_at)
  values (v_user.id, public.lb_hash_token(v_raw_token), now() + interval '7 days');

  return jsonb_build_object(
    'token', v_raw_token,
    'user', jsonb_build_object('id', v_user.id, 'username', v_user.username)
  );
end;
$$;

alter function public.lb_logout(text) set search_path = pg_catalog, public, extensions;
alter function public.lb_me(text) set search_path = pg_catalog, public, extensions;
alter function public.lb_change_password(text, text, text) set search_path = pg_catalog, public, extensions;
alter function public.lb_get_workspace(text, integer, integer, text, uuid, text[], text, date, boolean) set search_path = pg_catalog, public, extensions;
alter function public.lb_export_logs(text, text, uuid, text[], text, date, boolean) set search_path = pg_catalog, public, extensions;
alter function public.lb_create_category(text, text, text) set search_path = pg_catalog, public, extensions;
alter function public.lb_update_category(text, uuid, text, text) set search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- 5. Fix category deletion, tag upsert race conditions, and import resilience
-- -----------------------------------------------------------------------------
create or replace function public.lb_delete_category(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  -- Clear category references first so deletion succeeds cleanly across PG 14 & PG 15+
  update public.logs
  set category_id = null, updated_at = now()
  where user_id = v_user_id and category_id = p_id;

  delete from public.categories where id = p_id and user_id = v_user_id;
  return found;
end;
$$;

create or replace function public.lb_create_or_get_tag(
  p_token text,
  p_name text,
  p_color text default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := public.lb_normalize_tag(p_name);
  v_color text;
  v_row public.tags%rowtype;
begin
  if length(v_name) = 0 then
    raise exception 'Tag name is required.';
  end if;

  if p_color is not null and length(trim(p_color)) > 0 then
    if not public.lb_is_valid_hex_color(trim(p_color)) then
      raise exception 'Tag color must be a valid #RRGGBB hex code.';
    end if;
    v_color := trim(p_color);
  else
    v_color := public.lb_default_tag_color(v_name);
  end if;

  select * into v_row
  from public.tags
  where user_id = v_user_id and name = v_name
  limit 1;

  if v_row.id is null then
    insert into public.tags (user_id, name, color)
    values (v_user_id, v_name, v_color)
    on conflict (user_id, name) do update set name = excluded.name
    returning * into v_row;
  end if;

  return jsonb_build_object(
    'id', v_row.id,
    'name', v_row.name,
    'color', v_row.color,
    'created_at', v_row.created_at
  );
end;
$$;

alter function public.lb_update_tag(text, uuid, text, text) set search_path = pg_catalog, public, extensions;
alter function public.lb_delete_tag(text, uuid) set search_path = pg_catalog, public, extensions;
alter function public.lb_create_log(text, text, uuid, text[], boolean, timestamptz) set search_path = pg_catalog, public, extensions;
alter function public.lb_update_log(text, uuid, text, uuid, boolean, text[], boolean) set search_path = pg_catalog, public, extensions;
alter function public.lb_toggle_pin(text, uuid) set search_path = pg_catalog, public, extensions;
alter function public.lb_delete_log(text, uuid) set search_path = pg_catalog, public, extensions;

create or replace function public.lb_bulk_logs_action(
  p_token text,
  p_ids uuid[],
  p_action text,
  p_category_id uuid default null,
  p_tag text default null
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_affected int := 0;
  v_clean_tag text;
  v_tag_id uuid;
  v_log_id uuid;
  v_cat_id uuid := null;
begin
  perform public.lb_check_rate_limit('bulk', v_user_id::text, 30, 60);

  if p_ids is null or array_length(p_ids, 1) is null then
    return 0;
  end if;

  if array_length(p_ids, 1) > 200 then
    raise exception 'Bulk action is limited to 200 logs per request.';
  end if;

  if p_action = 'delete' then
    delete from public.logs where user_id = v_user_id and id = any(p_ids);
    get diagnostics v_affected = row_count;
  elsif p_action = 'pin' then
    update public.logs set pinned = true, updated_at = now()
    where user_id = v_user_id and id = any(p_ids);
    get diagnostics v_affected = row_count;
  elsif p_action = 'unpin' then
    update public.logs set pinned = false, updated_at = now()
    where user_id = v_user_id and id = any(p_ids);
    get diagnostics v_affected = row_count;
  elsif p_action = 'category' then
    if p_category_id is not null then
      select id into v_cat_id
      from public.categories
      where id = p_category_id and user_id = v_user_id
      limit 1;

      if v_cat_id is null then
        raise exception 'Category not found or access denied.';
      end if;
    end if;

    update public.logs set category_id = v_cat_id, updated_at = now()
    where user_id = v_user_id and id = any(p_ids);
    get diagnostics v_affected = row_count;
  elsif p_action = 'add_tag' then
    v_clean_tag := public.lb_normalize_tag(p_tag);
    if length(v_clean_tag) = 0 then
      raise exception 'Tag name is required.';
    end if;

    select id into v_tag_id
    from public.tags
    where user_id = v_user_id and name = v_clean_tag
    limit 1;

    if v_tag_id is null then
      insert into public.tags (user_id, name, color)
      values (v_user_id, v_clean_tag, public.lb_default_tag_color(v_clean_tag))
      on conflict (user_id, name) do update set name = excluded.name
      returning id into v_tag_id;
    end if;

    for v_log_id in select id from public.logs where user_id = v_user_id and id = any(p_ids) loop
      if (select count(*) from public.log_tags where log_id = v_log_id and user_id = v_user_id) < 25 then
        insert into public.log_tags (user_id, log_id, tag_id)
        values (v_user_id, v_log_id, v_tag_id)
        on conflict do nothing;
        v_affected := v_affected + 1;
      end if;
    end loop;
  else
    raise exception 'Unsupported bulk action.';
  end if;

  return v_affected;
end;
$$;

create or replace function public.lb_import_logs(p_token text, p_records jsonb)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_item jsonb;
  v_msg text;
  v_cat_json jsonb;
  v_cat_name text;
  v_cat_id uuid;
  v_tags_json jsonb;
  v_pinned_json jsonb;
  v_pinned boolean;
  v_created_at_raw text;
  v_created_at timestamptz;
  v_tags text[];
  v_log_id uuid;
  v_imported int := 0;
  v_skipped int := 0;
  v_failed int := 0;
  v_errors text[] := '{}';
  v_count int;
begin
  perform public.lb_check_rate_limit('import', v_user_id::text, 10, 300);

  if p_records is null or jsonb_typeof(p_records) <> 'array' then
    raise exception 'Import records must be a JSON array.';
  end if;

  v_count := jsonb_array_length(p_records);
  if v_count > 500 then
    raise exception 'Import is limited to 500 records per request.';
  end if;

  if octet_length(p_records::text) > 1048576 then
    raise exception 'Import payload exceeds 1 MB limit.';
  end if;

  for v_item in select * from jsonb_array_elements(p_records) loop
    if jsonb_typeof(v_item) <> 'object' then
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Record must be a JSON object');
      end if;
      continue;
    end if;

    v_msg := trim(coalesce(v_item->>'message', ''));
    if char_length(v_msg) = 0 or char_length(v_msg) > 10000 then
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Message must be between 1 and 10,000 characters');
      end if;
      continue;
    end if;

    v_cat_json := v_item->'category';
    if v_cat_json is not null and jsonb_typeof(v_cat_json) not in ('null', 'string') then
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Category must be a string');
      end if;
      continue;
    end if;

    v_tags_json := coalesce(v_item->'tags', '[]'::jsonb);
    if jsonb_typeof(v_tags_json) = 'null' then
      v_tags_json := '[]'::jsonb;
    elsif jsonb_typeof(v_tags_json) <> 'array' then
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Tags must be an array of strings');
      end if;
      continue;
    end if;

    select coalesce(array_agg(value::text), '{}')
    into v_tags
    from jsonb_array_elements_text(v_tags_json);

    if coalesce(array_length(v_tags, 1), 0) > 25 then
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Log exceeds maximum of 25 tags');
      end if;
      continue;
    end if;

    v_pinned_json := v_item->'pinned';
    if v_pinned_json is null or jsonb_typeof(v_pinned_json) = 'null' then
      v_pinned := false;
    elsif jsonb_typeof(v_pinned_json) = 'boolean' then
      v_pinned := (v_item->>'pinned')::boolean;
    elsif jsonb_typeof(v_pinned_json) = 'string' and lower(trim(v_item->>'pinned')) in ('true', 'false') then
      v_pinned := lower(trim(v_item->>'pinned')) = 'true';
    else
      v_failed := v_failed + 1;
      if coalesce(array_length(v_errors, 1), 0) < 20 then
        v_errors := array_append(v_errors, 'Invalid pinned boolean value');
      end if;
      continue;
    end if;

    v_created_at_raw := nullif(trim(coalesce(v_item->>'created_at', '')), '');
    if v_created_at_raw is null then
      v_created_at := now();
    else
      begin
        v_created_at := v_created_at_raw::timestamptz;
      exception when others then
        v_failed := v_failed + 1;
        if coalesce(array_length(v_errors, 1), 0) < 20 then
          v_errors := array_append(v_errors, 'Invalid created_at timestamp');
        end if;
        continue;
      end;
    end if;

    if exists (select 1 from public.logs where user_id = v_user_id and message = v_msg) then
      v_skipped := v_skipped + 1;
      continue;
    end if;

    v_cat_name := left(coalesce(nullif(trim(v_item->>'category'), ''), 'General'), 64);
    v_cat_id := public.lb_find_or_create_category(v_user_id, v_cat_name);

    insert into public.logs (user_id, message, category_id, pinned, created_at, updated_at)
    values (v_user_id, v_msg, v_cat_id, v_pinned, v_created_at, v_created_at)
    returning id into v_log_id;

    perform public.lb_sync_log_tags(v_user_id, v_log_id, v_tags);
    v_imported := v_imported + 1;
  end loop;

  return jsonb_build_object(
    'imported', v_imported,
    'skipped', v_skipped,
    'failed', v_failed,
    'errors', to_jsonb(v_errors)
  );
end;
$$;

alter function public.lb_list_api_tokens(text) set search_path = pg_catalog, public, extensions;
alter function public.lb_create_api_token(text, text) set search_path = pg_catalog, public, extensions;
alter function public.lb_delete_api_token(text, uuid) set search_path = pg_catalog, public, extensions;
alter function public.lb_ingest_webhook(text, text, text, text[], boolean) set search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- 6. Re-verify exact-signature REVOKE / GRANT function privileges
-- -----------------------------------------------------------------------------
revoke all on function public.lb_hash_token(text) from public, anon, authenticated;
revoke all on function public.lb_is_valid_hex_color(text) from public, anon, authenticated;
revoke all on function public.lb_normalize_username(text) from public, anon, authenticated;
revoke all on function public.lb_normalize_tag(text) from public, anon, authenticated;
revoke all on function public.lb_default_tag_color(text) from public, anon, authenticated;
revoke all on function public.lb_hash_password(text) from public, anon, authenticated;
revoke all on function public.lb_verify_password(text, text) from public, anon, authenticated;
revoke all on function public.lb_check_rate_limit(text, text, integer, integer) from public, anon, authenticated;
revoke all on function public.lb_cleanup_expired_sessions(integer) from public, anon, authenticated;
revoke all on function public.lb_require_session(text) from public, anon, authenticated;
revoke all on function public.lb_hydrate_log(uuid, uuid) from public, anon, authenticated;
revoke all on function public.lb_find_or_create_category(uuid, text) from public, anon, authenticated;
revoke all on function public.lb_sync_log_tags(uuid, uuid, text[]) from public, anon, authenticated;

grant execute on function public.lb_cleanup_expired_sessions(integer) to service_role;

revoke all on function public.lb_signup(text, text) from public;
revoke all on function public.lb_login(text, text) from public;
revoke all on function public.lb_logout(text) from public;
revoke all on function public.lb_me(text) from public;
revoke all on function public.lb_change_password(text, text, text) from public;
revoke all on function public.lb_get_workspace(text, integer, integer, text, uuid, text[], text, date, boolean) from public;
revoke all on function public.lb_export_logs(text, text, uuid, text[], text, date, boolean) from public;
revoke all on function public.lb_create_category(text, text, text) from public;
revoke all on function public.lb_update_category(text, uuid, text, text) from public;
revoke all on function public.lb_delete_category(text, uuid) from public;
revoke all on function public.lb_create_or_get_tag(text, text, text) from public;
revoke all on function public.lb_update_tag(text, uuid, text, text) from public;
revoke all on function public.lb_delete_tag(text, uuid) from public;
revoke all on function public.lb_create_log(text, text, uuid, text[], boolean, timestamptz) from public;
revoke all on function public.lb_update_log(text, uuid, text, uuid, boolean, text[], boolean) from public;
revoke all on function public.lb_toggle_pin(text, uuid) from public;
revoke all on function public.lb_delete_log(text, uuid) from public;
revoke all on function public.lb_bulk_logs_action(text, uuid[], text, uuid, text) from public;
revoke all on function public.lb_import_logs(text, jsonb) from public;
revoke all on function public.lb_list_api_tokens(text) from public;
revoke all on function public.lb_create_api_token(text, text) from public;
revoke all on function public.lb_delete_api_token(text, uuid) from public;
revoke all on function public.lb_ingest_webhook(text, text, text, text[], boolean) from public;

grant execute on function public.lb_signup(text, text) to anon, authenticated;
grant execute on function public.lb_login(text, text) to anon, authenticated;
grant execute on function public.lb_logout(text) to anon, authenticated;
grant execute on function public.lb_me(text) to anon, authenticated;
grant execute on function public.lb_change_password(text, text, text) to anon, authenticated;
grant execute on function public.lb_get_workspace(text, integer, integer, text, uuid, text[], text, date, boolean) to anon, authenticated;
grant execute on function public.lb_export_logs(text, text, uuid, text[], text, date, boolean) to anon, authenticated;
grant execute on function public.lb_create_category(text, text, text) to anon, authenticated;
grant execute on function public.lb_update_category(text, uuid, text, text) to anon, authenticated;
grant execute on function public.lb_delete_category(text, uuid) to anon, authenticated;
grant execute on function public.lb_create_or_get_tag(text, text, text) to anon, authenticated;
grant execute on function public.lb_update_tag(text, uuid, text, text) to anon, authenticated;
grant execute on function public.lb_delete_tag(text, uuid) to anon, authenticated;
grant execute on function public.lb_create_log(text, text, uuid, text[], boolean, timestamptz) to anon, authenticated;
grant execute on function public.lb_update_log(text, uuid, text, uuid, boolean, text[], boolean) to anon, authenticated;
grant execute on function public.lb_toggle_pin(text, uuid) to anon, authenticated;
grant execute on function public.lb_delete_log(text, uuid) to anon, authenticated;
grant execute on function public.lb_bulk_logs_action(text, uuid[], text, uuid, text) to anon, authenticated;
grant execute on function public.lb_import_logs(text, jsonb) to anon, authenticated;
grant execute on function public.lb_list_api_tokens(text) to anon, authenticated;
grant execute on function public.lb_create_api_token(text, text) to anon, authenticated;
grant execute on function public.lb_delete_api_token(text, uuid) to anon, authenticated;
grant execute on function public.lb_ingest_webhook(text, text, text, text[], boolean) to anon, authenticated;

commit;
