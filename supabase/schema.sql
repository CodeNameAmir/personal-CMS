-- =============================================================================
-- Logbook — Hardened Supabase PostgreSQL Schema & Secure RPCs
-- For existing databases, run supabase/migrations/0001_security_hardening.sql
-- followed by supabase/migrations/0002_deep_security_hardening.sql instead of
-- resetting tables. For fresh installations, run this entire script once in
-- your Supabase Project -> SQL Editor.
-- =============================================================================

create extension if not exists pgcrypto;

-- Lock down schema creation & future function execution privileges
revoke create on schema public from public, anon, authenticated;
grant usage on schema public to anon, authenticated;

alter default privileges in schema public
  revoke execute on functions from public, anon, authenticated;

-- 1. Tables
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create unique index if not exists idx_users_username_lower
  on public.users (lower(username));

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  token_hash text unique not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.api_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  token_prefix text not null,
  token_hash text unique not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  color text not null default '#3b82f6',
  created_at timestamptz not null default now(),
  unique (user_id, name),
  unique (user_id, id)
);

create table if not exists public.tags (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  color text not null default '#64748b',
  created_at timestamptz not null default now(),
  unique (user_id, name),
  unique (user_id, id)
);

create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  message text not null,
  category_id uuid references public.categories(id) on delete set null,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, id),
  constraint logs_user_category_fkey
    foreign key (user_id, category_id)
    references public.categories(user_id, id)
);

do $$
begin
  if current_setting('server_version_num')::int >= 150000 then
    alter table public.logs drop constraint if exists logs_user_category_fkey;
    alter table public.logs
      add constraint logs_user_category_fkey
      foreign key (user_id, category_id)
      references public.categories(user_id, id)
      on delete set null (category_id);
    alter table public.logs drop constraint if exists logs_category_id_fkey;
  end if;
end $$;

create table if not exists public.log_tags (
  user_id uuid not null references public.users(id) on delete cascade,
  log_id uuid not null,
  tag_id uuid not null,
  primary key (log_id, tag_id),
  constraint log_tags_user_log_fkey
    foreign key (user_id, log_id)
    references public.logs(user_id, id)
    on delete cascade,
  constraint log_tags_user_tag_fkey
    foreign key (user_id, tag_id)
    references public.tags(user_id, id)
    on delete cascade
);

create table if not exists public.lb_rate_limits (
  scope text not null,
  key_hash text not null,
  window_start timestamptz not null default now(),
  attempts integer not null default 1,
  primary key (scope, key_hash)
);

-- Performance & cleanup indexes
create index if not exists idx_logs_user_created on public.logs(user_id, pinned desc, created_at desc);
create index if not exists idx_logs_user_category on public.logs(user_id, category_id);
create index if not exists idx_categories_user on public.categories(user_id);
create index if not exists idx_tags_user on public.tags(user_id);
create index if not exists idx_log_tags_tag on public.log_tags(tag_id);
create index if not exists idx_api_tokens_hash on public.api_tokens(token_hash);
create index if not exists idx_api_tokens_user_id on public.api_tokens(user_id);
create index if not exists idx_sessions_hash on public.sessions(token_hash);
create index if not exists idx_sessions_expires_at on public.sessions(expires_at);
create index if not exists idx_sessions_user_id on public.sessions(user_id);
create index if not exists idx_rate_limits_window on public.lb_rate_limits(window_start);

-- 2. Lock down direct table access via Row Level Security & role revocations
alter table public.users enable row level security;
alter table public.sessions enable row level security;
alter table public.api_tokens enable row level security;
alter table public.categories enable row level security;
alter table public.tags enable row level security;
alter table public.logs enable row level security;
alter table public.log_tags enable row level security;
alter table public.lb_rate_limits enable row level security;

revoke all on table public.users from public, anon, authenticated;
revoke all on table public.sessions from public, anon, authenticated;
revoke all on table public.api_tokens from public, anon, authenticated;
revoke all on table public.categories from public, anon, authenticated;
revoke all on table public.tags from public, anon, authenticated;
revoke all on table public.logs from public, anon, authenticated;
revoke all on table public.log_tags from public, anon, authenticated;
revoke all on table public.lb_rate_limits from public, anon, authenticated;

do $$
declare
  v_tbl text;
begin
  foreach v_tbl in array array['users', 'sessions', 'api_tokens', 'categories', 'tags', 'logs', 'log_tags', 'lb_rate_limits'] loop
    execute format('drop policy if exists deny_direct_access on public.%I', v_tbl);
    execute format('create policy deny_direct_access on public.%I for all to anon, authenticated using (false) with check (false)', v_tbl);
  end loop;
end $$;

-- 3. Internal helpers (NEVER exposed to PUBLIC, anon, or authenticated)
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

-- 4. Authentication RPCs
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

create or replace function public.lb_logout(p_token text)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_trimmed text := trim(coalesce(p_token, ''));
begin
  if length(v_trimmed) = 0 or length(v_trimmed) > 256 then
    return true;
  end if;
  delete from public.sessions where token_hash = public.lb_hash_token(v_trimmed);
  return true;
end;
$$;

create or replace function public.lb_me(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_username text;
begin
  select username into v_username
  from public.users
  where id = v_user_id
  limit 1;

  if v_username is null then
    raise exception 'UNAUTHORIZED: Account not found';
  end if;

  update public.sessions
  set expires_at = now() + interval '7 days'
  where token_hash = public.lb_hash_token(trim(p_token))
    and expires_at < now() + interval '4 days';

  return jsonb_build_object('id', v_user_id, 'username', v_username);
end;
$$;

create or replace function public.lb_change_password(
  p_token text,
  p_current_password text,
  p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_hash text;
  v_new_token text;
begin
  perform public.lb_check_rate_limit('change_pw', v_user_id::text, 8, 900);

  if p_new_password is null or char_length(p_new_password) < 12 or char_length(p_new_password) > 128 then
    raise exception 'New password must be between 12 and 128 characters.';
  end if;

  if p_current_password is null or char_length(p_current_password) > 128 then
    raise exception 'Current password is incorrect.';
  end if;

  select password_hash into v_hash from public.users where id = v_user_id;
  if v_hash is null or not public.lb_verify_password(p_current_password, v_hash) then
    raise exception 'Current password is incorrect.';
  end if;

  update public.users
  set password_hash = public.lb_hash_password(p_new_password)
  where id = v_user_id;

  delete from public.sessions where user_id = v_user_id;

  v_new_token := 'lbs_' || encode(gen_random_bytes(32), 'hex');
  insert into public.sessions (user_id, token_hash, expires_at)
  values (v_user_id, public.lb_hash_token(v_new_token), now() + interval '7 days');

  return jsonb_build_object('ok', true, 'token', v_new_token);
end;
$$;

-- 5. Paginated Workspace Snapshot & Export RPCs
create or replace function public.lb_get_workspace(
  p_token text,
  p_page integer default 1,
  p_page_size integer default 20,
  p_q text default '',
  p_category_id uuid default null,
  p_tags text[] default '{}',
  p_tag_match_mode text default 'any',
  p_date_from date default null,
  p_pinned_only boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_page int := greatest(1, coalesce(p_page, 1));
  v_page_size int := least(100, greatest(1, coalesce(p_page_size, 20)));
  v_offset int := (greatest(1, coalesce(p_page, 1)) - 1) * least(100, greatest(1, coalesce(p_page_size, 20)));
  v_q text := trim(coalesce(p_q, ''));
  v_mode text := case when lower(coalesce(p_tag_match_mode, 'any')) = 'all' then 'all' else 'any' end;
  v_selected_tags text[];
  v_total_count int := 0;
  v_categories jsonb;
  v_tags jsonb;
  v_logs jsonb;
  v_stats jsonb;
begin
  perform public.lb_check_rate_limit('workspace', v_user_id::text, 240, 60);

  if char_length(v_q) > 200 then
    raise exception 'Search query is too long (maximum 200 characters).';
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'Too many filter tags (maximum 25).';
  end if;

  select coalesce(array_agg(distinct public.lb_normalize_tag(x)), '{}')
  into v_selected_tags
  from unnest(coalesce(p_tags, '{}')) as x
  where length(public.lb_normalize_tag(x)) > 0;

  with cat_counts as (
    select category_id, count(*)::int as cnt
    from public.logs
    where user_id = v_user_id and category_id is not null
    group by category_id
  )
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'id', c.id,
      'name', c.name,
      'color', c.color,
      'created_at', c.created_at,
      'log_count', coalesce(cc.cnt, 0)
    ) order by c.name asc
  ), '[]'::jsonb)
  into v_categories
  from public.categories c
  left join cat_counts cc on cc.category_id = c.id
  where c.user_id = v_user_id;

  with tag_counts as (
    select lt.tag_id, count(*)::int as cnt
    from public.log_tags lt
    where lt.user_id = v_user_id
    group by lt.tag_id
  )
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'id', t.id,
      'name', t.name,
      'color', t.color,
      'created_at', t.created_at,
      'usage_count', coalesce(tc.cnt, 0)
    ) order by t.name asc
  ), '[]'::jsonb)
  into v_tags
  from public.tags t
  left join tag_counts tc on tc.tag_id = t.id
  where t.user_id = v_user_id;

  with filtered_logs as (
    select l.id, l.message, l.category_id, l.pinned, l.created_at, l.updated_at,
           c.name as cat_name, c.color as cat_color
    from public.logs l
    left join public.categories c on c.id = l.category_id and c.user_id = l.user_id
    where l.user_id = v_user_id
      and (not coalesce(p_pinned_only, false) or l.pinned = true)
      and (p_category_id is null or l.category_id = p_category_id)
      and (p_date_from is null or l.created_at >= p_date_from::timestamptz)
      and (
        v_q = ''
        or l.message ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        or coalesce(c.name, '') ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        or exists (
          select 1
          from public.log_tags ltq
          join public.tags tq on tq.id = ltq.tag_id and tq.user_id = v_user_id
          where ltq.log_id = l.id
            and ltq.user_id = v_user_id
            and tq.name ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        )
      )
      and (
        coalesce(array_length(v_selected_tags, 1), 0) = 0
        or (
          v_mode = 'any' and exists (
            select 1
            from public.log_tags lta
            join public.tags ta on ta.id = lta.tag_id and ta.user_id = v_user_id
            where lta.log_id = l.id
              and lta.user_id = v_user_id
              and ta.name = any(v_selected_tags)
          )
        )
        or (
          v_mode = 'all' and (
            select count(distinct ta.name)
            from public.log_tags lta
            join public.tags ta on ta.id = lta.tag_id and ta.user_id = v_user_id
            where lta.log_id = l.id
              and lta.user_id = v_user_id
              and ta.name = any(v_selected_tags)
          ) = array_length(v_selected_tags, 1)
        )
      )
  ),
  paged as (
    select *
    from filtered_logs
    order by pinned desc, created_at desc, id desc
    limit v_page_size
    offset v_offset
  ),
  paged_tags as (
    select lt.log_id,
      jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color) order by t.name asc) as tags_json
    from public.log_tags lt
    join paged p on p.id = lt.log_id
    join public.tags t on t.id = lt.tag_id and t.user_id = v_user_id
    where lt.user_id = v_user_id
    group by lt.log_id
  )
  select
    (select count(*)::int from filtered_logs),
    coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id', p.id,
          'message', p.message,
          'category_id', p.category_id,
          'category_name', coalesce(p.cat_name, 'Uncategorized'),
          'category_color', coalesce(p.cat_color, '#64748b'),
          'tags', coalesce(pt.tags_json, '[]'::jsonb),
          'pinned', p.pinned,
          'created_at', p.created_at,
          'updated_at', p.updated_at
        ) order by p.pinned desc, p.created_at desc, p.id desc
      )
      from paged p
      left join paged_tags pt on pt.log_id = p.id
    ), '[]'::jsonb)
  into v_total_count, v_logs;

  with totals as (
    select
      count(*)::int as total_logs,
      count(*) filter (where pinned)::int as pinned_logs
    from public.logs
    where user_id = v_user_id
  ),
  cat_stats as (
    select
      coalesce(l.category_id::text, '__uncategorized__') as category_id,
      coalesce(c.name, 'Uncategorized') as category_name,
      coalesce(c.color, '#64748b') as category_color,
      count(*)::int as cnt
    from public.logs l
    left join public.categories c on c.id = l.category_id and c.user_id = l.user_id
    where l.user_id = v_user_id
    group by coalesce(l.category_id::text, '__uncategorized__'), coalesce(c.name, 'Uncategorized'), coalesce(c.color, '#64748b')
    order by cnt desc
  ),
  tag_stats as (
    select
      t.id as tag_id,
      t.name as tag_name,
      t.color as tag_color,
      count(*)::int as cnt
    from public.log_tags lt
    join public.tags t on t.id = lt.tag_id and t.user_id = v_user_id
    where lt.user_id = v_user_id
    group by t.id, t.name, t.color
    order by cnt desc
  ),
  days as (
    select generate_series(
      (current_date - interval '29 days')::date,
      current_date,
      interval '1 day'
    )::date as d
  ),
  day_counts as (
    select (created_at at time zone 'UTC')::date as d, count(*)::int as cnt
    from public.logs
    where user_id = v_user_id
      and created_at >= (current_date - interval '29 days')::timestamptz
    group by 1
  ),
  day_stats as (
    select to_char(days.d, 'YYYY-MM-DD') as day, coalesce(dc.cnt, 0)::int as cnt
    from days
    left join day_counts dc on dc.d = days.d
    order by days.d asc
  )
  select jsonb_build_object(
    'total_logs', (select total_logs from totals),
    'pinned_logs', (select pinned_logs from totals),
    'total_categories', (select count(*)::int from public.categories where user_id = v_user_id),
    'total_tags', (select count(*)::int from tag_stats),
    'by_category', coalesce((select jsonb_agg(jsonb_build_object('category_id', category_id, 'category_name', category_name, 'category_color', category_color, 'count', cnt)) from cat_stats), '[]'::jsonb),
    'by_tag', coalesce((select jsonb_agg(jsonb_build_object('tag_id', tag_id, 'tag_name', tag_name, 'tag_color', tag_color, 'count', cnt)) from tag_stats), '[]'::jsonb),
    'by_day', coalesce((select jsonb_agg(jsonb_build_object('day', day, 'count', cnt)) from day_stats), '[]'::jsonb)
  )
  into v_stats;

  return jsonb_build_object(
    'categories', v_categories,
    'tags', v_tags,
    'logs', v_logs,
    'total_count', v_total_count,
    'page', v_page,
    'page_size', v_page_size,
    'stats', v_stats
  );
end;
$$;

create or replace function public.lb_export_logs(
  p_token text,
  p_q text default '',
  p_category_id uuid default null,
  p_tags text[] default '{}',
  p_tag_match_mode text default 'any',
  p_date_from date default null,
  p_pinned_only boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_q text := trim(coalesce(p_q, ''));
  v_mode text := case when lower(coalesce(p_tag_match_mode, 'any')) = 'all' then 'all' else 'any' end;
  v_selected_tags text[];
  v_logs jsonb;
begin
  perform public.lb_check_rate_limit('export', v_user_id::text, 20, 300);

  if char_length(v_q) > 200 then
    raise exception 'Search query is too long (maximum 200 characters).';
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'Too many filter tags (maximum 25).';
  end if;

  select coalesce(array_agg(distinct public.lb_normalize_tag(x)), '{}')
  into v_selected_tags
  from unnest(coalesce(p_tags, '{}')) as x
  where length(public.lb_normalize_tag(x)) > 0;

  with matched as (
    select l.id, l.message, l.category_id, l.pinned, l.created_at, l.updated_at,
           c.name as cat_name, c.color as cat_color
    from public.logs l
    left join public.categories c on c.id = l.category_id and c.user_id = l.user_id
    where l.user_id = v_user_id
      and (not coalesce(p_pinned_only, false) or l.pinned = true)
      and (p_category_id is null or l.category_id = p_category_id)
      and (p_date_from is null or l.created_at >= p_date_from::timestamptz)
      and (
        v_q = ''
        or l.message ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        or coalesce(c.name, '') ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        or exists (
          select 1
          from public.log_tags ltq
          join public.tags tq on tq.id = ltq.tag_id and tq.user_id = v_user_id
          where ltq.log_id = l.id
            and ltq.user_id = v_user_id
            and tq.name ilike '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
        )
      )
      and (
        coalesce(array_length(v_selected_tags, 1), 0) = 0
        or (
          v_mode = 'any' and exists (
            select 1
            from public.log_tags lta
            join public.tags ta on ta.id = lta.tag_id and ta.user_id = v_user_id
            where lta.log_id = l.id
              and lta.user_id = v_user_id
              and ta.name = any(v_selected_tags)
          )
        )
        or (
          v_mode = 'all' and (
            select count(distinct ta.name)
            from public.log_tags lta
            join public.tags ta on ta.id = lta.tag_id and ta.user_id = v_user_id
            where lta.log_id = l.id
              and lta.user_id = v_user_id
              and ta.name = any(v_selected_tags)
          ) = array_length(v_selected_tags, 1)
        )
      )
    order by l.pinned desc, l.created_at desc, l.id desc
    limit 5000
  ),
  matched_tags as (
    select lt.log_id,
      jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color) order by t.name asc) as tags_json
    from public.log_tags lt
    join matched m on m.id = lt.log_id
    join public.tags t on t.id = lt.tag_id and t.user_id = v_user_id
    where lt.user_id = v_user_id
    group by lt.log_id
  )
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'id', m.id,
      'message', m.message,
      'category_id', m.category_id,
      'category_name', coalesce(m.cat_name, 'Uncategorized'),
      'category_color', coalesce(m.cat_color, '#64748b'),
      'tags', coalesce(mt.tags_json, '[]'::jsonb),
      'pinned', m.pinned,
      'created_at', m.created_at,
      'updated_at', m.updated_at
    ) order by m.pinned desc, m.created_at desc, m.id desc
  ), '[]'::jsonb)
  into v_logs
  from matched m
  left join matched_tags mt on mt.log_id = m.id;

  return v_logs;
end;
$$;

-- 6. Categories & Tags RPCs
create or replace function public.lb_create_category(
  p_token text,
  p_name text,
  p_color text default '#3b82f6'
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := trim(coalesce(p_name, ''));
  v_color text := coalesce(nullif(trim(p_color), ''), '#3b82f6');
  v_row public.categories%rowtype;
begin
  if char_length(v_name) = 0 or char_length(v_name) > 64 then
    raise exception 'Category name must be between 1 and 64 characters.';
  end if;
  if not public.lb_is_valid_hex_color(v_color) then
    raise exception 'Category color must be a valid #RRGGBB hex code.';
  end if;

  if exists (select 1 from public.categories where user_id = v_user_id and lower(name) = lower(v_name)) then
    raise exception 'Category already exists.';
  end if;

  insert into public.categories (user_id, name, color)
  values (v_user_id, v_name, v_color)
  returning * into v_row;

  return jsonb_build_object(
    'id', v_row.id,
    'name', v_row.name,
    'color', v_row.color,
    'created_at', v_row.created_at,
    'log_count', 0
  );
end;
$$;

create or replace function public.lb_update_category(
  p_token text,
  p_id uuid,
  p_name text,
  p_color text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := trim(coalesce(p_name, ''));
  v_color text := coalesce(nullif(trim(p_color), ''), '#3b82f6');
  v_row public.categories%rowtype;
begin
  if char_length(v_name) = 0 or char_length(v_name) > 64 then
    raise exception 'Category name must be between 1 and 64 characters.';
  end if;
  if not public.lb_is_valid_hex_color(v_color) then
    raise exception 'Category color must be a valid #RRGGBB hex code.';
  end if;

  if exists (
    select 1 from public.categories
    where user_id = v_user_id and lower(name) = lower(v_name) and id <> p_id
  ) then
    raise exception 'Category already exists.';
  end if;

  update public.categories
  set name = v_name, color = v_color
  where id = p_id and user_id = v_user_id
  returning * into v_row;

  if v_row.id is null then
    raise exception 'Category not found.';
  end if;

  return jsonb_build_object(
    'id', v_row.id,
    'name', v_row.name,
    'color', v_row.color,
    'created_at', v_row.created_at
  );
end;
$$;

create or replace function public.lb_delete_category(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
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

create or replace function public.lb_update_tag(
  p_token text,
  p_id uuid,
  p_name text,
  p_color text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := public.lb_normalize_tag(p_name);
  v_color text := coalesce(nullif(trim(p_color), ''), '#64748b');
  v_row public.tags%rowtype;
begin
  if length(v_name) = 0 then
    raise exception 'Tag name is required.';
  end if;
  if not public.lb_is_valid_hex_color(v_color) then
    raise exception 'Tag color must be a valid #RRGGBB hex code.';
  end if;

  if exists (
    select 1 from public.tags
    where user_id = v_user_id and name = v_name and id <> p_id
  ) then
    raise exception 'Tag already exists.';
  end if;

  update public.tags
  set name = v_name, color = v_color
  where id = p_id and user_id = v_user_id
  returning * into v_row;

  if v_row.id is null then
    raise exception 'Tag not found.';
  end if;

  return jsonb_build_object(
    'id', v_row.id,
    'name', v_row.name,
    'color', v_row.color,
    'created_at', v_row.created_at
  );
end;
$$;

create or replace function public.lb_delete_tag(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  delete from public.tags where id = p_id and user_id = v_user_id;
  return found;
end;
$$;

-- 7. Logs CRUD, Bulk & Import RPCs
create or replace function public.lb_create_log(
  p_token text,
  p_message text,
  p_category_id uuid default null,
  p_tags text[] default '{}',
  p_pinned boolean default false,
  p_created_at timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_msg text := trim(coalesce(p_message, ''));
  v_cat_id uuid := null;
  v_log_id uuid;
  v_ts timestamptz := coalesce(p_created_at, now());
begin
  if char_length(v_msg) = 0 or char_length(v_msg) > 10000 then
    raise exception 'Log message must be between 1 and 10,000 characters.';
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'A log cannot have more than 25 tags.';
  end if;

  if p_category_id is not null then
    select id into v_cat_id
    from public.categories
    where id = p_category_id and user_id = v_user_id
    limit 1;

    if v_cat_id is null then
      raise exception 'Category not found or access denied.';
    end if;
  end if;

  insert into public.logs (user_id, message, category_id, pinned, created_at, updated_at)
  values (v_user_id, v_msg, v_cat_id, coalesce(p_pinned, false), v_ts, v_ts)
  returning id into v_log_id;

  perform public.lb_sync_log_tags(v_user_id, v_log_id, p_tags);

  return public.lb_hydrate_log(v_user_id, v_log_id);
end;
$$;

create or replace function public.lb_update_log(
  p_token text,
  p_id uuid,
  p_message text default null,
  p_category_id uuid default null,
  p_clear_category boolean default false,
  p_tags text[] default null,
  p_pinned boolean default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_existing public.logs%rowtype;
  v_new_cat_id uuid;
  v_new_msg text;
begin
  select * into v_existing
  from public.logs
  where id = p_id and user_id = v_user_id
  limit 1;

  if v_existing.id is null then
    raise exception 'Log not found.';
  end if;

  if p_message is not null then
    v_new_msg := trim(p_message);
    if char_length(v_new_msg) = 0 or char_length(v_new_msg) > 10000 then
      raise exception 'Log message must be between 1 and 10,000 characters.';
    end if;
  else
    v_new_msg := v_existing.message;
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'A log cannot have more than 25 tags.';
  end if;

  if p_clear_category then
    v_new_cat_id := null;
  elsif p_category_id is not null then
    select id into v_new_cat_id
    from public.categories
    where id = p_category_id and user_id = v_user_id
    limit 1;

    if v_new_cat_id is null then
      raise exception 'Category not found or access denied.';
    end if;
  else
    v_new_cat_id := v_existing.category_id;
  end if;

  update public.logs
  set
    message = v_new_msg,
    category_id = v_new_cat_id,
    pinned = coalesce(p_pinned, v_existing.pinned),
    updated_at = now()
  where id = p_id and user_id = v_user_id;

  if p_tags is not null then
    perform public.lb_sync_log_tags(v_user_id, p_id, p_tags);
  end if;

  return public.lb_hydrate_log(v_user_id, p_id);
end;
$$;

create or replace function public.lb_toggle_pin(p_token text, p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  update public.logs
  set pinned = not pinned, updated_at = now()
  where id = p_id and user_id = v_user_id;

  if not found then
    raise exception 'Log not found.';
  end if;

  return public.lb_hydrate_log(v_user_id, p_id);
end;
$$;

create or replace function public.lb_delete_log(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  delete from public.logs where id = p_id and user_id = v_user_id;
  return found;
end;
$$;

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

-- 8. API Tokens & Webhook Ingestion RPCs
create or replace function public.lb_list_api_tokens(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  return coalesce((
    select jsonb_agg(
      jsonb_build_object(
        'id', id,
        'name', name,
        'token_prefix', token_prefix,
        'last_used_at', last_used_at,
        'created_at', created_at
      ) order by created_at desc
    )
    from public.api_tokens
    where user_id = v_user_id
  ), '[]'::jsonb);
end;
$$;

create or replace function public.lb_create_api_token(p_token text, p_name text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := trim(coalesce(p_name, ''));
  v_raw text;
  v_prefix text;
  v_row public.api_tokens%rowtype;
begin
  perform public.lb_check_rate_limit('create_token', v_user_id::text, 15, 900);

  if char_length(v_name) = 0 or char_length(v_name) > 64 then
    raise exception 'Token name must be between 1 and 64 characters.';
  end if;

  if (select count(*) from public.api_tokens where user_id = v_user_id) >= 25 then
    raise exception 'Maximum of 25 active API tokens reached.';
  end if;

  v_raw := 'lbk_' || encode(gen_random_bytes(24), 'hex');
  v_prefix := left(v_raw, 12);

  insert into public.api_tokens (user_id, name, token_prefix, token_hash)
  values (v_user_id, v_name, v_prefix, public.lb_hash_token(v_raw))
  returning * into v_row;

  return jsonb_build_object(
    'id', v_row.id,
    'name', v_row.name,
    'token_prefix', v_row.token_prefix,
    'last_used_at', v_row.last_used_at,
    'created_at', v_row.created_at,
    'raw_token', v_raw
  );
end;
$$;

create or replace function public.lb_delete_api_token(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
  delete from public.api_tokens where id = p_id and user_id = v_user_id;
  return found;
end;
$$;

create or replace function public.lb_ingest_webhook(
  p_raw_token text,
  p_message text,
  p_category text default 'Webhook',
  p_tags text[] default '{}',
  p_pinned boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_raw_token text := trim(coalesce(p_raw_token, ''));
  v_token_hash text;
  v_token_id uuid;
  v_user_id uuid;
  v_msg text := trim(coalesce(p_message, ''));
  v_cat_name text := left(coalesce(nullif(trim(p_category), ''), 'Webhook'), 64);
  v_cat_id uuid;
  v_log_id uuid;
begin
  if length(v_raw_token) < 16 or length(v_raw_token) > 128 or left(v_raw_token, 4) <> 'lbk_' then
    raise exception 'UNAUTHORIZED: Missing or invalid API token';
  end if;

  v_token_hash := public.lb_hash_token(v_raw_token);
  perform public.lb_check_rate_limit('webhook', v_token_hash, 120, 60);

  if char_length(v_msg) = 0 or char_length(v_msg) > 10000 then
    raise exception 'Log message must be between 1 and 10,000 characters.';
  end if;

  if p_tags is not null and coalesce(array_length(p_tags, 1), 0) > 25 then
    raise exception 'A log cannot have more than 25 tags.';
  end if;

  select id, user_id into v_token_id, v_user_id
  from public.api_tokens
  where token_hash = v_token_hash
  limit 1;

  if v_user_id is null then
    raise exception 'UNAUTHORIZED: Invalid API token';
  end if;

  update public.api_tokens set last_used_at = now() where id = v_token_id;

  v_cat_id := public.lb_find_or_create_category(v_user_id, v_cat_name);

  insert into public.logs (user_id, message, category_id, pinned)
  values (v_user_id, v_msg, v_cat_id, coalesce(p_pinned, false))
  returning id into v_log_id;

  perform public.lb_sync_log_tags(v_user_id, v_log_id, p_tags);

  return jsonb_build_object('log', public.lb_hydrate_log(v_user_id, v_log_id));
end;
$$;

-- 9. Strict Function Execution Privileges (Exact Signatures)
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

grant usage on schema public to anon, authenticated;
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
