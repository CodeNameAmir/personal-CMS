-- =============================================================================
-- Logbook — Supabase PostgreSQL Schema & Secure RPCs
-- Run this entire script once in your Supabase Project -> SQL Editor.
-- Works directly with static GitHub Pages hosting using ONLY VITE_SUPABASE_URL
-- and VITE_SUPABASE_PUBLISHABLE_KEY (RLS locks down raw table access).
-- =============================================================================

create extension if not exists pgcrypto;

-- 1. Tables
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

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
  unique (user_id, name)
);

create table if not exists public.tags (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  color text not null default '#64748b',
  created_at timestamptz not null default now(),
  unique (user_id, name)
);

create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  message text not null,
  category_id uuid references public.categories(id) on delete set null,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.log_tags (
  log_id uuid not null references public.logs(id) on delete cascade,
  tag_id uuid not null references public.tags(id) on delete cascade,
  primary key (log_id, tag_id)
);

create index if not exists idx_logs_user_created on public.logs(user_id, pinned desc, created_at desc);
create index if not exists idx_categories_user on public.categories(user_id);
create index if not exists idx_tags_user on public.tags(user_id);
create index if not exists idx_api_tokens_hash on public.api_tokens(token_hash);
create index if not exists idx_sessions_hash on public.sessions(token_hash);

-- Migrate legacy foreign keys if tables previously pointed to auth.users
alter table public.categories drop constraint if exists categories_user_id_fkey;
alter table public.categories add constraint categories_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.tags drop constraint if exists tags_user_id_fkey;
alter table public.tags add constraint tags_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.logs drop constraint if exists logs_user_id_fkey;
alter table public.logs add constraint logs_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.api_tokens drop constraint if exists api_tokens_user_id_fkey;
alter table public.api_tokens add constraint api_tokens_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;

-- 2. Lock down direct table access via Row Level Security
-- All client operations pass through SECURITY DEFINER RPC functions below.
alter table public.users enable row level security;
alter table public.sessions enable row level security;
alter table public.api_tokens enable row level security;
alter table public.categories enable row level security;
alter table public.tags enable row level security;
alter table public.logs enable row level security;
alter table public.log_tags enable row level security;

-- 3. Internal helpers
create or replace function public.lb_hash_token(p_raw text)
returns text
language sql
immutable
set search_path = public, extensions
as $$
  select encode(digest(convert_to(coalesce(p_raw, ''), 'UTF8'), 'sha256'), 'hex');
$$;

create or replace function public.lb_require_session(p_token text)
returns uuid
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_user_id uuid;
begin
  if p_token is null or length(trim(p_token)) = 0 then
    raise exception 'UNAUTHORIZED: Missing session token';
  end if;

  delete from public.sessions where expires_at <= now();

  select user_id into v_user_id
  from public.sessions
  where token_hash = public.lb_hash_token(p_token)
    and expires_at > now()
  limit 1;

  if v_user_id is null then
    raise exception 'UNAUTHORIZED: Session expired or invalid';
  end if;

  return v_user_id;
end;
$$;

create or replace function public.lb_normalize_tag(p_raw text)
returns text
language sql
immutable
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
as $$
declare
  v_palette text[] := array['#64748b', '#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#f97316'];
  v_idx int;
begin
  v_idx := (abs(hashtext(coalesce(p_name, ''))) % array_length(v_palette, 1)) + 1;
  return v_palette[v_idx];
end;
$$;

create or replace function public.lb_hydrate_log(p_log_id uuid)
returns jsonb
language sql
security definer
set search_path = public, extensions
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
      join public.tags t on t.id = lt.tag_id
      where lt.log_id = l.id
    ), '[]'::jsonb),
    'pinned', l.pinned,
    'created_at', l.created_at,
    'updated_at', l.updated_at
  )
  from public.logs l
  left join public.categories c on c.id = l.category_id
  where l.id = p_log_id;
$$;

create or replace function public.lb_find_or_create_category(p_user_id uuid, p_name text)
returns uuid
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_clean text := left(coalesce(nullif(trim(p_name), ''), 'General'), 64);
  v_id uuid;
begin
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
set search_path = public, extensions
as $$
declare
  v_raw text;
  v_clean text;
  v_tag_id uuid;
begin
  delete from public.log_tags where log_id = p_log_id;

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

    insert into public.log_tags (log_id, tag_id)
    values (p_log_id, v_tag_id)
    on conflict do nothing;
  end loop;
end;
$$;

-- 4. Authentication RPCs
create or replace function public.lb_signup(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_username text := trim(coalesce(p_username, ''));
  v_user_id uuid;
  v_raw_token text;
begin
  if length(v_username) < 2 or length(v_username) > 64 then
    raise exception 'Username must be between 2 and 64 characters.';
  end if;
  if length(coalesce(p_password, '')) < 6 then
    raise exception 'Password must be at least 6 characters.';
  end if;

  if exists (select 1 from public.users where lower(username) = lower(v_username)) then
    raise exception 'Username is already registered.';
  end if;

  insert into public.users (username, password_hash)
  values (v_username, crypt(p_password, gen_salt('bf', 10)))
  returning id into v_user_id;

  -- Starter categories
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
set search_path = public, extensions
as $$
declare
  v_username text := trim(coalesce(p_username, ''));
  v_user record;
  v_raw_token text;
begin
  select id, username, password_hash into v_user
  from public.users
  where lower(username) = lower(v_username)
  limit 1;

  if v_user.id is null or v_user.password_hash <> crypt(coalesce(p_password, ''), v_user.password_hash) then
    raise exception 'Invalid username or password.';
  end if;

  delete from public.sessions where expires_at <= now();

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
set search_path = public, extensions
as $$
begin
  delete from public.sessions where token_hash = public.lb_hash_token(p_token);
  return true;
end;
$$;

create or replace function public.lb_change_password(
  p_token text,
  p_current_password text,
  p_new_password text
)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_hash text;
begin
  if length(coalesce(p_new_password, '')) < 6 then
    raise exception 'New password must be at least 6 characters.';
  end if;

  select password_hash into v_hash from public.users where id = v_user_id;
  if v_hash is null or v_hash <> crypt(coalesce(p_current_password, ''), v_hash) then
    raise exception 'Current password is incorrect.';
  end if;

  update public.users
  set password_hash = crypt(p_new_password, gen_salt('bf', 10))
  where id = v_user_id;

  return true;
end;
$$;

-- 5. Workspace Snapshot RPC
create or replace function public.lb_get_workspace(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_categories jsonb;
  v_tags jsonb;
  v_logs jsonb;
begin
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'id', c.id,
      'name', c.name,
      'color', c.color,
      'created_at', c.created_at,
      'log_count', (select count(*)::int from public.logs l where l.category_id = c.id and l.user_id = v_user_id)
    ) order by c.name asc
  ), '[]'::jsonb)
  into v_categories
  from public.categories c
  where c.user_id = v_user_id;

  select coalesce(jsonb_agg(
    jsonb_build_object(
      'id', t.id,
      'name', t.name,
      'color', t.color,
      'created_at', t.created_at,
      'usage_count', (select count(*)::int from public.log_tags lt where lt.tag_id = t.id)
    ) order by t.name asc
  ), '[]'::jsonb)
  into v_tags
  from public.tags t
  where t.user_id = v_user_id;

  select coalesce(jsonb_agg(
    jsonb_build_object(
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
        join public.tags t on t.id = lt.tag_id
        where lt.log_id = l.id
      ), '[]'::jsonb),
      'pinned', l.pinned,
      'created_at', l.created_at,
      'updated_at', l.updated_at
    ) order by l.pinned desc, l.created_at desc
  ), '[]'::jsonb)
  into v_logs
  from public.logs l
  left join public.categories c on c.id = l.category_id
  where l.user_id = v_user_id;

  return jsonb_build_object(
    'categories', v_categories,
    'tags', v_tags,
    'logs', v_logs
  );
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := left(trim(coalesce(p_name, '')), 64);
  v_color text := coalesce(nullif(trim(p_color), ''), '#3b82f6');
  v_row public.categories%rowtype;
begin
  if length(v_name) = 0 then
    raise exception 'Category name is required.';
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := left(trim(coalesce(p_name, '')), 64);
  v_color text := coalesce(nullif(trim(p_color), ''), '#3b82f6');
  v_row public.categories%rowtype;
begin
  if length(v_name) = 0 then
    raise exception 'Category name is required.';
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
begin
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
set search_path = public, extensions
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

  select * into v_row
  from public.tags
  where user_id = v_user_id and name = v_name
  limit 1;

  if v_row.id is null then
    v_color := coalesce(nullif(trim(p_color), ''), public.lb_default_tag_color(v_name));
    insert into public.tags (user_id, name, color)
    values (v_user_id, v_name, v_color)
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
set search_path = public, extensions
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
set search_path = public, extensions
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_msg text := trim(coalesce(p_message, ''));
  v_cat_id uuid := null;
  v_log_id uuid;
  v_ts timestamptz := coalesce(p_created_at, now());
begin
  if length(v_msg) = 0 then
    raise exception 'Log message cannot be empty.';
  end if;

  if p_category_id is not null then
    select id into v_cat_id
    from public.categories
    where id = p_category_id and user_id = v_user_id
    limit 1;
  end if;

  insert into public.logs (user_id, message, category_id, pinned, created_at, updated_at)
  values (v_user_id, v_msg, v_cat_id, coalesce(p_pinned, false), v_ts, v_ts)
  returning id into v_log_id;

  perform public.lb_sync_log_tags(v_user_id, v_log_id, p_tags);

  return public.lb_hydrate_log(v_log_id);
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_existing public.logs%rowtype;
  v_new_cat_id uuid;
begin
  select * into v_existing
  from public.logs
  where id = p_id and user_id = v_user_id
  limit 1;

  if v_existing.id is null then
    raise exception 'Log not found.';
  end if;

  if p_clear_category then
    v_new_cat_id := null;
  elsif p_category_id is not null then
    select id into v_new_cat_id
    from public.categories
    where id = p_category_id and user_id = v_user_id
    limit 1;
  else
    v_new_cat_id := v_existing.category_id;
  end if;

  update public.logs
  set
    message = case when p_message is not null and length(trim(p_message)) > 0 then trim(p_message) else v_existing.message end,
    category_id = v_new_cat_id,
    pinned = coalesce(p_pinned, v_existing.pinned),
    updated_at = now()
  where id = p_id and user_id = v_user_id;

  if p_tags is not null then
    perform public.lb_sync_log_tags(v_user_id, p_id, p_tags);
  end if;

  return public.lb_hydrate_log(p_id);
end;
$$;

create or replace function public.lb_toggle_pin(p_token text, p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
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

  return public.lb_hydrate_log(p_id);
end;
$$;

create or replace function public.lb_delete_log(p_token text, p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_affected int := 0;
  v_clean_tag text;
  v_tag_id uuid;
  v_log_id uuid;
begin
  if p_ids is null or array_length(p_ids, 1) is null then
    return 0;
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
    update public.logs set category_id = p_category_id, updated_at = now()
    where user_id = v_user_id and id = any(p_ids);
    get diagnostics v_affected = row_count;
  elsif p_action = 'add_tag' then
    v_clean_tag := public.lb_normalize_tag(p_tag);
    if length(v_clean_tag) = 0 then
      return 0;
    end if;

    select id into v_tag_id
    from public.tags
    where user_id = v_user_id and name = v_clean_tag
    limit 1;

    if v_tag_id is null then
      insert into public.tags (user_id, name, color)
      values (v_user_id, v_clean_tag, public.lb_default_tag_color(v_clean_tag))
      returning id into v_tag_id;
    end if;

    for v_log_id in select id from public.logs where user_id = v_user_id and id = any(p_ids) loop
      insert into public.log_tags (log_id, tag_id)
      values (v_log_id, v_tag_id)
      on conflict do nothing;
      v_affected := v_affected + 1;
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_item jsonb;
  v_msg text;
  v_cat_name text;
  v_cat_id uuid;
  v_pinned boolean;
  v_created_at timestamptz;
  v_tags text[];
  v_log_id uuid;
  v_imported int := 0;
  v_skipped int := 0;
  v_failed int := 0;
  v_errors text[] := '{}';
begin
  if p_records is null or jsonb_typeof(p_records) <> 'array' then
    raise exception 'Import records must be a JSON array.';
  end if;

  for v_item in select * from jsonb_array_elements(p_records) loop
    v_msg := trim(coalesce(v_item->>'message', ''));
    if length(v_msg) = 0 then
      v_failed := v_failed + 1;
      continue;
    end if;

    if exists (select 1 from public.logs where user_id = v_user_id and message = v_msg) then
      v_skipped := v_skipped + 1;
      continue;
    end if;

    begin
      v_cat_name := coalesce(nullif(trim(v_item->>'category'), ''), 'General');
      v_cat_id := public.lb_find_or_create_category(v_user_id, v_cat_name);
      v_pinned := coalesce((v_item->>'pinned')::boolean, false);
      v_created_at := coalesce(nullif(v_item->>'created_at', '')::timestamptz, now());

      select coalesce(array_agg(value::text), '{}')
      into v_tags
      from jsonb_array_elements_text(coalesce(v_item->'tags', '[]'::jsonb));

      insert into public.logs (user_id, message, category_id, pinned, created_at, updated_at)
      values (v_user_id, v_msg, v_cat_id, v_pinned, v_created_at, v_created_at)
      returning id into v_log_id;

      perform public.lb_sync_log_tags(v_user_id, v_log_id, v_tags);
      v_imported := v_imported + 1;
    exception when others then
      v_failed := v_failed + 1;
      v_errors := array_append(v_errors, sqlerrm);
    end;
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
set search_path = public, extensions
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
set search_path = public, extensions
as $$
declare
  v_user_id uuid := public.lb_require_session(p_token);
  v_name text := left(trim(coalesce(p_name, '')), 64);
  v_raw text;
  v_prefix text;
  v_row public.api_tokens%rowtype;
begin
  if length(v_name) = 0 then
    raise exception 'Token name is required.';
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
set search_path = public, extensions
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
set search_path = public, extensions
as $$
declare
  v_token_id uuid;
  v_user_id uuid;
  v_msg text := trim(coalesce(p_message, ''));
  v_cat_id uuid;
  v_log_id uuid;
begin
  if p_raw_token is null or length(trim(p_raw_token)) = 0 then
    raise exception 'UNAUTHORIZED: Missing API token';
  end if;
  if length(v_msg) = 0 then
    raise exception 'Log message cannot be empty.';
  end if;

  select id, user_id into v_token_id, v_user_id
  from public.api_tokens
  where token_hash = public.lb_hash_token(trim(p_raw_token))
  limit 1;

  if v_user_id is null then
    raise exception 'UNAUTHORIZED: Invalid API token';
  end if;

  update public.api_tokens set last_used_at = now() where id = v_token_id;

  v_cat_id := public.lb_find_or_create_category(v_user_id, coalesce(nullif(trim(p_category), ''), 'Webhook'));

  insert into public.logs (user_id, message, category_id, pinned)
  values (v_user_id, v_msg, v_cat_id, coalesce(p_pinned, false))
  returning id into v_log_id;

  perform public.lb_sync_log_tags(v_user_id, v_log_id, p_tags);

  return jsonb_build_object('log', public.lb_hydrate_log(v_log_id));
end;
$$;

-- 9. Grant execute permissions for Supabase anon/authenticated clients
grant usage on schema public to anon, authenticated;
grant execute on function public.lb_signup(text, text) to anon, authenticated;
grant execute on function public.lb_login(text, text) to anon, authenticated;
grant execute on function public.lb_logout(text) to anon, authenticated;
grant execute on function public.lb_change_password(text, text, text) to anon, authenticated;
grant execute on function public.lb_get_workspace(text) to anon, authenticated;
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
