-- ============================================================================
-- Migration: 0003_relax_password_min_length.sql
-- Purpose: Lower minimum user password length from 12 to 6 characters in
--          public.lb_signup and public.lb_change_password while preserving
--          all security hardening, search_path pinning, and grants.
-- ============================================================================

begin;

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

  if p_password is null or char_length(p_password) < 6 or char_length(p_password) > 128 then
    raise exception 'Password must be between 6 and 128 characters.';
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

  if p_new_password is null or char_length(p_new_password) < 6 or char_length(p_new_password) > 128 then
    raise exception 'New password must be between 6 and 128 characters.';
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

revoke all on function public.lb_signup(text, text) from public;
revoke all on function public.lb_change_password(text, text, text) from public;
grant execute on function public.lb_signup(text, text) to anon, authenticated;
grant execute on function public.lb_change_password(text, text, text) to anon, authenticated;

commit;
