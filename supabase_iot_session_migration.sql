-- IOT v1.36 — Migrasi sesi token dan profil akun
-- Jalankan SEKALI di Supabase Dashboard > SQL Editor setelah supabase_iot_setup.sql.
-- Aman untuk data lama: tabel transaksi (iot_kv) tidak dihapus atau dipindahkan.

create extension if not exists pgcrypto with schema extensions;

-- Basis data lama mungkin belum pernah dibuat. Blok ini aman pada proyek baru
-- maupun proyek yang sudah memiliki tabel dari supabase_iot_setup.sql.
create table if not exists public.iot_users (
  username text primary key,
  password_hash text not null,
  created_at timestamptz not null default now(),
  constraint iot_users_username_format check (username ~ '^[a-z0-9_]{3,32}$')
);

create table if not exists public.iot_kv (
  username text not null references public.iot_users(username) on update cascade on delete cascade,
  key text not null,
  value jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (username, key),
  constraint iot_kv_key_format check (key ~ '^[A-Za-z0-9_-]{1,64}$')
);

alter table public.iot_users enable row level security;
alter table public.iot_kv enable row level security;
revoke all on table public.iot_users, public.iot_kv from anon, authenticated;

-- Versi lama memakai kunci seperti "ledger-entries" dan "currencyRates".
-- Longgarkan aturan lama agar semua data tersebut tetap dapat dibaca.
alter table public.iot_kv drop constraint if exists iot_kv_key_format;
alter table public.iot_kv add constraint iot_kv_key_format check (key ~ '^[A-Za-z0-9_-]{1,64}$');

-- Username perlu boleh diganti tanpa memutus data yang tersimpan.
alter table public.iot_kv drop constraint if exists iot_kv_username_fkey;
alter table public.iot_kv
  add constraint iot_kv_username_fkey
  foreign key (username) references public.iot_users(username)
  on update cascade on delete cascade;

create table if not exists public.iot_profiles (
  username text primary key references public.iot_users(username) on update cascade on delete cascade,
  display_name text not null default '',
  email text not null default '',
  phone text not null default '',
  city text not null default '',
  updated_at timestamptz not null default now()
);
alter table public.iot_profiles add column if not exists avatar_data text not null default '';

insert into public.iot_profiles(username, display_name)
select username, username from public.iot_users
on conflict (username) do nothing;

create table if not exists public.iot_sessions (
  token_hash text primary key,
  username text not null references public.iot_users(username) on update cascade on delete cascade,
  expires_at timestamptz not null,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index if not exists iot_sessions_username_idx on public.iot_sessions(username);
create index if not exists iot_sessions_expires_idx on public.iot_sessions(expires_at);

alter table public.iot_profiles enable row level security;
alter table public.iot_sessions enable row level security;
revoke all on table public.iot_profiles, public.iot_sessions from anon, authenticated;

create or replace function public.iot_session_user(p_session_token text)
returns text
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_username text;
  v_token_hash text;
begin
  if p_session_token is null or length(p_session_token) <> 64 or p_session_token !~ '^[a-f0-9]+$' then
    return null;
  end if;
  v_token_hash := encode(extensions.digest(p_session_token, 'sha256'), 'hex');
  select username into v_username
  from public.iot_sessions
  where token_hash = v_token_hash and expires_at > now();
  if v_username is null then
    delete from public.iot_sessions where token_hash = v_token_hash;
    return null;
  end if;
  update public.iot_sessions
  set last_seen_at = now(), expires_at = now() + interval '5 minutes'
  where token_hash = v_token_hash;
  return v_username;
end;
$$;

create or replace function public.login_with_session(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_hash text;
  v_status text;
  v_token text;
  v_expiry timestamptz;
begin
  if p_username is null or p_username !~ '^[a-z0-9_]{3,32}$' or p_password is null or length(p_password) < 4 or length(p_password) > 128 then
    return jsonb_build_object('status', 'invalid');
  end if;
  select password_hash into v_hash from public.iot_users where username = p_username;
  if v_hash is null then
    insert into public.iot_users(username, password_hash)
    values (p_username, extensions.crypt(p_password, extensions.gen_salt('bf', 12)));
    insert into public.iot_profiles(username, display_name) values (p_username, p_username);
    v_status := 'created';
  elsif extensions.crypt(p_password, v_hash) <> v_hash then
    return jsonb_build_object('status', 'wrong_password');
  else
    v_status := 'ok';
  end if;

  delete from public.iot_sessions where expires_at <= now();
  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  v_expiry := now() + interval '5 minutes';
  insert into public.iot_sessions(token_hash, username, expires_at)
  values (encode(extensions.digest(v_token, 'sha256'), 'hex'), p_username, v_expiry);
  return jsonb_build_object('status', v_status, 'username', p_username, 'token', v_token, 'expires_at', v_expiry);
end;
$$;

create or replace function public.session_kv_get(p_session_token text, p_key text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_value jsonb;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  if p_key is null or p_key !~ '^[A-Za-z0-9_-]{1,64}$' then raise exception 'invalid key' using errcode = '22023'; end if;
  select value into v_value from public.iot_kv where username = v_username and key = p_key;
  return v_value;
end;
$$;

create or replace function public.session_kv_set(p_session_token text, p_key text, p_value jsonb)
returns boolean
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  if p_key is null or p_key !~ '^[A-Za-z0-9_-]{1,64}$' then raise exception 'invalid key' using errcode = '22023'; end if;
  insert into public.iot_kv(username, key, value, updated_at) values (v_username, p_key, p_value, now())
  on conflict (username, key) do update set value = excluded.value, updated_at = excluded.updated_at;
  return true;
end;
$$;

create or replace function public.profile_get(p_session_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_profile public.iot_profiles%rowtype;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  select * into v_profile from public.iot_profiles where username = v_username;
  return jsonb_build_object('username', v_username, 'display_name', coalesce(v_profile.display_name, ''), 'email', coalesce(v_profile.email, ''), 'phone', coalesce(v_profile.phone, ''), 'city', coalesce(v_profile.city, ''), 'avatar_data', coalesce(v_profile.avatar_data, ''));
end;
$$;

create or replace function public.profile_update(p_session_token text, p_display_name text, p_email text, p_phone text, p_city text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  insert into public.iot_profiles(username, display_name, email, phone, city, updated_at)
  values (v_username, left(trim(coalesce(p_display_name, '')), 60), left(trim(coalesce(p_email, '')), 120), left(trim(coalesce(p_phone, '')), 32), left(trim(coalesce(p_city, '')), 60), now())
  on conflict (username) do update set display_name = excluded.display_name, email = excluded.email, phone = excluded.phone, city = excluded.city, updated_at = now();
  return public.profile_get(p_session_token);
end;
$$;

create or replace function public.profile_update(p_session_token text, p_display_name text, p_email text, p_phone text, p_city text, p_avatar_data text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_avatar text;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  v_avatar := coalesce(p_avatar_data, '');
  if length(v_avatar) > 160000 or (v_avatar <> '' and v_avatar !~ '^data:image/(jpeg|png|webp);base64,') then
    raise exception 'invalid avatar' using errcode = '22023';
  end if;
  insert into public.iot_profiles(username, display_name, email, phone, city, avatar_data, updated_at)
  values (v_username, left(trim(coalesce(p_display_name, '')), 60), left(trim(coalesce(p_email, '')), 120), left(trim(coalesce(p_phone, '')), 32), left(trim(coalesce(p_city, '')), 60), v_avatar, now())
  on conflict (username) do update set display_name = excluded.display_name, email = excluded.email, phone = excluded.phone, city = excluded.city, avatar_data = excluded.avatar_data, updated_at = now();
  return public.profile_get(p_session_token);
end;
$$;

create or replace function public.profile_change_username(p_session_token text, p_current_password text, p_new_username text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_hash text;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then return jsonb_build_object('status', 'session_expired'); end if;
  if p_new_username is null or p_new_username !~ '^[a-z0-9_]{3,32}$' then return jsonb_build_object('status', 'invalid_username'); end if;
  select password_hash into v_hash from public.iot_users where username = v_username;
  if p_current_password is null or extensions.crypt(p_current_password, v_hash) <> v_hash then return jsonb_build_object('status', 'wrong_password'); end if;
  if p_new_username <> v_username and exists(select 1 from public.iot_users where username = p_new_username) then return jsonb_build_object('status', 'username_taken'); end if;
  update public.iot_users set username = p_new_username where username = v_username;
  return jsonb_build_object('status', 'ok', 'username', p_new_username);
end;
$$;

create or replace function public.profile_change_password(p_session_token text, p_current_password text, p_new_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_hash text; v_token_hash text;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then return jsonb_build_object('status', 'session_expired'); end if;
  if p_new_password is null or length(p_new_password) < 4 or length(p_new_password) > 128 then return jsonb_build_object('status', 'invalid_password'); end if;
  select password_hash into v_hash from public.iot_users where username = v_username;
  if p_current_password is null or extensions.crypt(p_current_password, v_hash) <> v_hash then return jsonb_build_object('status', 'wrong_password'); end if;
  update public.iot_users set password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf', 12)) where username = v_username;
  v_token_hash := encode(extensions.digest(p_session_token, 'sha256'), 'hex');
  delete from public.iot_sessions where username = v_username and token_hash <> v_token_hash;
  return jsonb_build_object('status', 'ok');
end;
$$;

create or replace function public.logout_session(p_session_token text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
begin
  if p_session_token is not null then
    delete from public.iot_sessions where token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex');
  end if;
  return true;
end;
$$;

create or replace function public.session_touch(p_session_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare v_username text; v_expiry timestamptz;
begin
  v_username := public.iot_session_user(p_session_token);
  if v_username is null then raise exception 'session expired' using errcode = '28000'; end if;
  select expires_at into v_expiry from public.iot_sessions
  where token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex');
  return jsonb_build_object('username', v_username, 'expires_at', v_expiry);
end;
$$;

revoke all on function public.iot_session_user(text) from public;
revoke all on function public.login_with_session(text, text) from public;
revoke all on function public.session_kv_get(text, text) from public;
revoke all on function public.session_kv_set(text, text, jsonb) from public;
revoke all on function public.profile_get(text) from public;
revoke all on function public.profile_update(text, text, text, text, text) from public;
revoke all on function public.profile_update(text, text, text, text, text, text) from public;
revoke all on function public.profile_change_username(text, text, text) from public;
revoke all on function public.profile_change_password(text, text, text) from public;
revoke all on function public.logout_session(text) from public;
revoke all on function public.session_touch(text) from public;
grant execute on function public.login_with_session(text, text) to anon;
grant execute on function public.session_kv_get(text, text) to anon;
grant execute on function public.session_kv_set(text, text, jsonb) to anon;
grant execute on function public.profile_get(text) to anon;
grant execute on function public.profile_update(text, text, text, text, text) to anon;
grant execute on function public.profile_update(text, text, text, text, text, text) to anon;
grant execute on function public.profile_change_username(text, text, text) to anon;
grant execute on function public.profile_change_password(text, text, text) to anon;
grant execute on function public.logout_session(text) to anon;
grant execute on function public.session_touch(text) to anon;
