-- Supabase backend for the existing real-estate app.
-- Browser clients use only the publishable key; RLS is the security boundary.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null default '',
  fullname text not null default '',
  username text not null default '',
  phone text not null default '',
  role text not null default 'advisor' check (role in ('admin', 'advisor')),
  status text not null default 'pending' check (status in ('pending', 'active', 'disabled')),
  join_date text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.app_records (
  owner_id uuid not null references auth.users(id) on delete cascade,
  collection_name text not null check (collection_name in (
    'properties', 'clients', 'deals', 'tgposts', 'reminders',
    'followups', 'priceHistory', 'accounting', 'advisors'
  )),
  record_id text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (owner_id, collection_name, record_id)
);

create index app_records_owner_collection_idx on public.app_records(owner_id, collection_name);
create index app_records_updated_at_idx on public.app_records(updated_at desc);

create table public.chat_messages (
  chat_id text not null,
  id text not null,
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  primary key (chat_id, id),
  check (sender_id <> recipient_id)
);

create index chat_messages_sender_created_idx on public.chat_messages(sender_id, created_at desc);
create index chat_messages_recipient_created_idx on public.chat_messages(recipient_id, created_at desc);

create or replace function public.is_active_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin' and p.status = 'active'
  );
$$;

create or replace function public.is_active_advisor()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'advisor' and p.status = 'active'
  );
$$;

create or replace function public.is_active_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.status = 'active'
      and p.role in ('admin', 'advisor')
  );
$$;

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, fullname, username, phone, role, status, join_date)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'fullname', ''),
    coalesce(new.raw_user_meta_data ->> 'username', split_part(coalesce(new.email, ''), '@', 1)),
    coalesce(new.raw_user_meta_data ->> 'phone', ''),
    'advisor',
    'pending',
    to_char(now() at time zone 'Asia/Tehran', 'YYYY/MM/DD')
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.handle_new_auth_user();

create or replace function public.admin_update_profile(
  p_user_id uuid,
  p_status text default null,
  p_fullname text default null,
  p_phone text default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_status is not null and p_status not in ('pending', 'active', 'disabled') then
    raise exception 'invalid profile status';
  end if;
  update public.profiles
  set status = coalesce(p_status, status),
      fullname = coalesce(p_fullname, fullname),
      phone = coalesce(p_phone, phone),
      updated_at = now()
  where id = p_user_id;
end;
$$;

create or replace function public.merge_app_record(
  p_owner_id uuid,
  p_collection_name text,
  p_record_id text,
  p_patch jsonb
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if jsonb_typeof(coalesce(p_patch, '{}'::jsonb)) <> 'object' then
    raise exception 'record patch must be a JSON object';
  end if;
  update public.app_records
  set payload = coalesce(payload, '{}'::jsonb) || coalesce(p_patch, '{}'::jsonb),
      updated_at = now()
  where owner_id = p_owner_id
    and collection_name = p_collection_name
    and record_id = p_record_id;
  if not found then
    raise exception 'record not found';
  end if;
end;
$$;

alter table public.profiles enable row level security;
alter table public.app_records enable row level security;
alter table public.chat_messages enable row level security;

create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or (select public.is_active_admin()));

create policy profiles_update_self on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

create policy profiles_update_admin on public.profiles
  for update to authenticated
  using ((select public.is_active_admin()))
  with check ((select public.is_active_admin()));

create policy app_records_admin_all on public.app_records
  for all to authenticated
  using ((select public.is_active_admin()))
  with check ((select public.is_active_admin()));

create policy app_records_advisor_own on public.app_records
  for all to authenticated
  using (
    owner_id = (select auth.uid())
    and (select public.is_active_advisor())
    and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
  )
  with check (
    owner_id = (select auth.uid())
    and (select public.is_active_advisor())
    and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
  );

create policy chat_messages_read_participant on public.chat_messages
  for select to authenticated
  using (
    (select public.is_active_member())
    and ((select auth.uid()) = sender_id or (select auth.uid()) = recipient_id)
  );

create policy chat_messages_insert_sender on public.chat_messages
  for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and sender_id <> recipient_id
    and (select public.is_active_member())
    and exists (
      select 1 from public.profiles p
      where p.id = recipient_id and p.status = 'active'
    )
    and chat_id = case
      when sender_id::text < recipient_id::text then sender_id::text || '_' || recipient_id::text
      else recipient_id::text || '_' || sender_id::text
    end
  );

create policy chat_messages_update_sender on public.chat_messages
  for update to authenticated
  using (sender_id = (select auth.uid()) and (select public.is_active_member()))
  with check (sender_id = (select auth.uid()) and (select public.is_active_member()));

create policy chat_messages_delete_sender on public.chat_messages
  for delete to authenticated
  using (sender_id = (select auth.uid()) and (select public.is_active_member()));

revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (fullname, phone) on public.profiles to authenticated;

revoke all on public.app_records from anon, authenticated;
grant select, insert, update, delete on public.app_records to authenticated;

revoke all on public.chat_messages from anon, authenticated;
grant select, insert, update, delete on public.chat_messages to authenticated;

grant execute on function public.is_active_admin() to authenticated;
grant execute on function public.is_active_advisor() to authenticated;
grant execute on function public.is_active_member() to authenticated;
grant execute on function public.admin_update_profile(uuid, text, text, text) to authenticated;
grant execute on function public.merge_app_record(uuid, text, text, jsonb) to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('property-images', 'property-images', false, 10485760, array['image/*'])
on conflict (id) do update
set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

create policy property_images_read_owner_or_admin on storage.objects
  for select to authenticated
  using (
    bucket_id = 'property-images'
    and (select public.is_active_member())
    and (
      (split_part(name, '/', 1) = 'properties' and split_part(name, '/', 2) = (select auth.uid())::text)
      or (select public.is_active_admin())
    )
  );

create policy property_images_insert_owner on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'property-images'
    and (select public.is_active_member())
    and split_part(name, '/', 1) = 'properties'
    and split_part(name, '/', 2) = (select auth.uid())::text
  );

create policy property_images_delete_owner_or_admin on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'property-images'
    and (select public.is_active_member())
    and (
      (split_part(name, '/', 1) = 'properties' and split_part(name, '/', 2) = (select auth.uid())::text)
      or (select public.is_active_admin())
    )
  );
