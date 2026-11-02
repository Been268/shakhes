-- Keep internal SECURITY DEFINER helpers out of the exposed public API schema.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.is_active_admin()
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

create or replace function private.is_active_advisor()
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

create or replace function private.is_active_member()
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

create or replace function private.is_active_user(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = p_user_id and p.status = 'active' and p.role in ('admin', 'advisor')
  );
$$;

revoke all on function private.is_active_admin() from public, anon, authenticated;
revoke all on function private.is_active_advisor() from public, anon, authenticated;
revoke all on function private.is_active_member() from public, anon, authenticated;
revoke all on function private.is_active_user(uuid) from public, anon, authenticated;
grant execute on function private.is_active_admin() to authenticated;
grant execute on function private.is_active_advisor() to authenticated;
grant execute on function private.is_active_member() to authenticated;
grant execute on function private.is_active_user(uuid) to authenticated;

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
  if not private.is_active_admin() then
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

create or replace function public.list_active_chat_contacts()
returns table(id uuid, fullname text, role text)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, p.fullname, p.role
  from public.profiles p
  where p.status = 'active'
    and p.id <> (select auth.uid())
    and (select private.is_active_member())
  order by p.fullname;
$$;

-- All exposed policies now use private helpers; no client needs these public RPCs.
drop policy profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or (select private.is_active_admin()));

drop policy profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated
  using (id = (select auth.uid()) or (select private.is_active_admin()))
  with check (id = (select auth.uid()) or (select private.is_active_admin()));

drop policy app_records_access on public.app_records;
create policy app_records_access on public.app_records
  for all to authenticated
  using (
    (select private.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select private.is_active_advisor())
      and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
    )
  )
  with check (
    (select private.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select private.is_active_advisor())
      and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
    )
  );

drop policy chat_messages_read_participant on public.chat_messages;
create policy chat_messages_read_participant on public.chat_messages
  for select to authenticated
  using (
    (select private.is_active_member())
    and ((select auth.uid()) = sender_id or (select auth.uid()) = recipient_id or chat_id = 'all')
  );

drop policy chat_messages_insert_sender on public.chat_messages;
create policy chat_messages_insert_sender on public.chat_messages
  for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and (select private.is_active_member())
    and (
      (recipient_id is null and chat_id = 'all')
      or (
        recipient_id is not null
        and sender_id <> recipient_id
        and private.is_active_user(recipient_id)
        and chat_id = case
          when sender_id::text < recipient_id::text then sender_id::text || '_' || recipient_id::text
          else recipient_id::text || '_' || sender_id::text
        end
      )
    )
  );

drop policy chat_messages_delete_sender on public.chat_messages;
create policy chat_messages_delete_sender on public.chat_messages
  for delete to authenticated
  using (sender_id = (select auth.uid()) and (select private.is_active_member()));

drop policy property_images_read_owner_or_admin on storage.objects;
create policy property_images_read_owner_or_admin on storage.objects
  for select to authenticated
  using (
    bucket_id = 'property-images'
    and (select private.is_active_member())
    and (
      (split_part(name, '/', 1) = 'properties' and split_part(name, '/', 2) = (select auth.uid())::text)
      or (select private.is_active_admin())
    )
  );

drop policy property_images_insert_owner on storage.objects;
create policy property_images_insert_owner on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'property-images'
    and (select private.is_active_member())
    and split_part(name, '/', 1) = 'properties'
    and split_part(name, '/', 2) = (select auth.uid())::text
  );

drop policy property_images_delete_owner_or_admin on storage.objects;
create policy property_images_delete_owner_or_admin on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'property-images'
    and (select private.is_active_member())
    and (
      (split_part(name, '/', 1) = 'properties' and split_part(name, '/', 2) = (select auth.uid())::text)
      or (select private.is_active_admin())
    )
  );

drop function public.is_active_admin();
drop function public.is_active_advisor();
drop function public.is_active_member();
