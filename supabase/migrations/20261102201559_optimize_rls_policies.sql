-- Consolidate equivalent permissive policies and keep only useful query indexes.
drop policy app_records_admin_all on public.app_records;
drop policy app_records_advisor_own on public.app_records;
create policy app_records_access on public.app_records
  for all to authenticated
  using (
    (select public.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select public.is_active_advisor())
      and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
    )
  )
  with check (
    (select public.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select public.is_active_advisor())
      and collection_name in ('properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory')
    )
  );

drop policy profiles_update_self on public.profiles;
drop policy profiles_update_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated
  using (id = (select auth.uid()) or (select public.is_active_admin()))
  with check (id = (select auth.uid()) or (select public.is_active_admin()));

drop index if exists public.app_records_owner_collection_idx;
drop index if exists public.app_records_updated_at_idx;
drop index if exists public.chat_messages_sender_created_idx;
drop index if exists public.chat_messages_recipient_created_idx;
create index if not exists chat_messages_chat_created_idx on public.chat_messages(chat_id, created_at);
