-- Support direct messages and a shared all-users channel without weakening RLS.
alter table public.chat_messages alter column recipient_id drop not null;

drop policy chat_messages_read_participant on public.chat_messages;
drop policy chat_messages_insert_sender on public.chat_messages;
drop policy chat_messages_update_sender on public.chat_messages;
drop policy chat_messages_delete_sender on public.chat_messages;

create policy chat_messages_read_participant on public.chat_messages
  for select to authenticated
  using (
    (select public.is_active_member())
    and (
      (select auth.uid()) = sender_id
      or (select auth.uid()) = recipient_id
      or chat_id = 'all'
    )
  );

create policy chat_messages_insert_sender on public.chat_messages
  for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and (select public.is_active_member())
    and (
      (
        recipient_id is null
        and chat_id = 'all'
      )
      or (
        recipient_id is not null
        and sender_id <> recipient_id
        and exists (
          select 1 from public.profiles p
          where p.id = recipient_id and p.status = 'active'
        )
        and chat_id = case
          when sender_id::text < recipient_id::text then sender_id::text || '_' || recipient_id::text
          else recipient_id::text || '_' || sender_id::text
        end
      )
    )
  );

create policy chat_messages_delete_sender on public.chat_messages
  for delete to authenticated
  using (sender_id = (select auth.uid()) and (select public.is_active_member()));

revoke update on public.chat_messages from authenticated;

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
    and (select public.is_active_member())
  order by p.fullname;
$$;

revoke all on function public.list_active_chat_contacts() from public, anon, authenticated;
grant execute on function public.list_active_chat_contacts() to authenticated;
