-- Allow advisor-owned customer activity records while preserving admin-wide access.
alter table public.app_records
  drop constraint if exists app_records_collection_name_check;

alter table public.app_records
  add constraint app_records_collection_name_check
  check (collection_name in (
    'properties', 'clients', 'deals', 'tgposts', 'reminders',
    'followups', 'priceHistory', 'accounting', 'advisors', 'clientActivities'
  ));

drop policy if exists app_records_access on public.app_records;
create policy app_records_access on public.app_records
  for all to authenticated
  using (
    (select private.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select private.is_active_advisor())
      and collection_name in (
        'properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory', 'clientActivities'
      )
    )
  )
  with check (
    (select private.is_active_admin())
    or (
      owner_id = (select auth.uid())
      and (select private.is_active_advisor())
      and collection_name in (
        'properties', 'clients', 'deals', 'reminders', 'followups', 'priceHistory', 'clientActivities'
      )
    )
  );
