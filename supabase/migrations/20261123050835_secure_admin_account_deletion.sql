-- Secure account removal is a single database transaction. The browser never
-- receives a service-role credential; this RPC is limited to the active primary admin.

create table public.admin_account_deletion_audit (
  id bigint generated always as identity primary key,
  target_user_id uuid not null,
  actor_id uuid not null,
  target_role text not null check (target_role in ('admin','advisor','customer')),
  transferred_record_count integer not null default 0 check (transferred_record_count >= 0),
  transferred_listing_count integer not null default 0 check (transferred_listing_count >= 0),
  created_at timestamptz not null default pg_catalog.now()
);

create index admin_account_deletion_audit_target_created_idx
  on public.admin_account_deletion_audit (target_user_id, created_at desc);

alter table public.admin_account_deletion_audit enable row level security;
revoke all on table public.admin_account_deletion_audit from public, anon, authenticated;
grant select on table public.admin_account_deletion_audit to authenticated;
create policy admin_account_deletion_audit_read on public.admin_account_deletion_audit
  for select to authenticated
  using ((select private.is_active_admin()));

create or replace function public.admin_delete_user_transfer_records(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor_id uuid := (select auth.uid());
  v_primary_admin_id uuid;
  v_target public.profiles%rowtype;
  v_access record;
  v_transferred_records integer := 0;
  v_transferred_listings integer := 0;
  v_deleted_count integer := 0;
begin
  if v_actor_id is null or not private.is_active_admin() then
    raise exception 'فقط مدیر فعال می‌تواند این عملیات را انجام دهد';
  end if;

  v_primary_admin_id := private.primary_admin_id();
  if v_primary_admin_id is null then
    raise exception 'مدیر اصلی فعال پیدا نشد؛ حذف حساب انجام نشد';
  end if;
  if v_actor_id <> v_primary_admin_id then
    raise exception 'حذف حساب فقط توسط مدیر اصلی مجاز است';
  end if;
  if p_user_id is null then
    raise exception 'شناسهٔ کاربر معتبر نیست';
  end if;
  if p_user_id = v_actor_id then
    raise exception 'مدیر نمی‌تواند حساب خودش را حذف کند';
  end if;

  select p.* into v_target
  from public.profiles p
  where p.id = p_user_id
  for update;
  if not found then
    raise exception 'حساب کاربر پیدا نشد یا قبلاً حذف شده است';
  end if;
  if v_target.is_primary_admin or p_user_id = v_primary_admin_id then
    raise exception 'حساب مدیر اصلی قابل حذف نیست';
  end if;

  if v_target.role = 'admin' and v_target.status = 'active' and not exists (
    select 1 from public.profiles p
    where p.role = 'admin' and p.status = 'active' and p.id <> p_user_id
    limit 1
  ) then
    raise exception 'برای جلوگیری از قفل‌شدن سامانه، آخرین مدیر فعال قابل حذف نیست';
  end if;

  -- These foreign keys cascade or restrict. Never silently erase chat/request history.
  if exists (
    select 1 from public.chat_messages m
    where m.sender_id = p_user_id or m.recipient_id = p_user_id
    limit 1
  ) then
    raise exception 'این حساب سابقهٔ گفتگو دارد؛ برای حفظ پیام‌ها حذف دائمی متوقف شد. حساب را غیرفعال کنید';
  end if;
  if exists (
    select 1 from public.advisor_requests r
    where r.customer_id = p_user_id or r.manager_id = p_user_id
    limit 1
  ) then
    raise exception 'این حساب در سابقهٔ درخواست مشاور نقش دارد؛ برای حفظ سوابق حذف دائمی متوقف شد. حساب را غیرفعال کنید';
  end if;

  -- Preflight both composite keys before any transfer. A collision aborts the
  -- whole transaction instead of merging or overwriting another person's file.
  if exists (
    select 1
    from public.app_records source_record
    join public.app_records manager_record
      on manager_record.owner_id = v_primary_admin_id
     and manager_record.collection_name = source_record.collection_name
     and manager_record.record_id = source_record.record_id
    where source_record.owner_id = p_user_id
    limit 1
  ) then
    raise exception 'شناسهٔ یکی از پرونده‌ها با پروندهٔ مدیر اصلی تداخل دارد؛ هیچ تغییری انجام نشد';
  end if;
  if exists (
    select 1
    from public.property_marketplace source_listing
    join public.property_marketplace manager_listing
      on manager_listing.owner_id = v_primary_admin_id
     and manager_listing.record_id = source_listing.record_id
    where source_listing.owner_id = p_user_id
    limit 1
  ) then
    raise exception 'شناسهٔ یکی از آگهی‌ها با آگهی مدیر اصلی تداخل دارد؛ هیچ تغییری انجام نشد';
  end if;

  -- Revoke advisor grants before deleting the profile. Keep request/audit rows.
  if v_target.role = 'advisor' then
    perform private.revoke_advisor_client_access(p_user_id, v_actor_id);
  end if;

  -- If this account owned a client record, revoke existing grants to that owner
  -- and retain the resulting audit trail before the record moves to the manager.
  for v_access in
    update public.client_access_requests r
    set status = 'revoked',
        revoked_at = pg_catalog.now(),
        revoked_by = v_actor_id,
        decision_note = case
          when r.decision_note = '' then 'لغو دسترسی به‌دلیل انتقال پرونده به مدیر اصلی و حذف حساب'
          else r.decision_note
        end
    where r.client_owner_id = p_user_id
      and r.status = 'approved'
    returning r.id, r.requester_id, r.client_owner_id, r.client_record_id
  loop
    insert into public.client_access_audit
      (request_id, advisor_id, client_owner_id, client_record_id, actor_id, action)
    values
      (v_access.id, v_access.requester_id, v_access.client_owner_id,
       v_access.client_record_id, v_actor_id, 'access_revoked');
    insert into public.client_access_notifications (recipient_id, request_id, event_type)
    values (v_access.requester_id, v_access.id, 'access_revoked');
  end loop;

  -- Preserve advisor-request history while updating its surviving references.
  update public.advisor_requests
  set assigned_advisor_id = null, updated_at = pg_catalog.now()
  where assigned_advisor_id = p_user_id;
  update public.advisor_requests
  set property_owner_id = v_primary_admin_id, updated_at = pg_catalog.now()
  where property_owner_id = p_user_id;

  select count(*)::integer into v_transferred_records
  from public.app_records r
  where r.owner_id = p_user_id;
  select count(*)::integer into v_transferred_listings
  from public.property_marketplace m
  where m.owner_id = p_user_id;

  -- Transfer every CRM collection. The property sync trigger recreates approved
  -- marketplace rows under the manager; primary-key collisions were checked above.
  update public.app_records r
  set owner_id = v_primary_admin_id,
      payload = case
        when pg_catalog.jsonb_typeof(r.payload) = 'object' then
          r.payload
          || case when r.payload ->> 'userId' = p_user_id::text
                  then pg_catalog.jsonb_build_object('userId', v_primary_admin_id::text)
                  else '{}'::jsonb end
          || case when r.payload ->> 'ownerId' = p_user_id::text
                  then pg_catalog.jsonb_build_object('ownerId', v_primary_admin_id::text)
                  else '{}'::jsonb end
          || case when r.payload ->> '_uid' = p_user_id::text
                  then pg_catalog.jsonb_build_object('_uid', v_primary_admin_id::text)
                  else '{}'::jsonb end
        else r.payload
      end,
      updated_at = pg_catalog.now()
  where r.owner_id = p_user_id;

  -- Update linked client-owner references without changing historical actor IDs.
  update public.app_records r
  set payload = pg_catalog.jsonb_set(r.payload, '{clientOwnerId}',
                                     pg_catalog.to_jsonb(v_primary_admin_id::text), true),
      updated_at = pg_catalog.now()
  where pg_catalog.jsonb_typeof(r.payload) = 'object'
    and r.payload ->> 'clientOwnerId' = p_user_id::text;

  -- Move any legacy/orphan listing rows not recreated by the property sync trigger.
  update public.property_marketplace m
  set owner_id = v_primary_admin_id, updated_at = pg_catalog.now()
  where m.owner_id = p_user_id;

  insert into public.admin_account_deletion_audit
    (target_user_id, actor_id, target_role, transferred_record_count, transferred_listing_count)
  values
    (p_user_id, v_actor_id, v_target.role, v_transferred_records, v_transferred_listings);

  -- Notifications are not audit records and should not remain addressed to a deleted login.
  delete from public.client_access_notifications n where n.recipient_id = p_user_id;

  -- The existing FK uses ON DELETE SET NULL; do it explicitly to retain the requests.
  delete from auth.users u where u.id = p_user_id;
  get diagnostics v_deleted_count = row_count;
  if v_deleted_count <> 1 then
    raise exception 'حذف حساب ورود انجام نشد؛ همهٔ تغییرات لغو شدند';
  end if;

  return pg_catalog.jsonb_build_object(
    'transferred_records', v_transferred_records,
    'transferred_marketplace_listings', v_transferred_listings
  );
end;
$$;

revoke all on function public.admin_delete_user_transfer_records(uuid) from public, anon, authenticated;
grant execute on function public.admin_delete_user_transfer_records(uuid) to authenticated;
