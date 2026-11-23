-- Manager-controlled, read-only access to CRM client records.
-- Single-office scope: admins see office clients; advisors see only owned or granted clients.
-- No client rows are copied into request/notification records; requesters provide
-- identifying details and a manager resolves them to the authoritative client row.

create table public.client_access_requests (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  requester_id uuid not null,
  target_name text not null check (char_length(btrim(target_name)) between 2 and 160),
  target_phone text not null default '' check (char_length(target_phone) <= 64),
  reason text not null default '' check (char_length(reason) <= 1000),
  client_owner_id uuid,
  client_record_id text,
  status text not null default 'pending' check (status in ('pending','approved','denied','revoked')),
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by uuid,
  decision_note text not null default '' check (char_length(decision_note) <= 1000),
  revoked_at timestamptz,
  revoked_by uuid,
  constraint client_access_request_target_pair check ((client_owner_id is null) = (client_record_id is null)),
  constraint client_access_request_approved_has_target check (status not in ('approved','revoked') or client_owner_id is not null),
  constraint client_access_request_decision_metadata check (status = 'pending' or (decided_at is not null and decided_by is not null)),
  constraint client_access_request_revocation_metadata check (status <> 'revoked' or (revoked_at is not null and revoked_by is not null))
);

create index client_access_requests_requester_created_idx
  on public.client_access_requests (requester_id, created_at desc);
create index client_access_requests_status_created_idx
  on public.client_access_requests (status, created_at desc);
create index client_access_requests_client_idx
  on public.client_access_requests (client_owner_id, client_record_id, status);
create unique index client_access_requests_one_active_client_grant_idx
  on public.client_access_requests (requester_id, client_owner_id, client_record_id)
  where status = 'approved';

create table public.advisor_access_permissions (
  advisor_id uuid not null,
  permission_key text not null check (permission_key in ('view_all_client_information')),
  granted boolean not null default false,
  changed_at timestamptz not null default now(),
  changed_by uuid not null,
  primary key (advisor_id, permission_key)
);

create table public.client_access_audit (
  id bigint generated always as identity primary key,
  request_id uuid,
  advisor_id uuid not null,
  client_owner_id uuid,
  client_record_id text,
  actor_id uuid not null,
  action text not null check (action in (
    'request_submitted','request_approved','request_denied','access_revoked',
    'permission_granted','permission_revoked'
  )),
  created_at timestamptz not null default now()
);
create index client_access_audit_advisor_created_idx
  on public.client_access_audit (advisor_id, created_at desc);
create index client_access_audit_client_created_idx
  on public.client_access_audit (client_owner_id, client_record_id, created_at desc);

create table public.client_access_notifications (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  recipient_id uuid not null,
  request_id uuid,
  event_type text not null check (event_type in (
    'request_submitted','request_approved','request_denied','access_revoked',
    'permission_granted','permission_revoked'
  )),
  created_at timestamptz not null default now(),
  read_at timestamptz
);
create index client_access_notifications_recipient_created_idx
  on public.client_access_notifications (recipient_id, created_at desc);

alter table public.client_access_requests enable row level security;
alter table public.advisor_access_permissions enable row level security;
alter table public.client_access_audit enable row level security;
alter table public.client_access_notifications enable row level security;

revoke all on table public.client_access_requests from public, anon, authenticated;
revoke all on table public.advisor_access_permissions from public, anon, authenticated;
revoke all on table public.client_access_audit from public, anon, authenticated;
revoke all on table public.client_access_notifications from public, anon, authenticated;
grant select on table public.client_access_requests to authenticated;
grant select on table public.advisor_access_permissions to authenticated;
grant select on table public.client_access_audit to authenticated;
grant select on table public.client_access_notifications to authenticated;

drop policy if exists client_access_requests_read_scoped on public.client_access_requests;
create policy client_access_requests_read_scoped on public.client_access_requests
  for select to authenticated
  using (
    (select private.is_active_admin())
    or ((select private.is_active_advisor()) and requester_id = (select auth.uid()))
  );

drop policy if exists advisor_access_permissions_read_scoped on public.advisor_access_permissions;
create policy advisor_access_permissions_read_scoped on public.advisor_access_permissions
  for select to authenticated
  using (
    (select private.is_active_admin())
    or ((select private.is_active_advisor()) and advisor_id = (select auth.uid()))
  );

drop policy if exists client_access_audit_admin_read on public.client_access_audit;
create policy client_access_audit_admin_read on public.client_access_audit
  for select to authenticated
  using ((select private.is_active_admin()));

drop policy if exists client_access_notifications_recipient_read on public.client_access_notifications;
create policy client_access_notifications_recipient_read on public.client_access_notifications
  for select to authenticated
  using ((select private.is_active_member()) and recipient_id = (select auth.uid()));

create or replace function private.normalize_client_phone(p_value text)
returns text
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_digits text;
begin
  v_digits := pg_catalog.regexp_replace(
    pg_catalog.translate(coalesce(p_value, ''), '۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789'),
    '[^0-9]', '', 'g'
  );
  if pg_catalog.left(v_digits, 4) = '0098' and pg_catalog.length(v_digits) >= 14 then
    v_digits := '0' || pg_catalog.substr(v_digits, 5);
  elsif pg_catalog.left(v_digits, 2) = '98' and pg_catalog.length(v_digits) >= 12 then
    v_digits := '0' || pg_catalog.substr(v_digits, 3);
  elsif pg_catalog.length(v_digits) = 10 and pg_catalog.left(v_digits, 1) = '9' then
    v_digits := '0' || v_digits;
  end if;
  return v_digits;
end;
$$;

revoke all on function private.normalize_client_phone(text) from public, anon, authenticated;

grant usage on schema private to authenticated;

create or replace function private.can_view_client(p_owner_id uuid, p_record_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select private.is_active_admin())
    or (
      (select private.is_active_advisor())
      and (
        p_owner_id = (select auth.uid())
        or exists (
          select 1 from public.advisor_access_permissions p
          where p.advisor_id = (select auth.uid())
            and p.permission_key = 'view_all_client_information'
            and p.granted = true
        )
        or exists (
          select 1 from public.client_access_requests r
          where r.requester_id = (select auth.uid())
            and r.client_owner_id = p_owner_id
            and r.client_record_id = p_record_id
            and r.status = 'approved'
        )
      )
    );
$$;

create or replace function private.can_read_client_related(p_owner_id uuid, p_client_record_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_client_record_id is not null
    and exists (
      select 1 from public.app_records c
      where c.owner_id = p_owner_id
        and c.collection_name = 'clients'
        and c.record_id = p_client_record_id
        and private.can_view_client(c.owner_id, c.record_id)
    );
$$;

revoke all on function private.can_view_client(uuid,text) from public, anon, authenticated;
revoke all on function private.can_read_client_related(uuid,text) from public, anon, authenticated;
grant execute on function private.can_view_client(uuid,text) to authenticated;
grant execute on function private.can_read_client_related(uuid,text) to authenticated;

-- A new permissive SELECT policy supplies the exceptional grants; restrictive
-- guards ensure no future permissive policy can bypass client ownership/approval.
drop policy if exists app_records_clients_access_select on public.app_records;
create policy app_records_clients_access_select on public.app_records
  for select to authenticated
  using (
    collection_name = 'clients'
    and (select private.can_view_client(owner_id, record_id))
  );

drop policy if exists app_records_clients_access_guard on public.app_records;
create policy app_records_clients_access_guard on public.app_records
  as restrictive
  for select to authenticated
  using (
    collection_name <> 'clients'
    or (select private.can_view_client(owner_id, record_id))
  );

-- Read access to activity/follow-up history follows the same client grant,
-- while all write policies remain owner/admin-only through app_records_access.
drop policy if exists app_records_client_history_select on public.app_records;
create policy app_records_client_history_select on public.app_records
  for select to authenticated
  using (
    collection_name in ('clientActivities','followups')
    and (select private.can_read_client_related(owner_id, payload ->> 'clientId'))
  );

drop policy if exists app_records_client_history_guard on public.app_records;
create policy app_records_client_history_guard on public.app_records
  as restrictive
  for select to authenticated
  using (
    collection_name not in ('clientActivities','followups')
    or (select private.is_active_admin())
    or ((select private.is_active_advisor()) and owner_id = (select auth.uid()))
    or (select private.can_read_client_related(owner_id, payload ->> 'clientId'))
  );

create or replace function public.request_client_access(
  p_target_name text,
  p_target_phone text default '',
  p_reason text default ''
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_name text := pg_catalog.btrim(coalesce(p_target_name, ''));
  v_phone text := pg_catalog.btrim(coalesce(p_target_phone, ''));
  v_phone_normalized text;
  v_reason text := pg_catalog.btrim(coalesce(p_reason, ''));
  v_request_id uuid;
begin
  -- Serialize request creation with admin role/status transitions so a pending
  -- request cannot be inserted just after the manager's revocation sweep.
  perform 1 from public.profiles p
  where p.id = (select auth.uid())
    and p.role = 'advisor'
    and p.status = 'active'
  for share;
  if not found then
    raise exception 'active advisor access required';
  end if;
  if pg_catalog.char_length(v_name) < 2 or pg_catalog.char_length(v_name) > 160 then
    raise exception 'نام مشتری باید بین ۲ تا ۱۶۰ نویسه باشد';
  end if;
  if pg_catalog.char_length(v_phone) > 64 then
    raise exception 'شماره تماس بیش از حد طولانی است';
  end if;
  if pg_catalog.char_length(v_reason) > 1000 then
    raise exception 'توضیح درخواست بیش از حد طولانی است';
  end if;
  v_phone_normalized := private.normalize_client_phone(v_phone);
  if v_phone <> '' and (pg_catalog.char_length(v_phone_normalized) < 8 or pg_catalog.char_length(v_phone_normalized) > 15) then
    raise exception 'شماره تماس معتبر نیست';
  end if;
  if exists (
    select 1 from public.client_access_requests r
    where r.requester_id = (select auth.uid()) and r.status = 'pending'
      and (
        (v_phone_normalized <> '' and private.normalize_client_phone(r.target_phone) = v_phone_normalized)
        or (v_phone_normalized = '' and pg_catalog.lower(pg_catalog.btrim(r.target_name)) = pg_catalog.lower(v_name))
      )
  ) then
    raise exception 'برای این مشتری درخواست در حال بررسی دارید';
  end if;

  insert into public.client_access_requests (requester_id, target_name, target_phone, reason)
  values ((select auth.uid()), v_name, v_phone, v_reason)
  returning id into v_request_id;

  insert into public.client_access_audit (request_id, advisor_id, actor_id, action)
  values (v_request_id, (select auth.uid()), (select auth.uid()), 'request_submitted');

  insert into public.client_access_notifications (recipient_id, request_id, event_type)
  select p.id, v_request_id, 'request_submitted'
  from public.profiles p
  where p.role = 'admin' and p.status = 'active';

  insert into public.client_access_notifications (recipient_id, request_id, event_type)
  values ((select auth.uid()), v_request_id, 'request_submitted');

  return v_request_id;
end;
$$;

create or replace function public.manager_decide_client_access(
  p_request_id uuid,
  p_decision text,
  p_client_owner_id uuid default null,
  p_client_record_id text default null,
  p_note text default ''
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request public.client_access_requests%rowtype;
  v_payload jsonb;
  v_note text := pg_catalog.btrim(coalesce(p_note, ''));
  v_action text;
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_decision not in ('approved','denied') then
    raise exception 'invalid decision';
  end if;
  if pg_catalog.char_length(v_note) > 1000 then
    raise exception 'یادداشت تصمیم بیش از حد طولانی است';
  end if;
  if (p_client_owner_id is null) <> (p_client_record_id is null) then
    raise exception 'شناسه مالک و پرونده باید هم‌زمان وارد شوند';
  end if;
  if p_decision = 'approved' and p_client_owner_id is null then
    raise exception 'برای تأیید باید پروندهٔ دقیق مشتری را انتخاب کنید';
  end if;

  select r.* into v_request
  from public.client_access_requests r
  where r.id = p_request_id
  for update;
  if not found or v_request.status <> 'pending' then
    raise exception 'درخواست پیدا نشد یا قبلاً تعیین تکلیف شده است';
  end if;

  if p_decision = 'approved' and not exists (
    select 1 from public.profiles p
    where p.id = v_request.requester_id
      and p.role = 'advisor'
      and p.status = 'active'
  ) then
    raise exception 'فقط حساب مشاور فعال می‌تواند دسترسی مشتری دریافت کند';
  end if;

  if p_client_owner_id is not null then
    select c.payload into v_payload
    from public.app_records c
    where c.owner_id = p_client_owner_id
      and c.collection_name = 'clients'
      and c.record_id = p_client_record_id;
    if not found then
      raise exception 'پروندهٔ مشتری انتخاب‌شده پیدا نشد';
    end if;
    if pg_catalog.lower(pg_catalog.btrim(coalesce(v_payload ->> 'name', ''))) <> pg_catalog.lower(v_request.target_name) then
      raise exception 'نام پرونده با نام درخواست مطابقت ندارد';
    end if;
    if private.normalize_client_phone(v_request.target_phone) <> ''
       and private.normalize_client_phone(v_payload ->> 'phone') <> private.normalize_client_phone(v_request.target_phone) then
      raise exception 'شمارهٔ پرونده با شمارهٔ درخواست مطابقت ندارد';
    end if;
  end if;

  v_action := case when p_decision = 'approved' then 'request_approved' else 'request_denied' end;
  update public.client_access_requests
  set client_owner_id = p_client_owner_id,
      client_record_id = p_client_record_id,
      status = p_decision,
      decided_at = pg_catalog.now(),
      decided_by = (select auth.uid()),
      decision_note = v_note
  where id = p_request_id;

  -- Once the manager has resolved the request to the authoritative client,
  -- attach the original submission event so client history shows its true date.
  update public.client_access_audit
  set client_owner_id = p_client_owner_id,
      client_record_id = p_client_record_id
  where request_id = p_request_id
    and action = 'request_submitted';

  insert into public.client_access_audit (request_id, advisor_id, client_owner_id, client_record_id, actor_id, action)
  values (p_request_id, v_request.requester_id, p_client_owner_id, p_client_record_id, (select auth.uid()), v_action);

  insert into public.client_access_notifications (recipient_id, request_id, event_type)
  values (v_request.requester_id, p_request_id, v_action);
end;
$$;

create or replace function public.manager_revoke_client_access(p_request_id uuid, p_note text default '')
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request public.client_access_requests%rowtype;
  v_note text := pg_catalog.btrim(coalesce(p_note, ''));
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if pg_catalog.char_length(v_note) > 1000 then
    raise exception 'یادداشت لغو بیش از حد طولانی است';
  end if;
  select r.* into v_request from public.client_access_requests r where r.id = p_request_id for update;
  if not found or v_request.status <> 'approved' then
    raise exception 'دسترسی فعال پیدا نشد';
  end if;
  update public.client_access_requests
  set status = 'revoked', revoked_at = pg_catalog.now(), revoked_by = (select auth.uid()),
      decision_note = case when v_note = '' then decision_note else v_note end
  where id = p_request_id;
  insert into public.client_access_audit (request_id, advisor_id, client_owner_id, client_record_id, actor_id, action)
  values (p_request_id, v_request.requester_id, v_request.client_owner_id, v_request.client_record_id, (select auth.uid()), 'access_revoked');
  insert into public.client_access_notifications (recipient_id, request_id, event_type)
  values (v_request.requester_id, p_request_id, 'access_revoked');
end;
$$;

create or replace function public.manager_set_advisor_permission(
  p_advisor_id uuid,
  p_permission_key text,
  p_granted boolean
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_profile public.profiles%rowtype;
  v_previous boolean := false;
  v_action text;
  v_event text;
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_permission_key <> 'view_all_client_information' then
    raise exception 'unsupported permission';
  end if;
  select p.* into v_profile from public.profiles p where p.id = p_advisor_id;
  if not found or v_profile.role <> 'advisor' then
    raise exception 'مشاور پیدا نشد';
  end if;
  if p_granted and v_profile.status <> 'active' then
    raise exception 'فقط به مشاور فعال می‌توان دسترسی داد';
  end if;
  select p.granted into v_previous from public.advisor_access_permissions p
  where p.advisor_id = p_advisor_id and p.permission_key = p_permission_key;
  v_previous := coalesce(v_previous, false);
  if v_previous = p_granted then
    return;
  end if;

  insert into public.advisor_access_permissions (advisor_id, permission_key, granted, changed_at, changed_by)
  values (p_advisor_id, p_permission_key, p_granted, pg_catalog.now(), (select auth.uid()))
  on conflict (advisor_id, permission_key) do update
    set granted = excluded.granted, changed_at = excluded.changed_at, changed_by = excluded.changed_by;

  v_action := case when p_granted then 'permission_granted' else 'permission_revoked' end;
  v_event := v_action;
  insert into public.client_access_audit (advisor_id, actor_id, action)
  values (p_advisor_id, (select auth.uid()), v_action);
  insert into public.client_access_notifications (recipient_id, event_type)
  values (p_advisor_id, v_event);
end;
$$;

create or replace function public.mark_client_access_notification_read(p_notification_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_active_member() then
    raise exception 'active member access required';
  end if;
  update public.client_access_notifications
  set read_at = coalesce(read_at, pg_catalog.now())
  where id = p_notification_id and recipient_id = (select auth.uid());
end;
$$;

revoke all on function public.request_client_access(text,text,text) from public, anon, authenticated;
revoke all on function public.manager_decide_client_access(uuid,text,uuid,text,text) from public, anon, authenticated;
revoke all on function public.manager_revoke_client_access(uuid,text) from public, anon, authenticated;
revoke all on function public.manager_set_advisor_permission(uuid,text,boolean) from public, anon, authenticated;
revoke all on function public.mark_client_access_notification_read(uuid) from public, anon, authenticated;
grant execute on function public.request_client_access(text,text,text) to authenticated;
grant execute on function public.manager_decide_client_access(uuid,text,uuid,text,text) to authenticated;
grant execute on function public.manager_revoke_client_access(uuid,text) to authenticated;
grant execute on function public.manager_set_advisor_permission(uuid,text,boolean) to authenticated;
grant execute on function public.mark_client_access_notification_read(uuid) to authenticated;

-- Role/status transitions permanently revoke access. Returning to the advisor
-- role does not resurrect old approvals or the all-clients permission.
create or replace function private.revoke_advisor_client_access(p_advisor_id uuid, p_actor_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request public.client_access_requests%rowtype;
  v_permission_changed boolean := false;
begin
  if p_advisor_id is null or p_actor_id is null then
    raise exception 'advisor and manager IDs are required';
  end if;

  for v_request in
    update public.client_access_requests
    set status = 'revoked', revoked_at = pg_catalog.now(), revoked_by = p_actor_id,
        decision_note = case when decision_note = '' then 'لغو خودکار به‌دلیل تغییر نقش یا غیرفعال‌شدن حساب' else decision_note end
    where requester_id = p_advisor_id and status = 'approved'
    returning *
  loop
    insert into public.client_access_audit (request_id, advisor_id, client_owner_id, client_record_id, actor_id, action)
    values (v_request.id, p_advisor_id, v_request.client_owner_id, v_request.client_record_id, p_actor_id, 'access_revoked');
    insert into public.client_access_notifications (recipient_id, request_id, event_type)
    values (p_advisor_id, v_request.id, 'access_revoked');
  end loop;

  for v_request in
    update public.client_access_requests
    set status = 'denied', decided_at = pg_catalog.now(), decided_by = p_actor_id,
        decision_note = 'درخواست باز به‌دلیل تغییر نقش یا غیرفعال‌شدن حساب بسته شد'
    where requester_id = p_advisor_id and status = 'pending'
    returning *
  loop
    insert into public.client_access_audit (request_id, advisor_id, actor_id, action)
    values (v_request.id, p_advisor_id, p_actor_id, 'request_denied');
    insert into public.client_access_notifications (recipient_id, request_id, event_type)
    values (p_advisor_id, v_request.id, 'request_denied');
  end loop;

  update public.advisor_access_permissions
  set granted = false, changed_at = pg_catalog.now(), changed_by = p_actor_id
  where advisor_id = p_advisor_id and granted = true;
  v_permission_changed := found;
  if v_permission_changed then
    insert into public.client_access_audit (advisor_id, actor_id, action)
    values (p_advisor_id, p_actor_id, 'permission_revoked');
    insert into public.client_access_notifications (recipient_id, event_type)
    values (p_advisor_id, 'permission_revoked');
  end if;
end;
$$;

revoke all on function private.revoke_advisor_client_access(uuid,uuid) from public, anon, authenticated;

-- Preserve the existing admin profile API, adding permanent access revocation
-- when an advisor is made inactive.
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
declare
  v_profile public.profiles%rowtype;
  v_next_status text;
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_status is not null and p_status not in ('pending', 'active', 'disabled') then
    raise exception 'invalid profile status';
  end if;
  select p.* into v_profile from public.profiles p where p.id = p_user_id for update;
  if not found then
    raise exception 'profile not found';
  end if;
  v_next_status := coalesce(p_status, v_profile.status);
  update public.profiles
  set status = v_next_status,
      fullname = coalesce(p_fullname, fullname),
      phone = coalesce(p_phone, phone),
      updated_at = pg_catalog.now()
  where id = p_user_id;
  if v_profile.role = 'advisor' and v_next_status <> 'active' then
    perform private.revoke_advisor_client_access(p_user_id, (select auth.uid()));
  end if;
end;
$$;

-- Preserve the existing admin role-change protections and revoke any advisor
-- grants before the role changes; a later return to advisor starts unprivileged.
create or replace function public.admin_change_user_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_profile public.profiles%rowtype;
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_role not in ('admin', 'advisor', 'customer') then
    raise exception 'invalid role';
  end if;
  select p.* into v_profile from public.profiles p where p.id = p_user_id for update;
  if not found then
    raise exception 'profile not found';
  end if;
  if v_profile.is_primary_admin and p_role <> 'admin' then
    raise exception 'the primary admin role cannot be changed';
  end if;
  if v_profile.role = 'admin' and v_profile.status = 'active' and p_role <> 'admin'
     and not exists (
       select 1 from public.profiles p
       where p.role = 'admin' and p.status = 'active' and p.id <> p_user_id
     ) then
    raise exception 'at least one active admin must remain';
  end if;
  if v_profile.role = 'advisor' and p_role <> 'advisor' then
    perform private.revoke_advisor_client_access(p_user_id, (select auth.uid()));
  end if;
  update public.profiles set role = p_role, updated_at = pg_catalog.now() where id = p_user_id;
end;
$$;

revoke all on function public.admin_update_profile(uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.admin_change_user_role(uuid,text) from public, anon, authenticated;
grant execute on function public.admin_update_profile(uuid,text,text,text) to authenticated;
grant execute on function public.admin_change_user_role(uuid,text) to authenticated;
