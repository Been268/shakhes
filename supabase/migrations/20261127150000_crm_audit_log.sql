-- Metadata-only audit trail for sensitive CRM operations.
-- Payload contents are never copied into the audit table.
create table if not exists public.crm_audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid,
  action text not null check (action in ('insert','update','delete','read_private_document','upload_private_document','delete_private_document')),
  entity_type text not null,
  owner_id uuid,
  record_id text,
  collection_name text,
  changed_fields text[] not null default '{}'::text[],
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists crm_audit_log_created_idx on public.crm_audit_log (created_at desc);
create index if not exists crm_audit_log_entity_idx on public.crm_audit_log (entity_type, record_id, created_at desc);
create index if not exists crm_audit_log_actor_idx on public.crm_audit_log (actor_id, created_at desc);

alter table public.crm_audit_log enable row level security;
revoke all on table public.crm_audit_log from public, anon, authenticated;
grant select on table public.crm_audit_log to authenticated;

drop policy if exists crm_audit_log_admin_read on public.crm_audit_log;
create policy crm_audit_log_admin_read on public.crm_audit_log
  for select to authenticated
  using ((select private.is_active_admin()));

create or replace function private.audit_changed_json_keys(p_old jsonb, p_new jsonb)
returns text[]
language sql
immutable
set search_path = ''
as $$
  select coalesce(array_agg(key order by key), '{}'::text[])
  from (
    select key
    from pg_catalog.jsonb_object_keys(coalesce(p_old, '{}'::jsonb) || coalesce(p_new, '{}'::jsonb)) as keys(key)
    where (coalesce(p_old, '{}'::jsonb) -> key) is distinct from (coalesce(p_new, '{}'::jsonb) -> key)
  ) changed;
$$;

revoke all on function private.audit_changed_json_keys(jsonb,jsonb) from public, anon, authenticated;

create or replace function private.audit_app_record_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row public.app_records%rowtype;
  v_old jsonb;
  v_new jsonb;
  v_action text;
begin
  if tg_op = 'DELETE' then
    v_row := old;
    v_old := old.payload;
    v_new := null;
    v_action := 'delete';
  else
    v_row := new;
    v_old := case when tg_op = 'UPDATE' then old.payload else null end;
    v_new := new.payload;
    v_action := lower(tg_op);
  end if;

  insert into public.crm_audit_log
    (actor_id, action, entity_type, owner_id, record_id, collection_name, changed_fields, metadata)
  values
    (
      (select auth.uid()),
      v_action,
      'app_record',
      v_row.owner_id,
      v_row.record_id,
      v_row.collection_name,
      case when tg_op = 'UPDATE' then private.audit_changed_json_keys(v_old, v_new) else '{}'::text[] end,
      jsonb_build_object('source', 'app_records_trigger')
    );
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

revoke all on function private.audit_app_record_change() from public, anon, authenticated;
drop trigger if exists audit_app_records_changes on public.app_records;
create trigger audit_app_records_changes
after insert or update or delete on public.app_records
for each row execute function private.audit_app_record_change();

create or replace function public.log_private_property_document_event(
  p_property_record_id text,
  p_action text,
  p_file_name text default ''
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_name text := pg_catalog.left(pg_catalog.regexp_replace(coalesce(p_file_name, ''), '[\\x00-\\x1F\\x7F]', '_', 'g'), 160);
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_action not in ('read_private_document','upload_private_document','delete_private_document') then
    raise exception 'invalid private document audit action';
  end if;
  insert into public.crm_audit_log
    (actor_id, action, entity_type, record_id, metadata)
  values
    ((select auth.uid()), p_action, 'private_property_document', p_property_record_id, jsonb_build_object('file_name', v_name));
end;
$$;

revoke all on function public.log_private_property_document_event(text,text,text) from public, anon, authenticated;
grant execute on function public.log_private_property_document_event(text,text,text) to authenticated;
