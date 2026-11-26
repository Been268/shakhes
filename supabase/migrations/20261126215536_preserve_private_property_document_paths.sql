-- Preserve the Storage folder identity of private property documents when a
-- property record changes owner (notably during admin account deletion).
-- The Storage object itself stays in the private bucket; only its lookup
-- metadata is retained in the non-exposed `private` schema.

create table if not exists private.property_private_document_storage_owners (
  current_owner_id uuid not null,
  property_record_id text not null,
  storage_owner_id uuid not null,
  updated_at timestamptz not null default pg_catalog.now(),
  primary key (current_owner_id, property_record_id)
);

alter table private.property_private_document_storage_owners enable row level security;
revoke all on table private.property_private_document_storage_owners from public, anon, authenticated;

-- Recover existing transferred-property folders only when the Storage path
-- points to exactly one former owner and the property record id is unambiguous.
-- Ambiguous or unmatched objects are left untouched for separate review.
with file_candidates as (
  select
    r.owner_id as database_owner_id,
    r.record_id as property_record_id,
    case
      when coalesce(nullif(r.payload ->> '_uid', ''), nullif(r.payload ->> 'userId', ''))
           ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then coalesce(nullif(r.payload ->> '_uid', ''), nullif(r.payload ->> 'userId', ''))::uuid
      else r.owner_id
    end as current_owner_id,
    split_part(o.name, '/', 2) as storage_owner_text,
    case
      when split_part(o.name, '/', 2)
           ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then split_part(o.name, '/', 2)::uuid
      else null
    end as storage_owner_id
  from public.app_records r
  join storage.objects o
    on o.bucket_id = 'property-private-documents'
   and split_part(o.name, '/', 1) = 'properties'
   and split_part(o.name, '/', 3) = r.record_id
   and split_part(o.name, '/', 4) = 'documents'
  where r.collection_name = 'properties'
)
insert into private.property_private_document_storage_owners
  (current_owner_id, property_record_id, storage_owner_id)
select distinct
  c.current_owner_id,
  c.property_record_id,
  c.storage_owner_id
from file_candidates c
where c.storage_owner_id is not null
  and c.storage_owner_id <> c.current_owner_id
  and not exists (
    select 1
    from storage.objects other_object
    where other_object.bucket_id = 'property-private-documents'
      and split_part(other_object.name, '/', 1) = 'properties'
      and split_part(other_object.name, '/', 3) = c.property_record_id
      and split_part(other_object.name, '/', 4) = 'documents'
      and split_part(other_object.name, '/', 2) <> c.storage_owner_text
  )
  and not exists (
    select 1
    from public.app_records duplicate_record
    where duplicate_record.collection_name = 'properties'
      and duplicate_record.record_id = c.property_record_id
      and duplicate_record.owner_id <> c.database_owner_id
  )
on conflict (current_owner_id, property_record_id) do nothing;

create or replace function private.remember_property_private_document_storage_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_old_owner_text text;
  v_new_owner_text text;
  v_old_owner_id uuid;
  v_new_owner_id uuid;
  v_storage_owner_id uuid;
  v_existing_storage_owner_id uuid;
begin
  if old.collection_name <> 'properties' or old.owner_id is not distinct from new.owner_id then
    return new;
  end if;

  -- Keep the same owner-id precedence as the UI's legacy folder builder.
  v_old_owner_text := coalesce(
    nullif(old.payload ->> '_uid', ''),
    nullif(old.payload ->> 'userId', ''),
    old.owner_id::text
  );
  begin
    v_old_owner_id := v_old_owner_text::uuid;
  exception when invalid_text_representation then
    v_old_owner_id := old.owner_id;
  end;

  v_new_owner_text := coalesce(
    nullif(new.payload ->> '_uid', ''),
    nullif(new.payload ->> 'userId', ''),
    new.owner_id::text
  );
  begin
    v_new_owner_id := v_new_owner_text::uuid;
  exception when invalid_text_representation then
    v_new_owner_id := new.owner_id;
  end;

  -- Carry forward an earlier mapping when a property changes owner more than once.
  select mapping.storage_owner_id
    into v_storage_owner_id
  from private.property_private_document_storage_owners mapping
  where mapping.current_owner_id = v_old_owner_id
    and mapping.property_record_id = old.record_id;

  if not found then
    v_storage_owner_id := v_old_owner_id;
  end if;

  insert into private.property_private_document_storage_owners
    (current_owner_id, property_record_id, storage_owner_id, updated_at)
  values (v_new_owner_id, new.record_id, v_storage_owner_id, pg_catalog.now())
  on conflict (current_owner_id, property_record_id) do nothing;

  select mapping.storage_owner_id
    into v_existing_storage_owner_id
  from private.property_private_document_storage_owners mapping
  where mapping.current_owner_id = v_new_owner_id
    and mapping.property_record_id = new.record_id;

  if v_existing_storage_owner_id is distinct from v_storage_owner_id then
    raise exception 'نگاشت پوشهٔ مدارک خصوصی با مالک فعلی تداخل دارد؛ انتقال ملک متوقف شد';
  end if;

  if v_old_owner_id is distinct from v_new_owner_id then
    delete from private.property_private_document_storage_owners mapping
    where mapping.current_owner_id = v_old_owner_id
      and mapping.property_record_id = old.record_id;
  end if;

  return new;
end;
$$;

revoke all on function private.remember_property_private_document_storage_owner() from public, anon, authenticated;

drop trigger if exists remember_property_private_document_storage_owner on public.app_records;
create trigger remember_property_private_document_storage_owner
after update of owner_id on public.app_records
for each row
when (old.collection_name = 'properties' and old.owner_id is distinct from new.owner_id)
execute function private.remember_property_private_document_storage_owner();

create or replace function public.resolve_property_private_document_storage_owner(
  p_property_record_id text,
  p_current_owner_id uuid,
  p_candidate_owner_id uuid
)
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_storage_owner_id uuid;
begin
  if (select auth.uid()) is null or not private.is_active_admin() then
    raise exception 'فقط مدیر فعال می‌تواند مسیر مدارک خصوصی را دریافت کند';
  end if;
  if p_property_record_id is null or pg_catalog.btrim(p_property_record_id) = ''
     or p_current_owner_id is null or p_candidate_owner_id is null then
    raise exception 'اطلاعات ملک برای یافتن مسیر مدارک کامل نیست';
  end if;

  select mapping.storage_owner_id
    into v_storage_owner_id
  from private.property_private_document_storage_owners mapping
  where mapping.current_owner_id = p_current_owner_id
    and mapping.property_record_id = p_property_record_id;

  if found then
    return v_storage_owner_id;
  end if;

  -- For properties that have not changed owner, retain the existing folder path.
  return p_candidate_owner_id;
end;
$$;

revoke all on function public.resolve_property_private_document_storage_owner(text, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.resolve_property_private_document_storage_owner(text, uuid, uuid)
  to authenticated;
