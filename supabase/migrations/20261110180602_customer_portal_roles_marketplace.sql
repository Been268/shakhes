-- Customer portal, role governance, safe property marketplace and advisor assignment.
-- Customer submissions remain owned by the primary admin and are private until approved.

alter table public.profiles
  add column if not exists is_primary_admin boolean not null default false;

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles
  add constraint profiles_role_check check (role in ('admin', 'advisor', 'customer'));

-- Preserve exactly one existing active admin as the immutable primary admin.
update public.profiles
set is_primary_admin = (id = (
  select p.id from public.profiles p
  where p.role = 'admin' and p.status = 'active'
  order by p.created_at asc, p.id asc
  limit 1
));
create unique index if not exists profiles_one_primary_admin_idx
  on public.profiles (is_primary_admin) where is_primary_admin;

create or replace function private.prevent_primary_admin_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    if old.is_primary_admin then
      raise exception 'the primary admin cannot be deleted';
    end if;
    return old;
  end if;
  if old.is_primary_admin and (
    new.is_primary_admin is distinct from true
    or new.role is distinct from 'admin'
    or new.status is distinct from 'active'
  ) then
    raise exception 'the primary admin cannot be demoted or disabled';
  end if;
  if not old.is_primary_admin and new.is_primary_admin is distinct from old.is_primary_admin then
    raise exception 'the primary admin designation is immutable';
  end if;
  return new;
end;
$$;
drop trigger if exists protect_primary_admin_profile on public.profiles;
create trigger protect_primary_admin_profile
  before update or delete on public.profiles
  for each row execute function private.prevent_primary_admin_change();

create or replace function private.is_active_customer()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'customer' and p.status = 'active'
  );
$$;

create or replace function private.primary_admin_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id from public.profiles p
  where p.is_primary_admin and p.role = 'admin' and p.status = 'active'
  limit 1;
$$;

grant execute on function private.is_active_customer() to authenticated;
grant execute on function private.primary_admin_id() to authenticated;

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_role text;
begin
  requested_role := coalesce(new.raw_user_meta_data ->> 'requested_role', 'advisor');
  if requested_role not in ('advisor', 'customer') then
    requested_role := 'advisor';
  end if;
  insert into public.profiles (id, email, fullname, username, phone, role, status, join_date)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'fullname', ''),
    coalesce(new.raw_user_meta_data ->> 'username', split_part(coalesce(new.email, ''), '@', 1)),
    coalesce(new.raw_user_meta_data ->> 'phone', ''),
    requested_role,
    'pending',
    to_char(now() at time zone 'Asia/Tehran', 'YYYY/MM/DD')
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

create or replace function public.admin_change_user_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  target public.profiles%rowtype;
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_role not in ('admin', 'advisor', 'customer') then
    raise exception 'invalid role';
  end if;
  select * into target from public.profiles where id = p_user_id for update;
  if not found then
    raise exception 'profile not found';
  end if;
  if target.is_primary_admin and p_role <> 'admin' then
    raise exception 'the primary admin role cannot be changed';
  end if;
  if target.role = 'admin' and target.status = 'active' and p_role <> 'admin'
     and not exists (
       select 1 from public.profiles p
       where p.role = 'admin' and p.status = 'active' and p.id <> p_user_id
     ) then
    raise exception 'at least one active admin must remain';
  end if;
  update public.profiles set role = p_role, updated_at = now() where id = p_user_id;
end;
$$;
grant execute on function public.admin_change_user_role(uuid, text) to authenticated;

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
    and p.role in ('admin', 'advisor')
    and p.id <> (select auth.uid())
    and (select private.is_active_member())
  order by p.fullname;
$$;

create or replace function private.customer_property_payload(
  p_record_id text,
  p_payload jsonb,
  p_manager_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  manager_name text;
  customer_name text;
  clean_payload jsonb;
begin
  select p.fullname into manager_name from public.profiles p where p.id = p_manager_id;
  select p.fullname into customer_name from public.profiles p where p.id = (select auth.uid());
  clean_payload := coalesce(p_payload, '{}'::jsonb)
    - '_uid' - 'ownerUid' - 'customerSubmitterId' - 'customerSubmitterName'
    - 'isCustomerSubmission' - 'assignedAdvisorId';
  return clean_payload || jsonb_build_object(
    'id', p_record_id,
    'userId', p_manager_id::text,
    'userName', coalesce(manager_name, 'مدیر مجموعه'),
    'customerSubmitterId', (select auth.uid())::text,
    'customerSubmitterName', coalesce(customer_name, 'مشتری'),
    'isCustomerSubmission', true,
    'approvalStatus', 'pending'
  );
end;
$$;

create or replace function private.guard_customer_property_record()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  manager_id uuid;
  prior_approval text;
begin
  if tg_op = 'INSERT' then
    if private.is_active_customer() then
      if new.collection_name <> 'properties' then
        raise exception 'customers may only submit property files';
      end if;
      manager_id := private.primary_admin_id();
      if manager_id is null then
        raise exception 'primary admin is not configured';
      end if;
      new.owner_id := manager_id;
      new.payload := private.customer_property_payload(new.record_id, new.payload, manager_id);
    elsif private.is_active_advisor() and new.collection_name = 'properties' then
      new.payload := jsonb_set(coalesce(new.payload, '{}'::jsonb), '{approvalStatus}', to_jsonb('pending'::text), true);
    end if;
    return new;
  end if;

  if private.is_active_customer() then
    manager_id := private.primary_admin_id();
    if old.collection_name <> 'properties'
       or new.collection_name <> 'properties'
       or old.owner_id <> manager_id
       or old.payload ->> 'customerSubmitterId' <> (select auth.uid())::text
       or new.owner_id <> old.owner_id
       or new.collection_name <> old.collection_name
       or new.record_id <> old.record_id then
      raise exception 'customers may only edit their own submitted property files';
    end if;
    new.payload := private.customer_property_payload(new.record_id, new.payload, manager_id);
    return new;
  end if;

  if private.is_active_advisor() and new.collection_name = 'properties' then
    prior_approval := coalesce(old.payload ->> 'approvalStatus', 'pending');
    new.payload := jsonb_set(coalesce(new.payload, '{}'::jsonb), '{approvalStatus}', to_jsonb(prior_approval), true);
  end if;
  return new;
end;
$$;
drop trigger if exists guard_customer_property_record on public.app_records;
create trigger guard_customer_property_record
  before insert or update on public.app_records
  for each row execute function private.guard_customer_property_record();

create policy customer_read_own_property_submissions on public.app_records
  for select to authenticated
  using (
    (select private.is_active_customer())
    and collection_name = 'properties'
    and owner_id = (select private.primary_admin_id())
    and payload ->> 'customerSubmitterId' = (select auth.uid())::text
  );

create or replace function public.save_customer_property_submission(p_record_id text, p_payload jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  manager_id uuid;
  existing public.app_records%rowtype;
  safe_payload jsonb;
begin
  if not private.is_active_customer() then
    raise exception 'active customer access required';
  end if;
  if p_record_id is null or length(btrim(p_record_id)) = 0 or length(p_record_id) > 160 then
    raise exception 'invalid property record id';
  end if;
  if jsonb_typeof(coalesce(p_payload, '{}'::jsonb)) <> 'object' then
    raise exception 'property payload must be an object';
  end if;
  manager_id := private.primary_admin_id();
  if manager_id is null then
    raise exception 'primary admin is not configured';
  end if;
  safe_payload := private.customer_property_payload(p_record_id, p_payload, manager_id);
  select * into existing
  from public.app_records
  where owner_id = manager_id and collection_name = 'properties' and record_id = p_record_id
  for update;
  if found then
    if existing.payload ->> 'customerSubmitterId' <> (select auth.uid())::text then
      raise exception 'property record is not owned by this customer';
    end if;
    update public.app_records set payload = safe_payload, updated_at = now()
    where owner_id = manager_id and collection_name = 'properties' and record_id = p_record_id;
  else
    insert into public.app_records(owner_id, collection_name, record_id, payload)
    values (manager_id, 'properties', p_record_id, safe_payload);
  end if;
end;
$$;
grant execute on function public.save_customer_property_submission(text, jsonb) to authenticated;

create or replace function public.get_my_property_submissions()
returns table(owner_id uuid, record_id text, payload jsonb, updated_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not private.is_active_customer() then
    raise exception 'active customer access required';
  end if;
  return query
  select r.owner_id, r.record_id, r.payload, r.updated_at
  from public.app_records r
  where r.owner_id = (select private.primary_admin_id())
    and r.collection_name = 'properties'
    and r.payload ->> 'customerSubmitterId' = (select auth.uid())::text
  order by r.updated_at desc;
end;
$$;
grant execute on function public.get_my_property_submissions() to authenticated;

create table if not exists public.property_marketplace (
  owner_id uuid not null,
  record_id text not null,
  listing_data jsonb not null,
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (owner_id, record_id)
);
alter table public.property_marketplace enable row level security;
revoke all on public.property_marketplace from anon, authenticated;

create or replace function private.build_marketplace_listing(p_payload jsonb)
returns jsonb
language plpgsql
immutable
security definer
set search_path = ''
as $$
declare
  extra_data jsonb;
  safe_extra jsonb;
  images_data jsonb;
  area_text text;
  display_title text;
  property_type text;
  property_status text;
  safe_price jsonb;
  safe_mortgage jsonb;
  safe_rent jsonb;
begin
  extra_data := case when jsonb_typeof(p_payload -> 'extra') = 'object' then p_payload -> 'extra' else '{}'::jsonb end;
  property_type := case when p_payload ->> 'type' = any(array['آپارتمان','ویلا','زمین','تجاری','اداری','کلنگی','باغ','مشارکت در ساخت','سایر']) then p_payload ->> 'type' else 'ملک' end;
  property_status := case when p_payload ->> 'status' = any(array['sale','rent','mortgage','rent_mortgage','presale','partnership','in_progress','exchange']) then p_payload ->> 'status' else 'sale' end;
  safe_price := case when coalesce(p_payload ->> 'price','') ~ '^[0-9۰-۹٠-٩,٬.]+$' then to_jsonb(regexp_replace(p_payload ->> 'price','[^0-9۰-۹٠-٩.]','','g')) else null end;
  safe_mortgage := case when coalesce(p_payload ->> 'mortgage','') ~ '^[0-9۰-۹٠-٩,٬.]+$' then to_jsonb(regexp_replace(p_payload ->> 'mortgage','[^0-9۰-۹٠-٩.]','','g')) else null end;
  safe_rent := case when coalesce(p_payload ->> 'rent','') ~ '^[0-9۰-۹٠-٩,٬.]+$' then to_jsonb(regexp_replace(p_payload ->> 'rent','[^0-9۰-۹٠-٩.]','','g')) else null end;
  select coalesce(jsonb_object_agg(e.key, e.value), '{}'::jsonb) into safe_extra
  from jsonb_each(extra_data) e
  where e.key = any(array['p-area','p-rooms','p-floor','p-total-floors','p-year','p-wc','p-bath','v-area','v-land','v-rooms','v-floors','v-year','v-wc','v-bath','l-area','l-width','l-price-per-m','cm-area','cm-floor','cm-width','cm-fronts','cm-goodwill','cm-wc','cm-price-per-m','pt-land','pt-width','pt-floors','pt-owner-share','pt-builder-share','pt-age','pt-price-per-m','o-area','o-year']::text[])
    and coalesce(e.value #>> '{}','') ~ '^[0-9۰-۹٠-٩,٬.]{1,18}$';
  select coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'path', case when image_item ->> 'path' ~ '^properties/[0-9A-Fa-f-]{36}/[0-9]{10,}_[A-Za-z0-9_. -]{1,100}\.(jpg|jpeg|png|webp|gif)$' then image_item -> 'path' else null end,
    'data', case when length(coalesce(image_item ->> 'data','')) <= 700000 and image_item ->> 'data' ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$' then image_item -> 'data' else null end
  )) order by ordinal), '[]'::jsonb) into images_data
  from jsonb_array_elements(case when jsonb_typeof(p_payload -> 'images') = 'array' then p_payload -> 'images' else '[]'::jsonb end) with ordinality as images(image_item,ordinal)
  where (image_item ->> 'path' ~ '^properties/[0-9A-Fa-f-]{36}/[0-9]{10,}_[A-Za-z0-9_. -]{1,100}\.(jpg|jpeg|png|webp|gif)$')
     or (length(coalesce(image_item ->> 'data','')) <= 700000 and image_item ->> 'data' ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$');
  area_text := coalesce(
    nullif(extra_data ->> 'p-area',''), nullif(extra_data ->> 'v-area',''),
    nullif(extra_data ->> 'l-area',''), nullif(extra_data ->> 'cm-area',''),
    nullif(extra_data ->> 'pt-land',''), nullif(extra_data ->> 'o-area','')
  );
  if area_text is not null and area_text !~ '^[0-9۰-۹٠-٩,٬.]{1,18}$' then area_text := null; end if;
  display_title := trim(concat_ws(' · ',
    property_type,
    case when area_text is not null then area_text || ' متر مربع' end
  ));
  return jsonb_strip_nulls(jsonb_build_object(
    'displayName', display_title,
    'type', property_type,
    'status', property_status,
    'price', safe_price,
    'mortgage', safe_mortgage,
    'rent', safe_rent,
    'extra', safe_extra,
    'images', images_data,
    'area', area_text
  ));
end;
$$;

create or replace function private.sync_property_marketplace()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  effective_approval text;
  manager_id uuid;
begin
  if (tg_op = 'UPDATE' or tg_op = 'DELETE') and old.collection_name = 'properties' then
    delete from public.property_marketplace
    where owner_id = old.owner_id and record_id = old.record_id;
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  if new.collection_name <> 'properties' then
    return new;
  end if;
  manager_id := private.primary_admin_id();
  effective_approval := coalesce(new.payload ->> 'approvalStatus','pending');
  if effective_approval = 'approved'
     and coalesce(new.payload ->> 'status','') not in ('sold','rented','done','inactive','archived') then
    insert into public.property_marketplace(owner_id, record_id, listing_data, published_at, updated_at)
    values (new.owner_id, new.record_id, private.build_marketplace_listing(new.payload), now(), now())
    on conflict (owner_id, record_id) do update
      set listing_data = excluded.listing_data, published_at = excluded.published_at, updated_at = now();
  end if;
  return new;
end;
$$;
drop trigger if exists sync_property_marketplace on public.app_records;
create trigger sync_property_marketplace
  after insert or update or delete on public.app_records
  for each row execute function private.sync_property_marketplace();

-- No legacy listing is exposed without explicit manager approval.
update public.app_records r
set payload = jsonb_set(coalesce(r.payload, '{}'::jsonb), '{approvalStatus}', to_jsonb('pending'::text), true),
    updated_at = now()
where r.collection_name = 'properties'
  and r.payload ->> 'approvalStatus' is null;

-- Expose only a strict allowlist, and never expose property address, coordinates, seller phone or notes.
insert into public.property_marketplace(owner_id, record_id, listing_data)
select r.owner_id, r.record_id, private.build_marketplace_listing(r.payload)
from public.app_records r
where r.collection_name = 'properties'
  and r.payload ->> 'approvalStatus' = 'approved'
  and coalesce(r.payload ->> 'status','') not in ('sold','rented','done','inactive','archived')
on conflict (owner_id, record_id) do update
set listing_data = excluded.listing_data, published_at = now(), updated_at = now();

create or replace view public.marketplace_listings with (security_barrier = true) as
select m.owner_id, m.record_id, m.listing_data, m.published_at,
       case when a.role = 'advisor' and a.status = 'active' then a.fullname else null end as advisor_name,
       case when a.role = 'advisor' and a.status = 'active' then a.phone else null end as advisor_phone
from public.property_marketplace m
left join public.profiles a on a.id = m.owner_id
where (select private.is_active_admin())
   or (select private.is_active_customer());
revoke all on public.marketplace_listings from anon;
grant select on public.marketplace_listings to authenticated;

create table if not exists public.advisor_requests (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  manager_id uuid not null references public.profiles(id) on delete restrict,
  assigned_advisor_id uuid references public.profiles(id) on delete set null,
  property_owner_id uuid,
  property_id text,
  property_summary text not null default '',
  message text not null default '',
  status text not null default 'pending' check (status in ('pending','assigned','contacted','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((property_owner_id is null) = (property_id is null))
);
create index if not exists advisor_requests_customer_created_idx on public.advisor_requests(customer_id, created_at desc);
create index if not exists advisor_requests_assigned_status_idx on public.advisor_requests(assigned_advisor_id, status, created_at desc);
alter table public.advisor_requests enable row level security;
revoke all on public.advisor_requests from anon, authenticated;

create or replace function public.request_advisor(p_property_owner_id uuid, p_property_id text, p_message text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  customer_id uuid;
  manager_id uuid;
  customer_phone text;
  property_summary text := 'درخواست عمومی مشاور';
  request_id uuid;
  listing_row public.property_marketplace%rowtype;
  submitted_record public.app_records%rowtype;
begin
  if not private.is_active_customer() then
    raise exception 'active customer access required';
  end if;
  customer_id := (select auth.uid());
  manager_id := private.primary_admin_id();
  if manager_id is null then
    raise exception 'primary admin is not configured';
  end if;
  select p.phone into customer_phone from public.profiles p where p.id = customer_id;
  if coalesce(btrim(customer_phone),'') = '' then
    raise exception 'لطفاً ابتدا شماره تماس را در پروفایل خود ثبت کنید';
  end if;
  if length(coalesce(p_message,'')) > 2000 then
    raise exception 'پیام درخواست بیش از حد طولانی است';
  end if;
  if (p_property_owner_id is null) <> (p_property_id is null) then
    raise exception 'invalid property reference';
  end if;
  if p_property_owner_id is not null then
    select * into listing_row from public.property_marketplace
    where owner_id = p_property_owner_id and record_id = p_property_id;
    if found then
      property_summary := coalesce(listing_row.listing_data ->> 'displayName','ملک انتخاب‌شده');
    else
      select * into submitted_record from public.app_records
      where owner_id = manager_id and collection_name = 'properties' and record_id = p_property_id
      for share;
      if not found or submitted_record.payload ->> 'customerSubmitterId' <> customer_id::text then
        raise exception 'ملک انتخاب‌شده در دسترس نیست';
      end if;
      property_summary := coalesce(nullif(submitted_record.payload ->> 'type',''), 'ملک') || ' — فایل شخصی مشتری';
    end if;
  end if;
  select r.id into request_id from public.advisor_requests r
  where r.customer_id = customer_id
    and r.property_owner_id is not distinct from p_property_owner_id
    and r.property_id is not distinct from p_property_id
    and r.status in ('pending','assigned','contacted')
  order by r.created_at desc limit 1;
  if request_id is not null then
    return request_id;
  end if;
  insert into public.advisor_requests(customer_id, manager_id, property_owner_id, property_id, property_summary, message)
  values (customer_id, manager_id, p_property_owner_id, p_property_id, property_summary, coalesce(btrim(p_message),''))
  returning id into request_id;
  return request_id;
end;
$$;
grant execute on function public.request_advisor(uuid, text, text) to authenticated;

create or replace function public.manager_assign_advisor_request(p_request_id uuid, p_advisor_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_active_admin() then
    raise exception 'admin access required';
  end if;
  if p_advisor_id is not null and not exists (
    select 1 from public.profiles p where p.id = p_advisor_id and p.role = 'advisor' and p.status = 'active'
  ) then
    raise exception 'مشاور فعال پیدا نشد';
  end if;
  update public.advisor_requests
  set assigned_advisor_id = p_advisor_id,
      status = case when p_advisor_id is null then 'pending' else 'assigned' end,
      updated_at = now()
  where id = p_request_id and status <> 'closed';
  if not found then
    raise exception 'درخواست پیدا نشد یا بسته شده است';
  end if;
end;
$$;
grant execute on function public.manager_assign_advisor_request(uuid, uuid) to authenticated;

create or replace function public.advisor_update_request_status(p_request_id uuid, p_status text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_active_advisor() then
    raise exception 'active advisor access required';
  end if;
  if p_status not in ('contacted','closed') then
    raise exception 'invalid request status';
  end if;
  update public.advisor_requests
  set status = p_status, updated_at = now()
  where id = p_request_id and assigned_advisor_id = (select auth.uid()) and status <> 'closed';
  if not found then
    raise exception 'این درخواست به شما واگذار نشده یا بسته شده است';
  end if;
end;
$$;
grant execute on function public.advisor_update_request_status(uuid, text) to authenticated;

create or replace view public.advisor_requests_visible with (security_barrier = true) as
select r.id, r.customer_id, r.manager_id, r.assigned_advisor_id,
       r.property_owner_id, r.property_id, r.property_summary, r.message, r.status,
       r.created_at, r.updated_at,
       c.fullname as customer_name, c.phone as customer_phone,
       a.fullname as assigned_advisor_name
from public.advisor_requests r
join public.profiles c on c.id = r.customer_id
left join public.profiles a on a.id = r.assigned_advisor_id
where (select private.is_active_admin())
   or ((select private.is_active_advisor()) and r.assigned_advisor_id = (select auth.uid()))
   or ((select private.is_active_customer()) and r.customer_id = (select auth.uid()));
revoke all on public.advisor_requests_visible from anon;
grant select on public.advisor_requests_visible to authenticated;

create or replace function private.can_read_marketplace_property_image(p_path text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select private.is_active_customer())
    and exists (
      select 1 from public.property_marketplace m
      cross join lateral jsonb_array_elements(
        case when jsonb_typeof(m.listing_data -> 'images') = 'array' then m.listing_data -> 'images' else '[]'::jsonb end
      ) image_item
      where image_item ->> 'path' = p_path
    );
$$;
grant execute on function private.can_read_marketplace_property_image(text) to authenticated;
drop policy if exists property_images_read_marketplace on storage.objects;
create policy property_images_read_marketplace on storage.objects
  for select to authenticated
  using (bucket_id = 'property-images' and (select private.can_read_marketplace_property_image(name)));

-- No direct REST access to internal workflow tables; use the guarded RPCs and role-filtered views.
revoke all on public.property_marketplace from public, anon, authenticated;
revoke all on public.advisor_requests from public, anon, authenticated;
revoke all on public.marketplace_listings from public, anon;
revoke all on public.advisor_requests_visible from public, anon;
grant select on public.marketplace_listings to authenticated;
grant select on public.advisor_requests_visible to authenticated;

revoke all on function public.list_active_chat_contacts() from public, anon;
grant execute on function public.list_active_chat_contacts() to authenticated;
revoke all on function public.admin_change_user_role(uuid, text) from public, anon;
grant execute on function public.admin_change_user_role(uuid, text) to authenticated;
revoke all on function public.save_customer_property_submission(text, jsonb) from public, anon;
grant execute on function public.save_customer_property_submission(text, jsonb) to authenticated;
revoke all on function public.get_my_property_submissions() from public, anon;
grant execute on function public.get_my_property_submissions() to authenticated;
revoke all on function public.request_advisor(uuid, text, text) from public, anon;
grant execute on function public.request_advisor(uuid, text, text) to authenticated;
revoke all on function public.manager_assign_advisor_request(uuid, uuid) from public, anon;
grant execute on function public.manager_assign_advisor_request(uuid, uuid) to authenticated;
revoke all on function public.advisor_update_request_status(uuid, text) from public, anon;
grant execute on function public.advisor_update_request_status(uuid, text) to authenticated;
revoke all on function private.is_active_customer() from public, anon;
grant execute on function private.is_active_customer() to authenticated;
revoke all on function private.primary_admin_id() from public, anon;
grant execute on function private.primary_admin_id() to authenticated;
revoke all on function private.can_read_marketplace_property_image(text) from public, anon;
grant execute on function private.can_read_marketplace_property_image(text) to authenticated;
revoke all on function private.customer_property_payload(text, jsonb, uuid) from public, anon, authenticated;
revoke all on function private.guard_customer_property_record() from public, anon, authenticated;
revoke all on function private.build_marketplace_listing(jsonb) from public, anon, authenticated;
revoke all on function private.sync_property_marketplace() from public, anon, authenticated;
revoke all on function private.prevent_primary_admin_change() from public, anon, authenticated;
