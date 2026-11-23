-- Serialize account deletion with concurrent FK-backed writes. The original
-- transactional implementation becomes private; the public RPC first locks the
-- target Auth row so app-record/chat inserts cannot race into an ON DELETE cascade.
alter function public.admin_delete_user_transfer_records(uuid) set schema private;
revoke all on function private.admin_delete_user_transfer_records(uuid)
  from public, anon, authenticated, service_role;

create or replace function public.admin_delete_user_transfer_records(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor_id uuid := (select auth.uid());
  v_primary_admin_id uuid;
  v_locked_user_id uuid;
  v_target_role text;
  v_target_status text;
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
  if p_user_id = v_actor_id or p_user_id = v_primary_admin_id then
    raise exception 'حساب مدیر اصلی یا حساب جاری قابل حذف نیست';
  end if;

  -- FOR UPDATE conflicts with the KEY SHARE lock taken by inserts referencing
  -- auth.users, so all checks and ownership changes see a stable target account.
  select u.id into v_locked_user_id
  from auth.users u
  where u.id = p_user_id
  for update;
  if not found then
    raise exception 'حساب کاربر پیدا نشد یا قبلاً حذف شده است';
  end if;

  select p.role, p.status into v_target_role, v_target_status
  from public.profiles p
  where p.id = p_user_id
  for update;
  if not found then
    raise exception 'پروفایل کاربر پیدا نشد؛ حذف حساب انجام نشد';
  end if;
  if v_target_role = 'admin' and v_target_status = 'active' then
    raise exception 'برای حفظ دسترسی مدیریتی، ابتدا مدیر فعال را غیرفعال یا نقش آن را تغییر دهید';
  end if;

  return private.admin_delete_user_transfer_records(p_user_id);
end;
$$;

revoke all on function public.admin_delete_user_transfer_records(uuid) from public, anon, authenticated;
grant execute on function public.admin_delete_user_transfer_records(uuid) to authenticated;
