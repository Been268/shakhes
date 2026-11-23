-- The deletion RPC is intended for authenticated user sessions only.
-- Keep the database service role from invoking it as an alternate API path.
revoke all on function public.admin_delete_user_transfer_records(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.admin_delete_user_transfer_records(uuid)
  to authenticated;
