-- Keep SECURITY DEFINER helpers unavailable to anonymous callers.
revoke all on function public.handle_new_auth_user() from public, anon, authenticated;
revoke all on function public.is_active_admin() from public, anon, authenticated;
revoke all on function public.is_active_advisor() from public, anon, authenticated;
revoke all on function public.is_active_member() from public, anon, authenticated;
revoke all on function public.admin_update_profile(uuid, text, text, text) from public, anon, authenticated;
revoke all on function public.merge_app_record(uuid, text, text, jsonb) from public, anon, authenticated;

grant execute on function public.is_active_admin() to authenticated;
grant execute on function public.is_active_advisor() to authenticated;
grant execute on function public.is_active_member() to authenticated;
grant execute on function public.admin_update_profile(uuid, text, text, text) to authenticated;
grant execute on function public.merge_app_record(uuid, text, text, jsonb) to authenticated;
