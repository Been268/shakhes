-- Role-filtered application views are read-only for authenticated clients.
revoke all on public.marketplace_listings from public, anon, authenticated;
revoke all on public.advisor_requests_visible from public, anon, authenticated;
grant select on public.marketplace_listings to authenticated;
grant select on public.advisor_requests_visible to authenticated;
