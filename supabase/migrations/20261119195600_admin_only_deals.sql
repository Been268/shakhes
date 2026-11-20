-- Restrict deals and deal attachments to active office administrators.
-- Restrictive policies leave the existing advisor/customer access rules intact,
-- while preventing any permissive policy from granting access to deals/.

drop policy if exists app_records_deals_admin_only_restrictive on public.app_records;
create policy app_records_deals_admin_only_restrictive
  on public.app_records
  as restrictive
  for all to authenticated
  using (
    collection_name <> 'deals'
    or (select private.is_active_admin())
  )
  with check (
    collection_name <> 'deals'
    or (select private.is_active_admin())
  );

-- Remove the previous owner-or-admin permissions for deal attachments.
drop policy if exists deal_images_read_owner_or_admin on storage.objects;
drop policy if exists deal_images_insert_owner_or_admin on storage.objects;
drop policy if exists deal_images_delete_owner_or_admin on storage.objects;

-- Keep the marketplace image exception limited to property photo paths.
drop policy if exists property_images_read_marketplace on storage.objects;
create policy property_images_read_marketplace on storage.objects
  for select to authenticated
  using (
    bucket_id = 'property-images'
    and split_part(name, '/', 1) = 'properties'
    and (select private.can_read_marketplace_property_image(name))
  );

-- Replace owner access with active-admin-only deal attachment access.
drop policy if exists deal_images_read_admin_only on storage.objects;
drop policy if exists deal_images_insert_admin_only on storage.objects;
drop policy if exists deal_images_delete_admin_only on storage.objects;
create policy deal_images_read_admin_only on storage.objects
  for select to authenticated
  using (
    bucket_id = 'property-images'
    and split_part(name, '/', 1) = 'deals'
    and (select private.is_active_admin())
  );
create policy deal_images_insert_admin_only on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'property-images'
    and split_part(name, '/', 1) = 'deals'
    and (select private.is_active_admin())
  );
create policy deal_images_delete_admin_only on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'property-images'
    and split_part(name, '/', 1) = 'deals'
    and (select private.is_active_admin())
  );

-- Fail closed if another permissive Storage policy is added later.
drop policy if exists deal_objects_admin_only_restrictive on storage.objects;
create policy deal_objects_admin_only_restrictive
  on storage.objects
  as restrictive
  for all to authenticated
  using (
    bucket_id <> 'property-images'
    or split_part(name, '/', 1) <> 'deals'
    or (select private.is_active_admin())
  )
  with check (
    bucket_id <> 'property-images'
    or split_part(name, '/', 1) <> 'deals'
    or (select private.is_active_admin())
  );
