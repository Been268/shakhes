-- Keep deal attachments in the existing private image bucket while enforcing
-- owner-scoped access for advisors and organization-wide access for admins.
create policy deal_images_insert_owner_or_admin
on storage.objects
for insert to authenticated
with check (
  bucket_id = 'property-images'
  and (select private.is_active_member())
  and split_part(name, '/', 1) = 'deals'
  and (
    split_part(name, '/', 2) = (select auth.uid())::text
    or (select private.is_active_admin())
  )
);

create policy deal_images_read_owner_or_admin
on storage.objects
for select to authenticated
using (
  bucket_id = 'property-images'
  and (select private.is_active_member())
  and split_part(name, '/', 1) = 'deals'
  and (
    split_part(name, '/', 2) = (select auth.uid())::text
    or (select private.is_active_admin())
  )
);

create policy deal_images_delete_owner_or_admin
on storage.objects
for delete to authenticated
using (
  bucket_id = 'property-images'
  and (select private.is_active_member())
  and split_part(name, '/', 1) = 'deals'
  and (
    split_part(name, '/', 2) = (select auth.uid())::text
    or (select private.is_active_admin())
  )
);
