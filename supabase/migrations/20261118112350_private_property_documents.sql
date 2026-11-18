-- Sensitive title deeds, permits, and private property photos must never use the
-- advisor-readable property-images bucket or be stored in a property payload.
-- This separate bucket is private, with storage operations limited to active admins.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'property-private-documents',
  'property-private-documents',
  false,
  20971520,
  array['application/pdf','image/jpeg','image/png','image/webp','image/heic','image/heif']
)
on conflict (id) do update
set name = excluded.name,
    public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists property_private_documents_admin_select on storage.objects;
create policy property_private_documents_admin_select
on storage.objects
for select to authenticated
using (
  bucket_id = 'property-private-documents'
  and (select private.is_active_admin())
);

drop policy if exists property_private_documents_admin_insert on storage.objects;
create policy property_private_documents_admin_insert
on storage.objects
for insert to authenticated
with check (
  bucket_id = 'property-private-documents'
  and (select private.is_active_admin())
);

drop policy if exists property_private_documents_admin_delete on storage.objects;
create policy property_private_documents_admin_delete
on storage.objects
for delete to authenticated
using (
  bucket_id = 'property-private-documents'
  and (select private.is_active_admin())
);
