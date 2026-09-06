-- קובץ מצורף (תמונה או PDF) לכל הטבה
-- הועלה לפרויקט HFCA Benefits Hub (ref kshmxhkdysuhxyigsett).

alter table public.benefits_hub_benefits
  add column if not exists file_url  text,
  add column if not exists file_name text,
  add column if not exists file_path text,
  add column if not exists file_type text;

comment on column public.benefits_hub_benefits.file_url  is 'Public URL of the attached file (image / PDF) in the benefit-files bucket';
comment on column public.benefits_hub_benefits.file_name is 'Original file name, used as the download name';
comment on column public.benefits_hub_benefits.file_path is 'Object path inside the benefit-files bucket (needed for replace / delete)';
comment on column public.benefits_hub_benefits.file_type is 'MIME type of the attached file';

-- דלי אחסון ציבורי לקבצים המצורפים
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('benefit-files', 'benefit-files', true, 10485760,
        array['image/png','image/jpeg','image/jpg','image/webp','image/gif','image/svg+xml','application/pdf'])
on conflict (id) do update
  set public = true,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- הורדה פתוחה לכולם; העלאה / החלפה / מחיקה רק למנהל מחובר
drop policy if exists benefit_files_public_read on storage.objects;
create policy benefit_files_public_read on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'benefit-files');

drop policy if exists benefit_files_auth_insert on storage.objects;
create policy benefit_files_auth_insert on storage.objects
  for insert to authenticated
  with check (bucket_id = 'benefit-files');

drop policy if exists benefit_files_auth_update on storage.objects;
create policy benefit_files_auth_update on storage.objects
  for update to authenticated
  using (bucket_id = 'benefit-files')
  with check (bucket_id = 'benefit-files');

drop policy if exists benefit_files_auth_delete on storage.objects;
create policy benefit_files_auth_delete on storage.objects
  for delete to authenticated
  using (bucket_id = 'benefit-files');
