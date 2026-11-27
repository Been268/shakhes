# یادداشت پیشرفت تکمیل قابلیت‌های نیمه‌تمام

- مخزن: https://github.com/Been268/shakhes
- پروژه Supabase: efafbvagqynfxzfcitax (amlak-github-pages), وضعیت ACTIVE_HEALTHY.
- آخرین migration اعمال‌شده: 20261126215536 preserve_private_property_document_paths.
- جداول فعلی شامل profiles، app_records، property_marketplace، advisor_requests، client_access_requests، advisor_access_permissions، client_access_audit، client_access_notifications و admin_account_deletion_audit است.
- داده خواندنی فعلی app_records فقط 4 رکورد clients و 3 رکورد properties دارد؛ محتوای حساس خوانده نشد.
- مدارک خصوصی: bucket خصوصی 20MB با MIME محدود و RLS مدیر فعال دارد؛ UI بارگذاری چند فایل، فهرست، دانلود امن، حذف و resolve مسیر مالکیت را پیاده‌سازی کرده است.
- برنامه مرحله‌ای در plan.md و TODO.md ثبت شده است.
- آخرین انتشار سایت: commit 07f97a5 (PWA automatic updates). در این مرحله هنوز تغییر جدیدی روی main برای هفت قابلیت انجام نشده است.
