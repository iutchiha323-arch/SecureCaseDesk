
# SecureCaseDesk v2.2

نظام إدارة القضايا والملفات الأمنية والمذكرات والمحتجزين.

## الجهة
وزارة الداخلية
إدارة المباحث الجنائية م/ حجة

## التقنيات
- Python 3.13
- Flet
- SQLite
- Cryptography
- Android APK

## المميزات
- إدارة القضايا.
- إدارة الأقسام.
- إدارة المذكرات.
- إدارة المحتجزين.
- إدارة المستخدمين والصلاحيات.
- سجل التدقيق.
- التقارير.
- النسخ الاحتياطي.
- الذكاء الاصطناعي الاختياري.

## التشغيل

pip install -r requirements.txt

flet run src/main.py

## بناء APK

flet build apk

## GitHub

يتم بناء APK تلقائياً باستخدام GitHub Actions.

افتح:
Repository > Actions

ثم اختر:
Build SecureCaseDesk Android APK

حمّل ملف البناء من Artifacts.
