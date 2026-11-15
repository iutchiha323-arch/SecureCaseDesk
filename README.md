
# SecureCaseDesk v2.2 — Android APK Build

مشروع Flet جاهز للرفع إلى GitHub وبناء تطبيق Android بصيغة APK باستخدام GitHub Actions.

## محتويات المشروع

```text
SecureCaseDesk_GitHub/
├── .github/
│   └── workflows/
│       └── build.yml
├── src/
│   └── main.py
├── pyproject.toml
├── requirements.txt
├── .gitignore
└── README.md
```

## رفع المشروع إلى GitHub

1. أنشئ مستودعاً جديداً على GitHub.
2. ارفع محتويات مجلد المشروع إلى جذر المستودع، وليس ملف ZIP نفسه.
3. تأكد من ظهور الملفات والمجلدات التالية في الصفحة الرئيسية للمستودع:
   - `pyproject.toml`
   - `requirements.txt`
   - `src/`
   - `.github/`
4. افتح تبويب **Actions**.
5. اختر سير العمل **Build SecureCaseDesk APK**.
6. اضغط **Run workflow** ثم اضغط **Run workflow** مرة أخرى.
7. انتظر حتى تنتهي عملية البناء بنجاح.
8. افتح صفحة تشغيل Workflow المكتمل.
9. من قسم **Artifacts** نزّل الملف:

   `SecureCaseDesk-Android-APK`

10. استخرج ملف APK من الأرشيف وثبّته على هاتف Android.

## تشغيل المشروع محلياً للتجربة

يتطلب المشروع Python 3.12.

إنشاء بيئة افتراضية:

```bash
python -m venv .venv
```

على Windows:

```powershell
.venv\Scripts\activate
python -m pip install -r requirements.txt
python src/main.py
```

على Linux أو macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python src/main.py
```

## البناء السحابي باستخدام GitHub Actions

يعتمد المشروع على GitHub Actions لبناء تطبيق Android دون الحاجة إلى تثبيت Android Studio على جهازك.

خطوات البناء:

1. يحمّل GitHub ملفات المشروع.
2. يجهز بيئة Python وJava وAndroid SDK.
3. يثبت المكتبات المطلوبة من `requirements.txt`.
4. ينفذ أمر بناء APK باستخدام Flet.
5. يحفظ ملف APK الناتج ضمن Artifacts لتتمكن من تنزيله.

يمكن تشغيل البناء يدوياً من تبويب Actions وفق إعدادات `build.yml`.

## ملاحظات مهمة

- ملف APK الناتج قد يحتاج إلى توقيع بمفتاح نشر خاص قبل توزيعه رسمياً.
- قد يعرض Android تحذيراً عند تثبيت التطبيق من خارج متجر Google Play.
- قاعدة البيانات والمرفقات محفوظة محلياً داخل مساحة التطبيق على الجهاز.
- تثبيت التطبيق على جهاز آخر لا ينقل بيانات الجهاز الأول.
- المشروع لا يفعّل مزامنة سحابية تلقائية.
- لا تستخدم GitHub لتخزين كلمات المرور أو مفاتيح التشفير أو بيانات القضايا الحقيقية.
- لا تضع بيانات تشغيلية حساسة داخل ملفات المشروع.
- احتفظ بنسخ احتياطية آمنة من بيانات التطبيق.
- اختبر جميع وظائف التطبيق على هاتف Android فعلي قبل الاستخدام التشغيلي.

## متطلبات المشروع

- Python 3.12
- Flet
- Android SDK
- Java JDK
- المكتبات المحددة في `requirements.txt`

## تنبيه أمني

SecureCaseDesk أداة محلية لإدارة القضايا والملفات. يجب اختبار التشفير والصلاحيات والنسخ الاحتياطي واستعادة البيانات عملياً قبل الاعتماد عليه في حفظ معلومات حساسة.

لا تعتبر مجرد نجاح بناء APK دليلاً على أن التطبيق اجتاز مراجعة أمنية كاملة.
