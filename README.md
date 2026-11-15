# SecureCaseDesk v2.2 — GitHub Actions Build

مشروع Flet جاهز للرفع إلى GitHub وبناء نسختين سحابياً:

- Android APK عبر Ubuntu runner.
- Windows application عبر Windows runner.

## محتويات المشروع

```text
SecureCaseDesk_GitHub/
├── .github/workflows/build.yml
├── src/main.py
├── pyproject.toml
├── requirements.txt
├── .gitignore
└── README.md
```

## رفع المشروع إلى GitHub

1. أنشئ مستودعاً جديداً على GitHub.
2. ارفع **محتويات هذا المجلد** إلى جذر المستودع، وليس ملف ZIP نفسه.
3. تأكد أن `pyproject.toml` و`src/` و`.github/` ظاهرة في الصفحة الرئيسية للمستودع.
4. افتح تبويب **Actions**.
5. اختر **Build SecureCaseDesk APK and EXE**.
6. اضغط **Run workflow** ثم **Run workflow** مرة أخرى.
7. انتظر انتهاء مهمتي Android وWindows بنجاح.
8. افتح صفحة تشغيل workflow المكتمل، ثم نزّل:
   - `SecureCaseDesk-Android-APK`
   - `SecureCaseDesk-Windows`

يمكن أيضاً تشغيل البناء تلقائياً عند كل push إلى فرع `main` أو `master`.

## تشغيل محلي للتجربة

Python 3.12:

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
python -m pip install -r requirements.txt
python src/main.py
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python src/main.py
```

## ملاحظات مهمة

- ملف Windows الناتج من Flet هو مجلد تطبيق يحتوي على EXE ومكتباته وملفات التشغيل. نزّل الأرشيف كاملاً واستخرج محتوياته؛ لا تنقل EXE وحده خارج المجلد.
- APK الناتج نسخة Release غير موقعة بمفتاح نشر خاص بك. Android قد يعرض تحذيراً عند تثبيته من خارج المتجر.
- لا تضع مفاتيح توقيع Android أو كلمات المرور أو بيانات القضايا في GitHub.
- قاعدة بيانات التطبيق ومجلد المرفقات محلية على الجهاز. تثبيت التطبيق على جهاز آخر لا ينقل بيانات الجهاز الأول.
- هذا المشروع لا يفعّل مزامنة سحابية ولا يجعل GitHub مستودعاً لبيانات القضايا.
- يجب اختبار APK وWindows build فعلياً قبل إدخال بيانات تشغيلية حساسة.

## البناء

يستخدم GitHub Actions الإجراء الرسمي `flet-dev/flet-build-action@v1` لبناء `apk` و`windows` على runners مناسبة لكل منصة.
