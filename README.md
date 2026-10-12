# vpn-core — main

هذا الفرع يحتفظ بالكور الأصلي 0.4.11: محرك C++ مع مكونات TLS/QUIC في Go.
نسخة Go الكاملة مع TUN الداخلي موجودة في
[feature/go-native-core](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/tree/feature/go-native-core).
تنظيف هذا الفرع لا يغيّر كود المحرك أو دعم بروتوكولاته.

## البناء والاختبار من GitHub

افتح **Actions → Build & Test → Run workflow**، ثم اختر الفرع فقط:

- `main`: بناء واختبار الكور الأصلي على Windows وLinux، وبناء Android ARM64.
- `feature/go-native-core`: اختبار Go على Windows وLinux وmacOS، وبناء الأهداف المحمولة وAndroid ARM64 AAR.

لا توجد اختيارات إضافية للمعمارية أو الشاردات أو تنظيف الملفات في شاشة Run.
يبدأ الفحص أيضًا عند رفع تغيير إلى أحد الفرعين. الحزم متاحة في Artifacts؛
لا يحدث نشر Release أو دمج بين الفرعين تلقائيًا.

## البناء محليًا

```text
python scripts/Build.py --target windows
python scripts/Build.py --target linux
python scripts/Package-Target.py --build build/windows-amd64
```

الأدوات المثبتة في `scripts/toolchains.json`. راجع
[دليل البناء](docs/BUILDING.md)، و[SDK](docs/SDK-INTEGRATION.md)،
و[المكونات](docs/COMPONENTS.md). مصادر المحرك والاختبارات والتراخيص محفوظة؛
التقارير المتراكمة للنسخ القديمة متاحة في تاريخ Git.

فحص العقد العامة اختياري ومحلي بواسطة `scripts/Test-Nodes.py`؛ لا يدخل في
التشغيل الافتراضي. مدخلات اللقطات والمقارنة اللازمة محفوظة مع التحقق من هاشها.
