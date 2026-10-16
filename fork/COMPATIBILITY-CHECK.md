# تشغيل فحص التوافق يدويًا

1. افتح [Actions → Build & Test](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/workflows/core-validation.yml).
2. اضغط **Run workflow**.
3. من **Use workflow from** اختر **feature/xray-custom-core**، وليس main.
4. اضغط **Run workflow** لبدء الفحص بنفسك.
5. افتح التشغيل الذي يبدأ اسمه **Xray compatibility**، ثم نتائج Windows وLinux وmacOS.

نفس اسم الصفحة موجود من المشروع القديم؛ نسخة الفحص الموجودة في الفرع الجديد
مختلفة ومخصصة لكور Xray. استخدام نفس مسار الملف يتيح اختيار الفرع من صفحة
التشغيل الموجودة أصلًا، من غير تعديل main. اختيار main يشغّل فحص المشروع القديم.

## ماذا يفحص؟

- جميع اختبارات Go الموجودة في المستودع، مع اكتشاف تضارب الذاكرة، دون الاكتفاء
  بالملفات المعدلة. السجل يحتفظ بالنجاح والفشل والحالات المتخطاة كما هي.
- الفحص الثابت لجميع حزم الكور.
- توافق TCP وUDP بين الفرع ونسخة main المثبتة في manifest، بالاتجاهين، للأسماء
  التقليدية الـ32 في Shadowsocks: 64 حالة، 128 نقل TCP و576 حزمة UDP.
- النتائج منفصلة على Windows وLinux وmacOS، في تشغيل فعلي على كل نظام.

بعد التشغيل، صفحة **Summary** تعرض مراحل الفحص ونتائجها وعدد الحزم الناجحة
والفاشلة وقائمة الاختبارات المتخطاة. تفاصيل كل خطوة موجودة في السجل. مرفقات
**compatibility-report** تحتوي تقارير الاختبارات فقط؛ لا تحتوي نسخ تشغيل أو SDK.

لا يوجد تشغيل تلقائي عند الرفع، أو تجهيز Android، أو حزم تنزيل، أو نشر Release.
صاحب المشروع هو الذي يبدأ الفحص. لا توجد إعادة لمحاولات فحص البروتوكول حتى تنجح؛
الفشل يظل فشلًا، والأدلة الناقصة لا تظهر كنجاح. فشل نظام لا يلغي اختبار البقية.

## حدود النتيجة

النجاح يعني أن الاختبارات الحالية مرت؛ لا يعني اكتمال ميزات لم تُنقل بعد أو أن
كل العقد الخاصة تعمل على الإنترنت. SS2022-main يحتاج فحص توافق منفصل بمفاتيحه،
والـSDK الخاص بتطبيق الموبايل وباقي النواقص موضحة في [COMPARISON.md](COMPARISON.md).
نتائج هذه الأنظمة ليست اختبار Android ولا اختبار دمج التطبيق.

## Reproducibility and implementation

This manual-only file deliberately shares the already registered default-branch
workflow path. Main is not changed and its native-engine jobs are not reused.
Actions checkout/setup/upload dependencies are pinned to commit SHAs. Go1.27.1
is explicit; race prerequisites fail visibly rather than disabling race checks.
GeoIP/GeoSite data are pinned to Loyalsoldier commit
`a2d310e1de9ba35757f1633dda231192d114a306` and checked against fixed SHA256 values
before tests. Reference main is checked out at the manifest's exact commit,
not a moving branch. Both source checkouts are read-only to the wire fixture.

The new executable orchestration is Go (`fork/check`); YAML is workflow metadata.
No Python/PowerShell implementation is added. Go tests necessarily compile their
test targets; any subprocess peers used for wire exchanges live only in test
temporary directories. They are not packaged, published or included in reports.
Reports distinguish full-suite status, skipped tests, static checks and the
32-name wire scope, without presenting missing capability as verified parity.
