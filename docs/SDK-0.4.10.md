# التحقق من SDK الكور 0.4.10

تاريخ التحقق: 2026-10-08. المستودع: `noorelmostafa11-pixel/VPN-Core-Test`.
الأساس: `281a03a885cadbf4936f9f0727553b9c23311d1f` (0.4.9).
هذه نتائج محلية؛ لم يُشغّل GitHub Actions أو اختبار عقد عامة لهذه الإضافة.

## الإضافة وحفظ الدعم

| المكون والمسار | النتيجة | الدليل والحدود |
| --- | --- | --- |
| `src/udp-relay.hpp` و`src/udp-protocol.hpp` | SOCKS5 UDP ASSOCIATE، ونقل DNS عبر البروكسي، للبروتوكولات الأربعة | `RUNTIME_OBSERVED` على Linux بأقران مستقلين وخادم Xray مرجعي محلي |
| `src/core-api.h` و`src/network-hooks.hpp` و`tls-provider/socket_hooks.go` | ABI 2، حماية sockets، bootstrap DNS، حالة التشغيل والمنفذ الفعلي؛ ABI 1 محفوظ | تشغيل/إيقاف/إعادة تشغيل ورفض callbacks اختُبرت على Linux |
| `sdk/android` و`scripts/Package-Android.py` | JNI وAAR للمعماريات الأربع وحزمة مجمعة | بناء NDK وفحص ELF والهاشات؛ ليس اختبار جهاز Android |
| `sdk/windows/VpnCore.cs` | واجهة دمج .NET 6+ مع DLL الكور | ترجمة وتشغيل adapter على Linux؛ تشغيل Windows نفسه غير متحقق |

ملفات Pre المستخدمة هي ملفات `VPN-Nodes-Pre@b228d3adb5057d5135c5ecbb7f0bdc843baf3a5d`
نفسها الموثقة بهاشاتها في [SUPPORT-0.4.9.md](SUPPORT-0.4.9.md).
مقارنة JSON كاملة لكل 71,656 مدخلًا مع 0.4.9: **صفر صفوف فحص متغيرة**؛
70,917 إعدادًا مدعومًا و739 إعدادًا غير صالح. URI الأصلية والقيم وهويات العقد
ودعم TCP محفوظة. هذه أرقام فحص إعدادات، وليست أعداد عقد ناجحة على الإنترنت.

## الاختبارات المنفذة

- حزمة المصدر وإعادة الاختبارات المتأثرة: 229 حالة ناجحة؛ اختبارا Trojan
  المرجعيان الخارجيان مستثنيان لعدم توفير الخادم المطلوب لهما. أعيد اختبار
  رقم إصدار تقرير الدفعات بعد تحديثه إلى 0.4.10.
- آخر بناء Linux للإنتاج: 15 حالة ناجحة تشمل UDP وcallbacks والنقل وواجهة C؛
  self-test وفحص ABI المكونات والهاشات ناجحة.
- UDP مستقل: 29 طريقة Shadowsocks؛ تأطير VLESS وTrojan عبر raw وWebSocket
  وHTTP Upgrade وgRPC؛ الحفاظ على حدود الحزم والتحقق من SS2022 identity/replay
  والرفض الصحيح للـfragments والمصادر الأجنبية.
- Xray 26.3.27 كخادم اختبار محلي فقط: 16 تركيبًا ناجحًا تشمل VLESS وVision
  وXHTTP وTrojan وVMess بأربع طرق وShadowsocks AEAD/SS2022. Xray ليس محرك الكور
  ولا تبعية تشغيل أو بناء له.
- رفض حماية socket يمنع الاتصالات في C++ وHTTP/2 وXHTTP وHTTP/3 وQUIC وmKCP،
  وفي ECH عبر DNS UDP/TCP وDoT وDoH. لا bypass بعد رفض callback.
- `go test -race ./...` ناجح. Java/JNI و.NET اجتازا تشغيلًا فعليًا على Linux
  يشمل UTF-8 paths، callback exceptions، العمر الصحيح للـcallbacks وإعادة التشغيل.
- Android NDK `30.0.16248370` مع Go `1.27.1`: بناء `arm64-v8a` و`armeabi-v7a`
  و`x86_64` و`x86` ناجح؛ كل بناء يتضمن core/provider/JNI وAAR، وفحوص ELF
  والمعمارية ومحاذاة 16 KiB والهاشات ناجحة. مصدر الأبنية الخمسة متطابق:
  `1d305e2596aa15bd8ed4b010d66c7b456b1aae04960a9d6ff4cd4a5152108bc2`.
- المصدر الأصلي لـWindows اجتاز فحص C++ syntax باستخدام MinGW 13.2؛ هذا لا
  يُثبت بناء الإنتاج المثبت على GCC 16.2 أو تشغيل DLL على Windows.

## حدود الإصدار

لا يوجد TUN inbound أو API لاستقبال حزم IP الخام. التطبيق يتولى TUN وVpnService
والمسارات وطبقة TUN-to-SOCKS. يلزم التحقق من هذه الطبقة داخل التطبيق وعلى الأجهزة؛
لم يُبنَ APK ولم يُشغّل emulator في هذه المهمة. Windows runtime وAndroid device
runtime وقياسات السرعة والاستهلاك غير متحققة هنا.

RFC 1928 fragments لا يعاد تجميعها. VMess لا يرسل payload فارغًا لأن chunk فارغًا
يعني EOF؛ الوجهة المتوقفة أو جلسة VMess التي استنفدت nonce تُغلق، وتفتح الحزمة
التالية جلسة جديدة. SIP003 plugins تغلف TCP فقط، لذلك يلزم UDP مباشر في خادم
Shadowsocks. التفاصيل وعقد التكامل في [SDK-INTEGRATION.md](SDK-INTEGRATION.md).
