# مراجعة 0.4.11 وحدود الاعتماد

## تصحيح نتيجة Windows بتاريخ 2026-10-08

الرن [37771444330](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/37771444330)
اختبر `7d1784ed59aeabbec96732a450a79690d3fdb8ba`. نجحت Linux: الجولة الكاملة
250 حالة (248 نجاحًا و2 skipped)، ثم 15 حالة قبول إنتاج منفصلة. نجح بناء Windows
واختبارا PowerShell، لكن اختبار SDK أبلغ عن مهلة UDP في `table` و`rc4`، وعن
فشل معيار عدد Handles في اختباري bootstrap DNS وVLESS half-close. مسار الاتصال
المستقل أثناء DNS المعلقة وStop وعودة run_config نجح قبل فحص Handles.

التصحيح يجعل `random_bytes(0)` ترجع مصفوفة فارغة دون طلب entropy؛ `table` و`rc4`
لا يستخدمان IV. اختبار عقد CNG الصارم يرفض الطلب الفارغ ويثبت أن الطلب غير الفارغ
وفشل RNG ما زالا يمران عبر نفس المسار. هذا اختبار فرع CNG بعقد بديلة على Linux،
وليس تشغيل DLL فعلية على Windows. اختبارات UDP تحتفظ بسجل الكور عند الفشل.

عداد Handles القديم كان يحسب عملية Python كاملة بعد دورة واحدة، دون انتظار
كل handlers لسيرفر الاختبار. كما أن Go المثبت يحتفظ بأحداث ومؤقتات extra-M لإعادة
الاستخدام (`runtime/os_windows.go`: semacreate/minit؛ `runtime/proc.go`: dropm).
لا يثبت ذلك وحده أن زيادة الرن المذكور مجرد caching أو أنها تسريب.
الاختبار المعدل ينتظر خروج handlers، ثم يشترط ثلاث قراءات متطابقة بعد دورات عمل
كاملة ضمن سقف 8 دورات warmup. بعدها يثبت نفس المرجع ويختبر 12 دورة إضافية؛ لا
ترتفع العتبة عند زيادة Handles أو Threads، ولا توجد سماحية عددية أو GC إجباري أو
قتل Threads. يطبع السلسلة كاملة، ويفشل إذا لم تستقر الموارد أو إذا استمرت الزيادة.
اختبار حقن تسريب sockets فعلية يثبت رفض النمو أثناء warmup.

بعد التصحيح، نجحت محليًا جولة Linux الكاملة: **252 حالة، 250 نجاحًا و2 skipped**،
مع Go race tests. تشمل الجولة اختبار عقد CNG ورفض تسريب sockets المتعمد، ونقل
TCP وUDP ودورات DNS وhalf-close. أعاد اختبار CNG الصارم إنتاج خطأ RNG على السورس
السابق، ثم نجح بعد التصحيح. هذه نتيجة تنفيذ محلي؛ ليست نتيجة GitHub CI جديدة.

تشغيل Windows الأصلي بعد هذا التصحيح **NOT_VERIFIED** إلى أن يُشغّل المستخدم
Core Source Validation على الكوميت المصحح. لا يُعاد تشغيل Workflow تلقائيًا.
الأرقام والقياسات في بقية هذا التقرير تخص الجولة السابقة الموضحة فيه.

الإصلاحات إضافية؛ لا حذف لبروتوكول أو إعادة كتابة للرابط الأصلي أو تغيير لحقول
العقد كي ينجح الاختبار. ABI 1 وواجهات ABI 2 القديمة باقية. لا TUN inbound جديد.

| المشكلة | الإصلاح | دليل القبول الموجود في السورس |
| --- | --- | --- |
| انتظار DNS بلا مهلة | مهلة للانتظار، استجابة لـStop، وسقف 16 job بما فيها الطلبات المنتهية مهلتها | أول callback معلقة والثانية ترجع لنفس عنوان خادم العقدة؛ الثانية تنقل بيانات على نفس تشغيل الكور |
| callbacks تحت mutex | snapshot وlease تحت قفل قصير، والتنفيذ خارجه؛ drain لا يحتفظ بالقفل | نفس الحالة في TCP الخام وفي HTTP/2 عبر مزوّد Go، واختبار registry تحت Go race detector |
| موارد callback بعد Stop | `run_config` يظل STOPPING حتى رجوع جميع callbacks؛ buffers وuser/JNI/.NET مضمونة العمر؛ WSA يظل حيًا حتى drain | رفض التشغيل الثاني، توقف القبول والنقل القابل للإلغاء، رجوع callback ثم انتهاء run، وصفر leases بعد الإغلاق وتكرار Start/Stop |
| الإغلاق أثناء SOCKS/TLS/الاتصالات | انتظار sockets على فترات قصيرة، وإلغاء contexts الخاصة بالمزوّد، وإلغاء أثناء unwinding قبل join | Stop أثناء عميل SOCKS صامت وTLS صامت واتصال ناجح؛ الإلغاء قبل مهلة الاتصال |
| تراكم TCP بدون TLS | إرسال half-close قبل انتظار خادم ينتظر FIN؛ منعه بعد الإرسال الأول | 8 اتصالات VLESS فعلية، آخر payload والرد ثم EOF؛ الموارد تعود بعد كل دورة |
| Error API ناقصة | queue ذات 256 حدثًا، connection ID وأسباب/native/HTTP status؛ قراءتها من C/Java/.NET | قياس buffer دون استهلاك، هوية الاتصال، حجب URI/credential، واختبار JNI للأخطاء |
| صمت UDP | `udp_response_timeout_ms` اختياري، `UDP_NO_RESPONSE` وتشخيص أخطاء النقل | سيرفر صامت لا يتحول إلى UNSUPPORTED؛ TCP وUDP يختبران معًا |
| حماية sockets غير مثبتة | الاختبار أمام خادم reachable ثم رفض callback قبل أي اتصال/إرسال | نقل Shadowsocks UDP عند السماح وصفر وصول عند الرفض؛ رفض TCP وHTTP عبر المزوّد أمام خادم مستمع |
| DNS وIPv6 | اختبارات DNS فعلية، لا ردود A/AAAA مزيفة داخل الكور | A وAAAA عبر VLESS UDP إلى responder مستقل، وDNS destination IPv6 `::1` |
| حزمة الإصدار ومصدرها | NDK-NOTICE قبل AAR، commit فعلي وبصمة السورس وdirty flag، تحقق hashes قبل ZIP | رفض byte فاسد وmanifest مختلف وnotice ناقص؛ fixture AAR مع javac حقيقي وprovenance؛ بناء الإنتاج يرفض المصدر غير النظيف |

التفاصيل التعاقدية في [SDK-INTEGRATION.md](SDK-INTEGRATION.md). callback متزامنة
لا تستجيب للإلغاء يمكن أن تبقى نشطة بلا حد؛ نلغي انتظار الطلب ولا نقتل thread.
لا يرجع `run_config` قبل انتهائها. التطبيق يحافظ على مواردها حتى join، ويحافظ
على تحميل core/provider طوال عمر العملية. لا توجد ضمانة مهلة نهائية لـStop
تشمل كودًا معلقًا يملكه التطبيق.

## الأدلة المحلية وحدودها

- حصر 71,755 رابطًا من الملفات الأربعة قورن مع 0.4.10
  `bb123707dd74e89b9b44e565ba9aa6b119d46f2b`: صفر اختلاف في كامل JSON القراءة
  والإعدادات، وليس مجرد مقارنة أعداد. الحصر لا يثبت اتصال عقد الإنترنت.
- الجولة الكاملة أثناء التطوير شغلت 245 حالة: لا فشل، وحالتا Trojan اختياريتان
  متخطيتان لغياب السيرفر الخارجي. الإضافات التالية لها اختبارات مستقلة ناجحة؛
  قائمة القبول النهائية تحتوي 249 حالة. نتيجة الجولة النهائية وSHA الدقيق يجب
  الرجوع إليهما في تقرير التحقق المرتبط بالبناء، لا جمع أعداد جولات مختلفة.
- بناء Linux الإنتاجي، TCP وUDP وDNS وlifecycle، وJNI على JDK 17 في Linux
  نجحوا محليًا. نجاح JNI على Linux لا يثبت Android/VpnService.
- Go race detector نجح؛ اختبار AAR هنا يجمع Java فعليًا لكنه يستعمل native
  fixture صريحة، ولا يثبت تشغيل مكتبات Android.
- قياس أول نقل TCP وUDP وCPU/RSS وthreads/fds يستخدم
  `scripts/Measure-Core.py`. تجربة 30 دورة محلية قارنت 0.4.10 بالجديد:
  الجديد لم يسجل EOF timeout، وظلت threads/fds عند 7/7 بعد warmup. القديم
  سجل 31 EOF timeout (يشمل warmup) ووصل إلى 35 threads و63 fds. هذا يثبت
  أثر إصلاح الإغلاق في هذا السيناريو فقط. فروق زمن الاتصال القصيرة لا تثبت
  زيادة السرعة على الإنترنت أو على Windows.

تشغيل الجولة النظيفة على الكوميت المراد اعتماده:

```sh
export VPN_CORE_POWERSHELL=/absolute/path/to/pwsh
export JAVA_HOME=/absolute/path/to/jdk17
bash scripts/build-linux-tests.sh
python scripts/Build.py --target linux --build-tests --require-clean
PYTHONPATH=tests VPN_CORE_TEST_BINARY="$PWD/build/linux-amd64/vpn-core" \
  python -m unittest -v test_portable_044.PortableTransportTests \
  test_portable_044.SharedCoreTests test_udp_sdk.UdpSdkTests \
  test_udp_sdk.NetworkHookTests test_lifecycle_acceptance.LifecycleAcceptanceTests \
  test_dns_acceptance.DnsAcceptanceTests
python scripts/Test-Sdk-Bindings.py --build build/linux-amd64 --java-only
python scripts/Package-Target.py --build build/linux-amd64
```

## بوابات لم تُثبت في هذه البيئة

| البوابة | الحالة وحدود الدليل |
| --- | --- |
| CI على الكوميت النهائي | NOT_RUN؛ جميع Workflows يدوية، لا dispatch ضمن التنفيذ الحالي |
| Windows DLL و.NET على Windows | NOT_VERIFIED؛ أوامر البناء واختبارات TCP/UDP والدورات والأخطاء مجهزة في Workflows، وتشغيلها الفعلي مطلوب |
| Android ABIs/AAR الجديدة على NDK والجهاز | NOT_VERIFIED؛ NDK والجهاز غير متاحين هنا؛ لا استنتاج من بناء سابق أو JNI في Linux |
| تطبيق Android مستقل وRelease/VpnService | NOT_VERIFIED؛ يحتاج تطبيق مضيف وخدمة VPN واختبار على Android |
| TUN-to-SOCKS مع Wintun/VpnService في الاتجاهين | NOT_VERIFIED؛ خارج الكور ويحتاج الطبقة المضيفة الفعلية |
| منع التسريب واستعادة routes/DNS عند الأعطال | NOT_VERIFIED؛ اختبار DNS عبر SOCKS لا يقوم مقام فحص واجهات الشبكة ونظام التشغيل عند سقوط المكونات |
| Connect Windows ومقارنة 0.4.7 | NOT_VERIFIED؛ النسخة المرجعية القديمة محفوظة ولم تستبدل؛ القياس المحلي المرجعي هنا 0.4.10 Linux |

هذه بوابات اعتماد للإصدار على التطبيقات؛ لا يوصف الإصدار بأنه جاهز لها بمجرد
Build أو بعدد الحالات المحلية. لا إعادة تصميم للكور ولا استبدال لدعم سابق.

## قرارات التخزين وتشغيل العقد المحفوظة

`main` يحتفظ بالسورس والتراخيص وأدلة التحقق؛ نواتج البناء تبقى خارج Git. بناء
الهدف المطلوب ممكن من Clone على اللاب. كل Workflow يدوي. اختبار العقد يبني
revision واحدًا، والافتراضي Linux، ثم يجلب أحدث Pre مرة واحدة ويثبت الملفات
لكل الشاردات. الردود 2xx مقبولة بعد نجاح TLS، والروابط الأصلية محفوظة.

ملفات runtime/Pre والحزم مؤقتة يومًا؛ تقارير التحقق والشاردات 14 يومًا؛ تقارير
التجميع 30 يومًا. تنظيف القديم يتطلب تشغيل workflow التنظيف preview/apply؛
لم تحذف artifacts فعلية خلال هذا التنفيذ. الرنز الجارية وReleases المرجعية
محفوظة؛ لا نشر Release تلقائي بعد Build. نسخة Windows المرجعية تبقى كما هي
حتى تثبت النسخة الجديدة في التطبيق.
