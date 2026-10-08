# إضافات الدعم في 0.4.7

تنفيذ إضافي داخل الكور، مع استمرار تنفيذ البروتوكولات الأربعة المملوك للمشروع. لم يُضمّن محرك Xray أو V2Ray، ولم يُستبدل اختبار الاتصال بتغيير علامة `SUPPORTED`.

| المسار | التنفيذ المضاف | التحقق المستقل |
| --- | --- | --- |
| mKCP | ترويسات SRTP وuTP وWireGuard وDTLS وWeChat-video وDNS، مع احتساب حجمها في MTU | قرين UDP بلغة Python؛ البروتوكولات الأربعة، seed، TLS، فقد وترتيب الحزم |
| HTTP/2 | نقل cleartext عبر h2c بدل رفضه مبكرًا | خادم HTTP/2 مستقل؛ البروتوكولات الأربعة واتصالان متوازيان |
| QUIC | stream، وتشفير الحزمة none/AES-128-GCM/ChaCha20-Poly1305، والترويسات؛ حقول VMess JSON القديمة host/path | خادم QUIC مستقل يمرر البيانات إلى أقران البروتوكولات؛ native/Chrome/Firefox |
| v2ray-plugin | وضع QUIC، وcert/‏certRaw، مع استمرار WebSocket وMux الموجودين | اتصال ونقل بيانات، رفض الاسم والشهادة الخاطئين، أولوية cert على certRaw |
| simple-obfs / obfs-local | HTTP وTLS obfuscation | قرين مستقل يقرأ الترويسات ويرسل سجلات مجزأة؛ Shadowsocks AEAD |
| Shadowsocks | 15 خوارزمية stream قديمة، وXChaCha20-IETF-Poly1305 | PyCryptodome وcryptography، نقل 65,539 بايت واتصالان لكل خوارزمية، ورفض tag خاطئ |

الخوارزميات القديمة المضافة: `camellia-128-cfb` و`camellia-192-cfb` و`camellia-256-cfb` و`bf-cfb` و`cast5-cfb` و`des-cfb` و`idea-cfb` و`rc2-cfb` و`seed-cfb` و`rc4` و`rc4-md5` و`salsa20` و`chacha20` و`chacha20-ietf` و`table`. يحتفظ ChaCha20 الأصلي بعدّاد 64-bit؛ اختبار مستقل يغطي الانتقال بعد 256 GiB دون إرسال هذا الحجم. مسارات AES القديمة وAEAD وSS2022 الموجودة مستمرة.

الترويسات الجديدة تسبق تشفير حزمة mKCP على السلك، وفكها يسبق فك الحزمة. تنفيذ TLS داخل simple-obfs تمويه وفق صيغة ذلك plugin؛ التحقق من شهادات TLS الحقيقية مستمر. QUIC يحافظ على التحقق من الشهادة والاسم، بما في ذلك وضعه الداخلي؛ لا تُضاف آلية لتجاوز شهادة ذاتية التوقيع غير موثوقة. `cert` و`certRaw` يختاران جذور plugin دون دمج جذور INI أو الاختبار معها.

## مقارنة Pre دون حذف

ملفات `VPN-Nodes-Pre` المفحوصة مأخوذة من commit `b228d3adb5057d5135c5ecbb7f0bdc843baf3a5d` يوم 8 أكتوبر 2026. الفحص يشمل كل سطر ويتحقق من بايتات المصدر وSHA256 وهوية العقدة. مرجع المقارنة كور 0.4.6 عند `07d534f6f4ffe6553c7d5fb1cc8431c9cfd1ff75`.

| النتيجة | قبل | بعد |
| --- | ---: | ---: |
| جميع الروابط | 71,656 | 71,656 |
| SUPPORTED في فحص الإعدادات | 70,684 | 70,754 |
| INVALID في فحص الإعدادات | 972 | 902 |
| UNSUPPORTED | 0 | 0 |
| فقد دعم سابق | — | 0 |
| تغيّر هوية رابط أو حذفه | — | 0 |

الزيادة 70 إعداد HTTP/2 بدون TLS كان يُرفض بسبب شرط الكور السابق. النتائج هنا **حصر إعدادات**، ولا تعني نجاح 70,754 عقدة على الإنترنت. الإدخالات غير الصالحة تبقى مسجلة في التقارير، مع سبب رفضها؛ لا تُحذف من ملفات المصدر. لا تُطبع روابط Pre أو بيانات اعتمادها في أدلة هذا التعديل.

تشغيل main يستمر في تحميل أحدث commit من Pre مرة واحدة لكل تشغيل، واستخدام ملفاته الأربعة ذاتها للفحص والشاردات. هذه اللقطة دليل المقارنة لهذا التعديل؛ لا تحل محل التحميل الديناميكي.

## التحقق وحدوده

النتائج الرقمية والهاشات محفوظة في [support-additions-0.4.7.json](support-additions-0.4.7.json). تشمل فحص Go مع race، و1,024 تجربة بصمات TLS عشوائية، واختبارات Linux وPowerShell المحلية، وبناء Linux للإنتاج واختبار إضافاته وواجهة C، مع بقاء الشهادة الخاطئة مرفوضة.

لإعادة فحص السورس على Linux: `bash scripts/build-linux-tests.sh`. لإعادة اختبار الإضافات على الإنتاج بعد البناء، اضبط `PYTHONPATH=tests` و`VPN_CORE_TEST_BINARY` إلى ملف الإنتاج و`VPN_CORE_TEST_PRODUCTION=1`، ثم شغّل `test_support_additions.SupportAdditionTests` و`test_quic_carrier.QUICCarrierTests` و`test_mkcp.MKCPTests` عبر unittest. الأدوات المثبتة وتبعيات الاختبار مطلوبة كما في BUILDING.md.

بناء Windows وAndroid لهذا التعديل وتشغيل جهاز Android لم يُتحققا في هذه الجلسة. لم يُشغّل أي GitHub workflow. مقارنة عقد Public الناجحة في Xray، وقياس السرعة واستهلاك CPU/RAM، تحتاج مدخلاتها وتجربة مستقلة؛ لا تثبتها اختبارات الدعم المحلية. وسائل النقل الأخرى غير الموجودة في ملفات Pre المفحوصة ليست مشمولة بادعاء هذا الإصدار.

مصادر primitives المختارة وSHAs وتراخيصها في `tls-provider/thirdparty/sources.json`؛ حزم الأهداف تحفظ هذه التراخيص. صيغ plugin مرجعها [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin) و[simple-obfs](https://github.com/shadowsocks/simple-obfs)؛ التنفيذ المضاف خاص بالمشروع.
