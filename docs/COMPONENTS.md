# المكونات المثبتة والتعديلات

تنفيذ SOCKS والتوجيه وتأطير VPN وVision وFinalMask وMuxCool وmKCP وتشفير VLESS موجود في سورس المشروع. مكتبات TLS وQUIC وHTTP والتشفير أدناه مكونات داخل المحرك. الأقران في `tests` مخصصة للتحقق؛ لا تُبنى ضمن ملف التشغيل. المصادر المرجعية لمحركات VPN لم تُضمّن في الحزمة أو go.mod.

| المكون | النسخة المثبتة | الاستخدام |
| --- | --- | --- |
| Go | 1.27.1 | toolchain والتشفير القياسي وML-KEM/ML-DSA |
| uTLS | commit 88ba76ae4ee304e4d12e738b5e156a16ee6fe542 | TLS والبصمات وECH وQUIC TLS primitives |
| quic-go | 0.63.0 | QUIC وHTTP/3 |
| qpack | 0.6.0 | HTTP/3 header compression |
| golang.org/x/net | 0.59.0 | HTTP/2 |
| golang.org/x/crypto | 0.57.0 | crypto primitives المستوردة |
| golang.org/x/sys | 0.48.0 | واجهات النظام |
| golang.org/x/text | 0.42.0 | تبعيات HTTP |
| brotli | 1.2.6 | تبعية uTLS |
| klauspost/compress | 1.20.1 | تبعية uTLS |
| blake3 | 1.4.1 | KDF في تشفير VLESS ومراجع Go |
| klauspost/cpuid/v2 | 2.0.9 | تبعية BLAKE3 |

الإصدارات وchecksums الكاملة في `tls-provider/go.mod` و`go.sum`، والسورس المثبت والتراخيص في `tls-provider/vendor`. ترخيص Go وMinGW/GCC runtime في `third_party`. نسخة Android تحفظ NOTICE الخاص بالـNDK مع الملفات المبنية وتراخيص vendor. OpenSSL يستخدم في محول Linux للاختبار؛ ملفات Windows لا تستورد OpenSSL. أهداف Linux/Android للإنتاج تستخدم المزوّد المثبت وواجهات primitives من مكتبات Go القياسية. معمارية NDK وإصدارها في `scripts/toolchains.json`.

توجد تسعة ملفات معدّلة في المكونات، مع SHA-256 للأصل والبديل في `tls-provider/component-patches/manifest.json`. ملفات replacement هي المصدر المعتمد لإعادة تطبيق التعديلات. سكربتا Apply-Component-Patches يرفضان محتوى لا يطابق الأصل أو البديل المثبت.

| الملفات | الغرض والدليل |
| --- | --- |
| quic-go crypto_setup.go وuTLS u_quic.go | جسر QUIC TLS لتوفير ClientHello المشروع؛ اختبارات HTTP/3 بالتحقق الكامل من الشهادة والاسم. |
| project_records.go | primitives تسلسل وفك سجلات TLS لدعم XTLS القديم؛ اختبارات مستقلة للتحول وسجلات الإغلاق. |
| u_conn.go وu_handshake_client.go وhandshake_client_tls13.go | نقل ECH inner/outer transcript في native والمتصفح وHRR؛ اختبارات ECH/CV/Finished إيجابية وسلبية. |
| key_schedule.go وu_public.go وu_parrots.go | حفظ private key لكل classical key share واختيار المفتاح لمجموعة الخادم؛ اختبار Firefox/P-256 وHRR. |

`go mod vendor` يعيد محتوى upstream؛ يجب تطبيق البدائل وفحصها قبل البناء بعده. المسار المعتاد للبناء يطبقها تلقائيًا.

فحص govulncheck 1.8.0 بمستوى symbol أعاد **صفر نتائج لرموز مستوردة متأثرة**، مع تنبيه واحد على مستوى module: `GO-2026-5932` يخص OpenPGP غير المستورد من x/crypto. النتيجة ليست إعلانًا بخلو كل السورس من الثغرات. نسخة قاعدة بيانات الفحص وtrace في `component-security.json` والتقرير الكامل.
