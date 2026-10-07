# مصادر صيغ البروتوكول — تحقق 6 أكتوبر 2026

مصادر الصيغ استُخدمت لدراسة الرسائل والتوافق. تنفيذ المحرك في src وملفات المشروع أصل مستقل، ولا تضم الحزمة سورس محرك VPN مرجعي. ملفات البحث نفسها منفصلة عن السورس ولا تُشحن. سجل بايتات المصادر المرجعية المتاحة في هذه الجلسة في protocol-reference-sha256.json؛ تطابق Git blob موضح عندما توفرت له قائمة مصدر مثبتة.

| المجال | المصدر | النطاق والحدود |
| --- | --- | --- |
| Pre | [لقطة الملفات](https://github.com/noorelmostafa11-pixel/VPN-Nodes-Pre/tree/bd491d8e688d9bbbd910f3c48d1627e5886159b9/output/protocols) | حجم وعدد وSHA-256 في pre-source-manifest.json؛ لا إثبات لاستمرار اتصال العقد. |
| Public parser | [لقطة Public السابقة](https://github.com/noorelmostafa11-pixel/VPN-Nodes/tree/ee4651476912c5829c4a2c019606c7b1730cbe1b) | تفسير aliases والخيارات غير الفعالة وصيغ VMess/URI. |
| Trojan | [المواصفة الرسمية](https://trojan-gfw.github.io/trojan/protocol) | تأطير TCP واختبار خادم Trojan1.16.0 منفصل. |
| VMess | [V2Fly specification](https://www.v2fly.org/developer/protocols/vmess.html) | AEAD وMD5 legacy، KDF/header/body؛ الاختبارات تثبت التنفيذ المحلي. |
| Shadowsocks | [AEAD](https://shadowsocks.org/doc/aead.html) و[SIP022](https://shadowsocks.org/doc/sip022.html) و[SIP023 EIH](https://shadowsocks.org/doc/sip023.html) | AEAD2017/SS2022 والإثبات التفاضلي. سجل البحث يحدد بايتات النص المقروء بدل نسبة محتوى إلى main متغير. |
| VLESS/REALITY/Vision/Encryption/XHTTP | [XTLS reference snapshot](https://github.com/XTLS/Xray-core/tree/7da5dae6502b787fc6d903863e9a6c5043d107a2) | قراءة صيغ التأطير والعميل والإعدادات، ثم أقران مستقلة؛ لا تضمين أو fork للمحرك. |
| mKCP/XTLS القديم | [Xray v1.6.5](https://github.com/XTLS/Xray-core/tree/v1.6.5) | صيغ conversation/ARQ والflows القديمة؛ الأجزاء المرجعية غير مضمّنة في سورس المشروع. |
| TLS/Browsers/ECH | [uTLS pinned commit](https://github.com/refraction-networking/utls/tree/88ba76ae4ee304e4d12e738b5e156a16ee6fe542) | مكتبة TLS مسموحة كمكون، مع تسعة تغييرات SHA-256 موثقة واختبارات HRR/CertificateVerify/Finished. |
| HTTP/3 | [quic-go v0.63.0](https://github.com/quic-go/quic-go/tree/v0.63.0) | مكون QUIC/HTTP3 مثبت، واختبارات positive/negative؛ ليس محرك VPN. |
| WebSocket | [RFC6455](https://www.rfc-editor.org/rfc/rfc6455) | Upgrade/framing/masking/fragmentation/control. |
| HTTP/2/HPACK | [RFC9113](https://www.rfc-editor.org/rfc/rfc9113) و[RFC7541](https://www.rfc-editor.org/rfc/rfc7541) | HTTP2/gRPC وتطبيق المشروع، وجدول Huffman المعياري. |
| SOCKS/ChaCha | [RFC1928](https://www.rfc-editor.org/rfc/rfc1928) و[RFC8439](https://www.rfc-editor.org/rfc/rfc8439) | TCP CONNECT وتشفير تفاضلي ومتجهات معيارية. |
| Schannel | [SSPI cipher info](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_cipherinfo) و[SSPI connection info](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo) | مقارنة الكود مع الواجهات وفحص cipher policy في SSPIdouble؛ Windows runtime غير متحقق. |

روابط المعايير تحدد المصدر؛ إثبات التشغيل يخص الاختبارات والتقارير المحلية. محتوى المصدر الذي لم يملك ref ثابتًا يبقى محددًا ببصمة البايتات المحفوظة، ولا يُنسب إلى تحديث main بعد القراءة. الحزمة لا تعدل المكونات الإنتاجية أو تطبيقات Android.
