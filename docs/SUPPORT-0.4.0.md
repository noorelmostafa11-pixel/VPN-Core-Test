# دعم 0.4.0 ونطاق الدليل

الحصر يخص commit Pre `bd491d8e688d9bbbd910f3c48d1627e5886159b9`، مسار `output/protocols`. ميزات جميع الإعدادات الصحيحة في هذه اللقطة منفذة. `pre-census.json` يفصل فحص الميزات عن اختبار الاتصال، و`pre-feature-families.json` يحفظ عدد كل نمط بدون الروابط أو عناوين الخوادم أو بيانات الاعتماد.

| المجال | الأشكال المنفذة | دليل التشغيل المحلي |
| --- | --- | --- |
| VLESS | v0 وUUID، Vision TLS/REALITY، XTLS origin/direct/splice وأشكال udp443 الصحيحة | نقل ثنائي الاتجاه، سجلات TLS داخلية مجزأة، التحول الصحيح للنقل المباشر، رفض padding وتوليفات غير صحيحة. |
| VLESS Encryption | ML-KEM-768/X25519، native/xorpub/random، 1-RTT/0-RTT، relay/padding/tickets | أقران Go/Python مستقلون، authentication/length negatives، tickets، EN+Vision وEN+XHTTP بأوضاعه الثلاثة. |
| VMess | AEAD وalterId 1..65535 القديم، auto/AES-GCM/ChaCha/CFB/none/zero | header authentication/KDF، تأطير الأجسام، differential crypto، نقل متزامن بأقران مستقلة. |
| Shadowsocks | AES-128/192/256-GCM، ChaCha20-Poly1305 aliases، SS2022 AES-128/256/ChaCha وEIH | BLAKE3/KDF، PSK، salt/timestamp/tag/replay، أقران مستقلة وتحقق محتوى. |
| Shadowsocks القديم | AES-128/192/256-CFB/CTR/OFB، none/plain | مرجع cryptography؛ تحقق النقل داخل TLS موثوق. |
| SIP003 | v2ray-plugin WS مع TLS أو بدونه، mux/default=1 ومعدلاته، early data | MuxCool new/keep/end، حدود التأطير، رفض شهادة خاطئة، عدم إعادة إرسال early data. |
| Trojan | TCP CONNECT مع النواقل المناسبة، XTLS القديم | خادم Trojan 1.16.0 منفصل واختبارات تأطير مستقلة. |
| RAW/WS/HTTPUpgrade/gRPC | HTTP header القديم، WS fragmentation/ping/pong/close/early data، Tun/TunMulti | HTTP status، flow control، رفض headers غير الصالحة، نقل كبير ومتزامن. |
| HTTP/2 القديم | aliases http/h2/http2 وPUT duplex عبر TLS | طلب/رد مستقل، TLS/ALPN، رفض التشغيل بدون TLS. |
| XHTTP | auto/packet-up/stream-up/stream-one، metadata/padding/data chunks، split download | HTTP/1.1 وHTTP/2 وHTTP/3، أربعة بروتوكولات، ثلاثة أوضاع، body hash، status/redirect/compression negatives. |
| xmux | حدود العمر والطلبات وإعادة الاستخدام مع عميل HTTP مستقل لكل نفق SOCKS | rotation وحدود queues؛ لا مشاركة HTTP pool بين أنفاق SOCKS المختلفة. concurrency=1 يحقق حدود العميل الدنيا. |
| HTTP/3 | QUIC/TLS1.3 وALPN h3 وبصمات المتصفح | أربعة بروتوكولات وثلاثة أوضاع XHTTP وبصمات native/chrome/firefox، رفض الاسم الخاطئ. لا QUIC 0-RTT. |
| mKCP | data/ACK/command، conversation، ARQ/windows/reorder، header=none، seed AES-GCM أو checksum | فقد وترتيب مقلوب وduplicate، ثمانية أنفاق، رفض tag/conversation، EOF بعد آخر data، read deadline. |
| REALITY | X25519/HKDF/authenticated session، شهادة البروتوكول، CertificateVerify/Finished، ML-DSA-65 | إثبات إيجابي مستقل ورفض مفتاح/شهادة/PQ/CV/Finished غير صحيح. |
| ECH | raw config وDNS HTTPS عبر UDP/TCP/DoT/DoH | native/chrome/firefox، WS/HTTPUpgrade وXHTTP HTTP/2 بجميع الأوضاع، HRR واختيار P-256، رفض config/DNS/TLS غير صالح. |
| TLS fingerprints | chrome/firefox/safari/ios/android/edge/360/qq/random/randomized وnative/unsafe aliases | شهادات موثوقة، اختيار المجموعات، TLS1.2/1.3، 256 seed للبصمة randomized، منع CBC. |
| FinalMask | fragment/ClientHello arrays/chains، lengths/delays/maxSplit، صيغة freedom وinterval القديمة | تطابق البايتات وإعادة تأطير سجلات TLS، ranges، رفض JSON وتوليفات غير صحيحة. |
| Schannel | handshake continuation وSEC_I_RENEGOTIATE، EXTRA/no EXTRA، التحقق من الشهادة والcipher | محاكاة مستقلة لواجهات SSPI؛ Schannel الحقيقي على Windows غير متحقق. |
| Batch | direct .NET processes، exit code/output lifetime، throttling/cancellation/redaction | 14 اختبار PowerShell، وثمانية أنفاق متزامنة فعليًا بHTTPS body hash. |

`auto` في XHTTP يختار الوضع وفق الإعداد والأمان؛ لا يختزل كل الروابط إلى stream-one. ALPN والإعدادات غير الفعالة في ناقل معين تُفسّر حسب محلل الصيغة المرجعي. خيارات السيرفر فقط لا تتحول إلى سلوك عميل مخترع. اختيار h3 مع REALITY يعود إلى HTTP/2 حسب الصيغة المرجعية.

العناصر غير الصالحة الـ1,117 تتضمن UUID/endpoint غير صالح، transport/security/fingerprint/flow/cipher غير مسجل، REALITY keys/short IDs غير صحيحة، JSON غير صالح في XHTTP أو FinalMask، تشفير VLESS غير صالح، وlegacy HTTP/2 بدون TLS. `pre-invalid-reasons.json` يحفظ التصنيف التجميعي. هذه عناصر رفضها المحلل بسبب الصيغة؛ لا تشمل ميزات مسجلة صحيحة أُخفيت بتغيير التصنيف.

العدد صفر ينطبق على هذه اللقطة. ميزات خارجها، مثل طرق Shadowsocks المسجلة الأخرى، compression غير المنفذ، رؤوس mKCP الأخرى، أو UDP FinalMask النشط غير المنفذ، لها خطأ ميزة صريح عند طلبها. ECH على HTTP/3 غير متحقق محليًا؛ لا يوجد إعداد ECH نشط على HTTP/3 في لقطة Pre. خيارات UDP FinalMask غير الفعالة في نقل TCP تُفسّر حسب موقعها، ولا تُعتبر تنفيذًا لقناع UDP نشط.

عدد الأنماط 1,085 لا يعني اختبار اتصال مستقلًا لكل نمط؛ اختبارات التنفيذ تختبر فروع السلوك والتوليفات المهمة. سياسة TLS تمنع الشهادة أو الاسم غير الصحيحين وCBC والإصدارات قبل TLS1.2. دعم إعداد لا يضمن قوة cipher قديم خارج TLS أو حالة العقدة العامة. المنفذ الأصلي لا يُعدل أثناء الحصر أو الدفعات.
