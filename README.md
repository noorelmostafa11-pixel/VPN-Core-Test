# vpn-core 0.5.4 — Go

فرع Go مستقل مبني من `main` عند
`90a1853114de3e4bcb3deed6747801c10bc5b370`. الكور ينفذ VLESS وVMess وTrojan
وShadowsocks داخل Go، مع وسائل النقل والتشفير والبصمات التي يدعمها main.
أضيف عميل وخادم Hysteria 2 بمكوّن البروتوكول الرسمي المرخص داخل نفس العملية،
واتصالات SSH خارجية مع تثبيت هوية الخادم. تفاصيل التغطية والاختبارات وحدود
الإضافات في [سجل التنفيذ](docs/FULL-SUPPORT-IMPLEMENTATION.md).
يعمل كملف واحد، ويحتوي مسار TUN أصلي لـTCP/UDP وIPv4/IPv6. تنفيذ البروتوكولات
خاص بالمشروع للبروتوكولات الأصلية، مع مكونات Hysteria وSSH وTLS/QUIC والتشفير
وgVisor والتعريفات المرخصة محفوظة.

البناء والتشغيل:

```text
python scripts/Build-Go.py --target windows --arch amd64 --wintun
build/windows-amd64/vpn-core.exe --config node.ini
```

صيغة `node.ini` السابقة محفوظة:

```ini
node_uri=vless://12345678-1234-4567-9234-567812345678@example.test:443?security=tls&type=tcp
listen_port=1080
connect_timeout_ms=10000
idle_timeout_ms=60000
max_connections=128
```

الناتج الافتراضي برنامج Go واحد. `--shared` يبني مكتبة Go اختيارية تحافظ على
C ABI 2 لدمج التطبيقات. لا يحتاج التشغيل إلى `vpn-tls.dll` أو محرك C++.

السقف الافتراضي 128 اتصالًا، ويمكن ضبط `max_connections` بين 1 و512.
عند امتلائه يظهر `CONNECTION_LIMIT` في السجل، ويعود قبول الاتصالات بمجرد
إغلاق اتصال. انتهاء الخمول يظهر `IDLE_TIMEOUT` مع حجم البيانات ومدة الاتصال.

TUN داخل الكور يمرر الحزم مباشرة إلى البروتوكولات. لإنشاء جهاز:
`vpn-core --config node.ini --tun vpn0 --tun-only`. التطبيق المضيف يضبط عناوين
الجهاز والمسارات وDNS وحماية الاتصال بالشبكة الأصلية. Windows يحتاج صلاحيات
Administrator وتعريف Wintun الرسمي. لا يغيّر الكور المسار الافتراضي للجهاز.

حزمة Windows تتضمن إعداد IPv4 اختياريًا للمسارات وDNS وقواعد المنع والاستعادة:
[دليل إعداد نفق Windows](docs/WINDOWS-TUNNEL.md). تشغيل `--tun` وحده لا يضمن
منع تسريب DNS. إعداد المنع الجديد يحتاج تأكيدًا بالتقاط الحزم على الجهاز الحقيقي.

يدعم SDK Go، وAndroid AAR عبر `mobile.StartFD` مع VpnService، وواجهة حزم
`StartPackets` لدمج Android/iOS. بناء Apple يحتاج macOS/Xcode وصلاحية Network
Extension في التطبيق. الحزم الافتراضية تستهدف معمارية واحدة لتقليل الحجم.

```text
python scripts/Build-Go.py --target linux --arch arm64
python scripts/Build-Go.py --target darwin --arch arm64
python scripts/Build-Mobile.py --target android/arm64 --output dist/vpn-core.aar
python -m pip install -r tests/requirements-go.txt
go test -race ./core ./mobile
python scripts/Validate-Go.py
```

على GitHub توجد عملية واحدة: **Actions → Build & Test → Run workflow**.
اختر `main` أو `feature/go-native-core` فقط؛ البناء والاختبارات تتحدد حسب الفرع
دون اختيارات إضافية. يبدأ الفحص أيضًا عند رفع تغيير إلى أي منهما.

تفاصيل البروتوكولات والمنصات ودورة الحياة والبناء في
[دليل Go وTUN](docs/GO-NATIVE-CORE.md). تقارير النسخ السابقة متاحة في تاريخ Git.
يحتفظ هذا الفرع بالملكية والتراخيص السابقة؛ لم نضف ترخيصًا عامًا للكود الأصلي.
