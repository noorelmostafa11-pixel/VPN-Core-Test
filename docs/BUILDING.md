# بناء الكور من الريبو على اللاب وعلى GitHub

السورس الأصلي واحد. `scripts/Build.py` هو مدخل البناء المشترك للاب وActions. نظام جهاز البناء منفصل عن هدف البناء. اختيار `auto` يبني للنظام المحلي؛ Android يحتاج اختيارًا صريحًا ومعمارية ABI.

## الأدوات المثبتة

Python 3.12؛ Go 1.27.1؛ Windows MinGW-w64 GCC 16.2.0؛ Linux GCC 13.3.0؛ Android NDK **30.0.16248370**، API 23 كحد أدنى. القيم في `scripts/toolchains.json`. السكربت يرفض إصدار Go/NDK/compiler مخالفًا؛ لا يغيّر أدوات جهازك أو يحمل تبعيات تلقائيًا. مكونات Go موجودة في vendor وتطبق ترقيعاتها المثبتة بالـSHA256.

| جهاز البناء | الهدف | الأدوات الإضافية |
| --- | --- | --- |
| Windows amd64 | Windows amd64 | MinGW-w64 GCC في PATH |
| Windows amd64 | Android، أي ABI من الأربعة | نسخة Windows من NDK |
| Windows، داخل WSL2 Linux | Linux amd64 | Go وGCC وPython داخل WSL2 |
| Linux amd64 | Linux amd64 | GCC |
| Linux amd64 | Android، أي ABI من الأربعة | نسخة Linux من NDK |
| Linux amd64 | Windows amd64 | أدوات x86_64-w64-mingw32 بإصدار GCC المثبت؛ بناء عابر لا يُشغّل تلقائيًا |

## سحب السورس

```sh
git clone https://github.com/noorelmostafa11-pixel/VPN-Core-Test.git
cd VPN-Core-Test
```

لبناء إصدار محدد، استخدم `git checkout v0.4.4` بعد نشر هذا الـtag، أو SHA الكوميت المطلوب. `main` هو التطوير الحالي. تغيير الهدف لا يحتاج Fork.

## Windows، من PowerShell

```powershell
.\build.ps1 -Target windows
```

الناتج في `build/windows-amd64`: `vpn-core.exe` و`vpn-core.dll` و`vpn-tls.dll` والـheaders وملفات hashes/provenance. البناء المحلي يشغل self-test وفحص واجهات المكونات فقط؛ لا يبدأ اختبار عقد عامة.

## Linux

```sh
bash build.sh --target linux
```

الناتج في `build/linux-amd64`: `vpn-core` و`libvpn-core.so` و`libvpn-tls.so`. TLS والتشفير من المزوّد المثبت ومكتبات Go القياسية؛ لا تستخدم نسخة OpenSSL الخاصة بالاختبارات كنسخة إنتاج. الشهادات تتحقق باستخدام جذور الثقة النظامية. يمكن إضافة شهادة CA موثوقة من اختيار صاحب التطبيق عبر `tls_ca_file=/absolute/path/ca.pem` في ملف INI؛ تبقى سلسلة الشهادة والاسم والصلاحية مطلوبة. تُقرأ هذه القيمة من ملف الإعداد المحلي، ولا نستنتجها أو نعيد كتابة URI العقدة.

## Android، من لاب Windows أو Linux

ثبّت NDK المحدد من Android Studio / SDK Manager، أو `sdkmanager "ndk;30.0.16248370"`. مرر مسار الإصدار نفسه:

```powershell
.\build.ps1 -Target android -Abi arm64-v8a -Ndk 'C:\Android\Sdk\ndk\30.0.16248370'
```

```sh
bash build.sh --target android --abi arm64-v8a --ndk "$ANDROID_HOME/ndk/30.0.16248370"
```

يمكن اختيار `arm64-v8a` أو `armeabi-v7a` أو `x86_64` أو `x86`. كل ABI في مجلد `build/android-<abi>` مستقل. الناتج executable للاختبار بـadb، و`libvpn-core.so` و`libvpn-tls.so` وواجهة C. مكتبات 64-bit تُبنى بمحاذاة صفحات 16 KiB. البناء العابر يُسجل `CROSS_COMPILED_NOT_RUN`؛ لا يعتبر نجاح التجميع إثبات اتصال على جهاز.

مكتبات الكور تعرض SOCKS5 TCP CONNECT. لا ينتج هذا الريبو APK أو AAR، ولم يُضف JNI أو TUN أو ربط VPNService أو حماية sockets عبر VPNService.protect. دمج هذه الوظائف في التطبيق يحتاج تنفيذًا واختبارات منفصلة؛ لا تستخدم المكتبات كبديل جاهز لكور التطبيق الحالي داخل VPNService.

## استخدام المكتبة

الواجهة في `src/core-api.h`: `vpn_core_version` و`vpn_core_run(argc, argv)` و`vpn_core_stop`. شغّل run في thread مملوك للتطبيق، باستخدام `--config /absolute/path/node.ini`. يسمح تشغيلًا واحدًا؛ الثاني يعيد 2. Stop يطلب الإغلاق؛ انتظر خروج thread قبل أي عملية تحرير. لا تفك تحميل المكتبة أو مزوّد Go أثناء عمر العملية. المكتبة لا تثبت handlers للإشارات على حساب التطبيق المضيف. يحفظ الكور إعدادات العقد الأصلية وسياسة التحقق من TLS.

احتفظ بالمزوّد بجانب executable أو مكتبة الكور. تحميله من مجلد المكوّن نفسه؛ لا نبحث عنه في مجلد العمل أو PATH. يرفض بناء الإنتاج `test_ca_file`. اختبارات المحاكي تمرر CA مباشرة للمزوّد بدل الاعتماد على بيئة shell عند تحميل مكتبة Go، وتستخدم `tls_ca_file` مع CA مؤقتة معروفة، وتختبر رفض الاسم الخاطئ.

## GitHub للاختبارات

- **Core Source Validation:** الاختبارات المشتركة وWindows/PowerShell وفحص الحصر، ثم اختبار العقد المثبتة على main. لا اختبارات على لاب المستخدم.
- **Build Selected Core Target:** نفس أمر البناء المحلي، مع اختيار all/windows/linux/android في Run workflow. عند تغيير السورس يُتحقق من كل أهداف البناء. Android يبنى لكل ABI وعلى Windows أيضًا، وتوجد اختبارات تشغيل مستقلة على محاكي Android x86_64. ARM على هاتف فعلي وVPNService/TUN خارج تغطية هذا workflow.
- Artifacts تربط الهدف بـcommit المصدر. `build-hashes.json` يتحقق من الملفات؛ `build-provenance.json` يوضح الأدوات والهدف ونوع التحقق. بناء يدوي غير مرتبط بـgit يسجل `NOT_VERIFIED` للمصدر.

لتجميع ZIP للهدف المبني:

```sh
python scripts/Package-Target.py --build build/linux-amd64
```

اختبارات شبكة العقد العامة على Windows لها تقارير منفصلة عن اختبارات بناء وتشغيل Android/Linux. الرن الأخضر لا يعني أن جميع العقد ناجحة.

مراجع أدوات البناء: [NDK other build systems](https://developer.android.com/ndk/guides/other_build_systems)، [NDK downloads](https://developer.android.com/ndk/downloads)، [Android page sizes](https://developer.android.com/guide/practices/page-sizes)، [Go x509 roots](https://go.dev/src/crypto/x509/root_linux.go). تم الرجوع إليها في 7 أكتوبر 2026؛ ثبات الأدوات في السكربت هو المرجع لهذا الإصدار.
