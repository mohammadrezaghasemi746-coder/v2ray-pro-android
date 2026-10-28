# گزارش مهندسی عیب‌یابی و اصلاحات جامع (V2Ray Pro Android Fixed)

## ۱. خلاصه مشکلات ریشه‌ای شناسایی‌شده و اصلاحات انجام‌شده
1. **ارتباط ناقص WebView و Kotlin (`MainActivity.kt` / `index.html`):**
   - در نسخه قبلی، تنها ۴ دستور پایه در `MainActivity.kt` وجود داشت و کلاس‌های `StorageRepository`، `UriParser`، `XrayConfigBuilder`، `NetworkDiagnosticsEngine` و `OtaUpdateManager` به رابط کاربری متصل نبودند.
   - اکنون دستورات `v2ray://ping`، `v2ray://sync_sub`، `v2ray://traffic` و `v2ray://status` به پل ارتباطی دوگانه (`AndroidBridge` و `onJsPrompt`) اضافه شده و وضعیت واقعی هسته با رابط کاربری همگام می‌شود.
2. **جلوگیری از نمایش وضعیت کاذب Connected و مدیریت دقیق `libv2ray.aar` (`V2RayVpnService.kt` / `XrayCoreRunner.kt`):**
   - پیش از ایجاد رابط `tun0`، وجود واقعی کلاس بومی `libv2ray.Libv2ray` بررسی می‌شود تا در صورت عدم وجود فایل `app/libs/libv2ray.aar`، تونل سیاه‌چاله (Blackhole) ایجاد نشود و خطای دقیق به رابط کاربری گزارش گردد.
   - نشت فایل‌دسکریپتور (`dup().detachFd()`) در صورت بروز خطا هنگام اجرای `core.start(json, fd)` با بستن ایمن `ParcelFileDescriptor.adoptFd(fd)` برطرف شد.
3. **حفظ دسترسی به شبکه داخلی (LAN / Wi-Fi Gateway) در زمان اتصال (`V2RayVpnService.kt` / `XrayConfigBuilder.kt`):**
   - در اندروید ۱۳ به بالا از `Builder.excludeRoute(IpPrefix)` و در اندروید ۷ تا ۱۲ از جدول ۵۱ پیشوند دقیق ریاضی (`PUBLIC_IPV4_ROUTES_EXCLUDING_LAN`) استفاده شده است که زیرشبکه‌های خصوصی `10.0.0.0/8`، `172.16.0.0/12`، `192.168.0.0/16`، `169.254.0.0/16`، `100.64.0.0/10`، `127.0.0.0/8` و `224.0.0.0/3` را از مسیر تونل مستثنی می‌کند.
   - تشخیص خودکار تداخل آدرس شبکه محلی با `10.200.200.0/30` و تغییر خودکار آدرس TUN به `172.31.250.2/30` اضافه شد.
4. **اصلاح کامل سیستم اشتراک‌ها و Parser (`UriParser.kt` / `SubscriptionManager.kt`):**
   - خطای کرش `java.net.URI` روی نام سرورهای حاوی فاصله، کاراکترهای فارسی و ایموجی برطرف شد.
   - کلاس `SubscriptionManager.kt` برای دریافت مستقیم لینک‌های HTTPS با Timeout، بررسی کد وضعیت HTTP، بررسی انقضای `Subscription-Userinfo` و ادغام غیرمخرب (حفظ سرورهای قبلی در صورت دریافت پاسخ خالی یا خطا) اضافه شد.
   - ارسال لینک‌های اشتراک خصوصی کاربر به پراکسی‌های عمومی CORS ثالث (`allorigins` / `corsproxy`) به دلیل ریسک امنیتی لو رفتن UUIDها حذف شد.
5. **اصلاح تست پینگ واقعی و حذف مقادیر ساختگی (`NetworkDiagnosticsEngine.kt` / `index.html`):**
   - باگ نمایش پینگ ساختگی (۱۶ تا ۴۲۰ میلی‌ثانیه) برای سرورهای قطع و فیلترشده در `pingSingleServer` برطرف شد؛ اکنون خطاهای `DNS_ERROR`، `TIMEOUT`، `REFUSED` و `UNREACHABLE` تفکیک شده و مقدار `null` برمی‌گردانند.
   - تولید اعداد تصادفی سرعت دانلود/آپلود (`Math.sin`) حذف و با خواندن شمارنده‌های واقعی بایت سیستم‌عامل (`TrafficStats.getTotalRxBytes/TxBytes`) جایگزین شد.
