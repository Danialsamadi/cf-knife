# cf-knife

**زبان‌ها:** [English — README.md](README.md)

یک اسکنر با کارایی بالا برای شناسایی IPهای لبه (Edge) CDN، نوشته شده با زبان Go. این ابزار یک باینری استاتیک و کاملاً کراس‌پلتفرم است که با استفاده از کاوش‌های شبکه‌ای لایه‌بندی شده، گزارش پیشرفت لحظه‌ای و قابلیت‌های تحلیل پیشرفته، محیط شبکه را بررسی می‌کند.

## نگاه کلی

`cf-knife` آدرس‌های IP را در پورت‌های مختلف با رویکردی لایه‌بندی شده بررسی می‌کند: اتصال TCP، دست‌دادن (Handshake) TLS، پروتکل HTTP/1.1 و HTTP/2. این ابزار به‌طور ویژه برای اسکن مقیاس‌پذیر محدوده‌های IP کلودفلر (Cloudflare) و فستلی (Fastly) طراحی شده و دارای قالب‌های زمان‌بندی مشابه nmap، هم‌روند (Concurrency) قابل تنظیم و فرمت‌های خروجی متنوع است.

### ویژگی‌های کلیدی

- **اسکن مبتنی بر دامنه**: با استفاده از `--domain-file` لیستی از نام میزبان‌ها را دریافت کرده، آن‌ها را Resolve می‌کند و با SNI/Host اصلی به IP مربوطه متصل می‌شود (رویکرد DPI-bypass). از نام‌های ساده، URLهای کامل، پیشوندهای `label | host` و بلوک‌های CIDR پشتیبانی می‌کند.
- **جایگزینی خودکار HTTPS $\rightarrow$ HTTP**: در صورتی که بررسی اولیه روی پورت HTTPS شکست بخورد، ابزار به‌طور خودکار پورت 80 را با HTTP امتحان می‌کند تا اهداف حتی در شرایط سانسور جزئی شناسایی شوند.
- **کاوش‌های شبیه مرورگر**: در حالت دامنه، از درخواست‌های `GET` (به جای `HEAD`) و هدرهای واقعی (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`) برای شبیه‌سازی رفتار مرورگر استفاده می‌کند.
- **ثبت کدهای وضعیت HTTP**: کد پاسخ واقعی HTTP (مانند 200، 301، 403 و ...) در نتایج ذخیره و در تمامی فرمت‌های خروجی گنجانده می‌شود.
- **فیلد برچسب (Label)**: خطوطی با فرمت `label | host` در فایل‌های دامنه، برچسب خود را تا نتایج نهایی و فایل‌های خروجی حفظ می‌کنند.
- **کش اسکن دامنه** (`--domain-cache`): نتایج موفق پس از هر اجرا ذخیره می‌شوند تا در اجرای بعدی، ابتدا اهداف کش‌شده برای بررسی سریع‌تر بارگذاری شوند.
- **گزارش‌های دامنه**: پس از هر اسکن در حالت دامنه، دو فایل گزارش به‌طور خودکار ایجاد می‌شوند: `reachable-*.txt` (نتایج باز مرتب شده بر اساس تأخیر) و `full_log-*.txt` (تمام اهداف با تگ‌های OPEN/DEAD).
- **پشتیبانی از چندین CDN**: شناسایی اثر انگشت لبه‌های Cloudflare و Fastly با دریافت خودکار محدوده‌های IP.
- **کاوش‌های لایه‌بندی شده**: TCP، TLS، HTTP/1.1، HTTP/2 و HTTP/3 (QUIC)؛ امکان اجرای هر ترکیبی برای هر هدف.
- **اسکن ماتریسی Multi-SNI**: نام‌های میزبان جدا شده با کاما در `--sni` به اهداف مجزا تبدیل می‌شوند (هر IP $\times$ پورت یک بار برای هر SNI بررسی می‌شود).
- **نمونه‌گیری از زیرشبکه**: با `--sample N` به‌طور تصادفی تا $N$ آدرس از هر CIDR قبل از اسکن نگه داشته می‌شود (مفید برای محدوده‌های بسیار بزرگ).
- **کاوش تکه‌تکه HTTP**: گزینه `--http-fragment` بدنه درخواست HTTP را در تکه‌های کوچک و با تأخیر ارسال می‌کند (برای آزمایش‌های DPI و فیلترینگ لایه اپلیکیشن).
- **موتورهای اسکن**: `connect` (پیش‌فرض)، `fast` (تایم‌اوت‌های تهاجمی) و `syn` (ساختار اولیه با بازگشت به connect).
- **معیارهای عملکرد**: اندازه‌گیری پینگ/ژیتر واقعی (ICMP یا TCP-based) و تست سرعت دانلود/آپلود.
- **تحلیل دور زدن DPI**: تکه‌تکه‌سازی TLS ClientHello و شناسایی بهینه SNI fronting.
- **اسکنر نقاط پایانی WARP**: اسکنر اختصاصی UDP/WireGuard برای یافتن نقاط پایانی Cloudflare WARP.
- **اعتبارسنجی گواهینامه TLS**: شناسایی حملات MITM از طریق بررسی زنجیره گواهینامه‌ها.
- **منطق تکرار هوشمند**: در صورتی که تنظیمات سخت‌گیرانه منجر به نتیجه‌ای نشود، آستانه‌ها به‌طور خودکار تسهیل می‌شوند.
- **صف پایدار SQLite**: وضعیت اسکن با `--resume` حتی پس از ری‌استارت برنامه حفظ می‌شود.
- **کنترل نرخ**: سقف کلی تراکم عملیات در ثانیه و محدودیت نرخ برای هر worker.
- **قالب‌های زمان‌بندی ۰-۵**: از حالت "محتاطانه" (Paranoid) تا "دیوانه‌وار" (Insane)، مدل‌سازی شده بر اساس پرچم `-T` در nmap.
- **فرمت‌های خروجی**: txt، json، csv و همچنین `clean_list.txt` برای استفاده مستقیم در تنظیمات پروکسی.
- **نوار پیشرفت لحظه‌ای**: نمایش آمار زنده (شمارنده‌های TCP/TLS/HTTP/H2 و نرخ اسکن).
- **خروج graceful**: ذخیره نتایج جزئی هنگام فشردن Ctrl-C.
- **کراس‌پلتفرم**: پشتیبانی از Linux، macOS و Windows با باینری‌های پیش‌ساخته در هر ورژن.

## نصب

### دانلود باینری‌های پیش‌ساخته

آخرین نسخه را از [GitHub Releases](https://github.com/Danialsamadi/cf-knife/releases) دریافت کنید:

| پلتفرم | باینری |
|----------|--------|
| Linux amd64 | `cf-knife-linux-amd64` |
| Linux arm64 | `cf-knife-linux-arm64` |
| Linux 386 | `cf-knife-linux-386` |
| macOS amd64 | `cf-knife-darwin-amd64` |
| macOS arm64 (Apple Silicon) | `cf-knife-darwin-arm64` |
| Windows amd64 | `cf-knife-windows-amd64.exe` |

**برای لینوکس و macOS** — پس از دانلود، باینری را اجرایی کنید:

```bash
chmod +x cf-knife-*
```

**برای ویندوز** — نیازی به `chmod` نیست. از پوشه‌ای که فایل `.exe` در آن قرار دارد، اجرا کنید:

```powershell
.\cf-knife-windows-amd64.exe scan --help
```

### ساخت از سورس

نیازمند Go 1.25 یا نسخه‌های جدیدتر.

**لینوکس / macOS:**
```bash
go build -o cf-knife .
```

**ویندوز (PowerShell یا CMD):**
```powershell
go build -o cf-knife.exe .
```

مثال‌های کامپایل متقاطع (Cross-compilation):
```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-linux-arm64 .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife.exe .
```

## شروع سریع

در لینوکس و macOS از **`./cf-knife`** و در ویندوز از **`.\cf-knife.exe`** استفاده کنید. پرچم‌ها در تمامی پلتفرم‌ها یکسان هستند.

**خط شکستن:** در مثال‌های bash از `\` در انتهای خط استفاده شده است. در **PowerShell** از علامت بک‌تیک `` ` `` و در **CMD** از `^` استفاده کنید.

### لینوکس / macOS
اسکن یک IP واحد در دو پورت:
```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

اسکن محدوده CIDR از یک فایل با زمان‌بندی تهاجمی:
```bash
./cf-knife scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```

اسکن گره‌های لبه Fastly به‌جای کلودفلر:
```bash
./cf-knife scan --fastly-ranges --script fastly -p 443
```

استفاده از چند TLS server name برای IPهای یکسان (هر `--sni` یک هدف جداگانه است):
```bash
./cf-knife scan --ips 1.1.1.1,1.0.0.1 -p 443 \
  --sni "www.cloudflare.com,example.com" \
  -o multi-sni.txt
```

نمونه‌گیری تصادفی چند میزبان از هر CIDR به‌جای باز کردن کل محدوده:
```bash
./cf-knife scan --ips 104.16.0.0/16 -p 443 --sample 200 --timing 4 -o sampled.txt
```

کاوش HTTP/HTTPS با ارسال تکه‌تکه درخواست‌ها (مقایسه کنید با اجرای عادی بدون این پرچم):
```bash
./cf-knife scan --ips 1.1.1.1 -p 443 --mode http --http-fragment -o http-frag.txt
```

### ویندوز (PowerShell)
```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
```
```powershell
.\cf-knife.exe scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```
```powershell
.\cf-knife.exe scan --fastly-ranges --script fastly -p 443
```
```powershell
.\cf-knife.exe scan --ips 1.1.1.1,1.0.0.1 -p 443 `
  --sni "www.cloudflare.com,example.com" `
  -o multi-sni.txt
```
```powershell
.\cf-knife.exe scan --ips 104.16.0.0/16 -p 443 --sample 200 --timing 4 -o sampled.txt
```
```powershell
.\cf-knife.exe scan --ips 1.1.1.1 -p 443 --mode http --http-fragment -o http-frag.txt
```

---

## مرجع دستورات

`cf-knife` دارای یک زیردستور اصلی به نام `scan` است.

```
# Linux / macOS
./cf-knife scan [flags]

# Windows (PowerShell / CMD)
.\cf-knife.exe scan [flags]
```

### پرچم‌های ورودی (Input Flags)

| پرچم | کوتاه | پیش‌فرض | توضیح |
|------|-------|---------|-------------|
| `--ips` | | _(هیچ)_ | IPها یا محدوده‌های CIDR جدا شده با کاما. مثال: `1.1.1.0/24,104.16.0.0/20` |
| `--input-file` | `-i` | _(هیچ)_ | مسیر فایلی حاوی IP یا CIDR (هر خط یکی). خطوطی که با `#` شروع شوند نادیده گرفته می‌شوند. |
| `--ipv4-only` | | `false` | فقط اسکن آدرس‌های IPv4. |
| `--ipv6-only` | | `false` | فقط اسکن آدرس‌های IPv6. |
| `--shuffle` | | `false` | تصادفی کردن ترتیب اهداف قبل از اسکن. |
| `--sample` | | `0` | نمونه‌گیری تصادفی تا $N$ آدرس IP از هر زیرشبکه CIDR (`0` = باز کردن تمام آدرس‌ها). |
| `--fastly-ranges` | | `false` | استفاده از محدوده IPهای لبه Fastly (دریافت از `api.fastly.com`). |
| `--domain-file` | | _(هیچ)_ | مسیر فایلی حاوی نام‌های میزبان. پشتیبانی از نام‌های ساده، URLهای `http(s)://`، پیشوندهای `label \| host` و بلوک‌های CIDR. هر میزبان از طریق DNS تحلیل شده و با SNI و `Host` اصلی متصل می‌شود. ناسازگار با `--ips`, `--input-file`, `--fastly-ranges`, `--warp`. |
| `--cf-all-ports` | | `false` | هنگام استفاده از `--domain-file` هر میزبان را در تمام ۱۳ پورت لبه کلودفلر (۶ HTTPS + ۷ HTTP) بررسی می‌کند. |
| `--site-preflight` | | `true` | اجرای بررسی DNS $\rightarrow$ TCP $\rightarrow$ TLS قبل از کاوش‌های اصلی. اگر HTTPS شکست بخورد، به‌طور خودکار روی پورت 80 با HTTP تلاش می‌کند. |
| `--domain-cache` | | `domain-cache.txt` | فایل کش برای نتایج اسکن دامنه. اهداف موفق ذخیره شده و در اجرای بعدی ابتدا بارگذاری می‌شوند. |

اگر هیچ‌کدام از پرچم‌های ورودی ارائه نشود، `cf-knife` به‌طور خودکار محدوده‌های رسمی IPهای کلودفلر را دریافت می‌کند.

### پرچم‌های کاوش (Probe Flags)

| پرچم | کوتاه | پیش‌فرض | توضیح |
|------|-------|---------|-------------|
| `--port` | `-p` | `443,80,8443,2053,2083` | لیست پورت‌هایی که باید روی هر IP اسکن شوند. |
| `--mode` | | `full` | حالت کاوش: `tcp-only`, `tls`, `http`, `http2`, `http3`, `full`. |
| `--test-tcp` | | `false` | اجبار به تست TCP بدون توجه به حالت (`mode`). |
| `--test-tls` | | `false` | اجبار به تست TLS بدون توجه به حالت. |
| `--test-http` | | `false` | اجبار به تست HTTP/1.1 بدون توجه به حالت. |
| `--test-http2` | | `false` | اجبار به تست HTTP/2 بدون توجه به حالت. |
| `--test-http3` | | `false` | اجبار به تست HTTP/3 (QUIC) بدون توجه به حالت. |
| `--sni` | | `www.cloudflare.com` | نام میزبان(های) SNI برای TLS. مقادیر جدا شده با کاما باعث **اسکن ماتریسی** می‌شوند. |
| `--http-url` | | `https://www.cloudflare.com/cdn-cgi/trace` | URLی که در طول کاوش‌های HTTP/HTTP2 فراخوانی می‌شود. |
| `--scan-type` | | `connect` | موتور اسکن: `connect`, `fast`, `syn`. |
| `--script` | | _(هیچ)_ | اجرای اسکریپت شناسایی: `cloudflare` یا `fastly`. |

### پرچم‌های عملکرد (Performance Flags)

| پرچم | کوتاه | پیش‌فرض | توضیح |
|------|-------|---------|-------------|
| `--threads` | `-t` | `200` | تعداد Workerهای هم‌روند (۱-۱۰۰۰۰). |
| `--timeout` | | `3s` | تایم‌اوت برای هر عملیات شبکه. |
| `--retries` | | `2` | تعداد تلاش مجدد برای هر کاوش شکست‌خورده. |
| `--rate` | | `0` | سقف عملیات در ثانیه برای کل برنامه (۰ = نامحدود). |
| `--rate-limit` | | `0` | سقف عملیات در ثانیه برای هر worker (۰ = نامحدود). |
| `--timing` | | `3` | قالب زمان‌بندی مدل nmap (۰-۵). پرچم‌های صریح اولویت دارند. |
| `--max-latency` | | `800ms` | حذف نتایجی که تأخیر آن‌ها بیشتر از این مقدار باشد. |

### قالب‌های زمان‌بندی (Timing Templates)

| سطح | نام | Threads | Timeout | Max Latency | Rate |
|-------|------|---------|---------|-------------|------|
| 0 | Paranoid | 1 | 10s | 5s | 1/s |
| 1 | Sneaky | 5 | 8s | 3s | 10/s |
| 2 | Polite | 50 | 5s | 2s | 100/s |
| 3 | Normal | 200 | 3s | 800ms | نامحدود |
| 4 | Aggressive | 2000 | 2s | 500ms | نامحدود |
| 5 | Insane | 8000 | 1s | 300ms | نامحدود |

### پرچم‌های تحلیل (Analysis Flags)

| پرچم | پیش‌فرض | توضیح |
|------|---------|-------------|
| `--speed-test` | `false` | اندازه‌گیری پینگ ICMP، ژیتر و سرعت دانلود/آپلود HTTP برای هر هدف. |
| `--dpi` | `false` | شناسایی اندازه‌های تکه‌تکه (Fragment) DPI و یافتن بهترین SNI front برای هر هدف. |
| `--fragment-sizes` | `10,50,100,200,500` | اندازه‌های تکه‌تکه (به بایت) برای تست DPI، جدا شده با کاما. |
| `--http-fragment` | `false` | استفاده از درخواست‌های HTTP تکه‌تکه (نوشت‌های کوچک با تأخیر) به جای یک درخواست HEAD ساده. |
| `--cert-check` | `false` | اعتبارسنجی گواهینامه‌های TLS در برابر صادرکنندگان شناخته شده CDN و شناسایی MITM. |
| `--smart-retry` | `false` | تسهیل خودکار `max-latency` (۲ برابر) و `timeout` (۱.۵ برابر) در صورت نبود نتیجه. |
| `--warp` | `false` | اسکن نقاط پایانی UDP قابل دسترس Cloudflare WARP. |
| `--warp-port` | `2408` | پورت UDP برای کاوش WARP. |

### پرچم‌های ماندگاری (Persistence Flags)

| پرچم | پیش‌فرض | توضیح |
|------|---------|-------------|
| `--db` | `cf-knife.db` | مسیر فایل دیتابیس SQLite برای حفظ وضعیت اسکن. |
| `--resume` | `false` | ادامه آخرین اسکن متوقف شده از صف SQLite. |

### پرچم‌های خروجی (Output Flags)

| پرچم | کوتاه | پیش‌فرض | توضیح |
|------|-------|---------|-------------|
| `--output` | `-o` | `clean_ips.txt` | نام پایه فایل خروجی. یک برچسب زمانی به‌طور خودکار اضافه می‌شود. |
| `--output-format` | | `txt` | فرمت خروجی: `txt`, `json`, `csv`. |
| `--verbose` | | `false` | چاپ جزئیات پیشرفت در stdout. |
| `--progress` | | `true` | نمایش نوار پیشرفت لحظه‌ای با آمار زنده. |

### پرچم‌های پیکربندی (Configuration Flags)

| پرچم | پیش‌فرض | توضیح |
|------|---------|-------------|
| `--config` | _(هیچ)_ | مسیر فایل پیکربندی JSON. پرچم‌های CLI اولویت دارند. |
| `--save-config` | `false` | ذخیره پرچم‌های فعلی در یک فایل JSON و خروج. |

### مثال‌های مرجع (کپی-پیست)

اسکن ماتریسی Multi-SNI:
```bash
./cf-knife scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```
```powershell
.\cf-knife.exe scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```

نمونه‌گیری از زیرشبکه:
```bash
./cf-knife scan -i ranges.txt -p 443 --sample 25 -o out.txt
```
```powershell
.\cf-knife.exe scan -i ranges.txt -p 443 --sample 25 -o out.txt
```

کاوش تکه‌تکه HTTP (نیازمند لایه HTTP، مثلاً `--mode http` یا `full`):
```bash
./cf-knife scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```
```powershell
.\cf-knife.exe scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```

---

## مثال‌ها

در تمام این بخش، **`./cf-knife`** به معنای باینری ساخته شده یا دانلود شده در لینوکس/macOS است. در ویندوز، همین پرچم‌ها را با **`.\cf-knife.exe`** اجرا کنید. دستورات چندخطی **bash** از `\` و در **PowerShell** از `` ` `` در انتهای خط استفاده می‌کنند.

### ۱. اسکن پایه یک IP واحد
```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```
```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
```
اجرای کاوش‌های TCP، TLS، HTTP/1.1، HTTP/2 و HTTP/3 روی هر دو پورت با زمان‌بندی پیش‌فرض (سطح ۳: ۲۰۰ نخ، ۳ ثانیه تایم‌اوت).

### ۲. اسکن از فایل با زمان‌بندی تهاجمی
```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443,2053,2083 \
  --timing 4 \
  -o result.txt \
  --shuffle
```
```powershell
.\cf-knife.exe scan `
  -i Cloudflare-IP.txt `
  -p 443,80,8443,2053,2083 `
  --timing 4 `
  -o result.txt `
  --shuffle
```
- بارگذاری CIDRها از فایل، تست ۵ پورت برای هر IP.
- ۲۰۰۰ نخ، ۲ ثانیه تایم‌اوت، حداکثر تأخیر ۵۰۰ میلی‌ثانیه.
- ذخیره خروجی به صورت `result-YYYYMMDD-HHMMSS.txt`.
- `--shuffle` ترتیب اهداف را برای توزیع بار تصادفی می‌کند.

### ۳. بررسی سریع دسترسی (فقط TCP)
```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443 \
  --mode tcp-only \
  --timing 5
```
جهت حداکثر سرعت، کاوش‌های TLS/HTTP به‌طور کامل نادیده گرفته می‌شوند. زمان‌بندی Insane: ۸۰۰۰ نخ، ۱ ثانیه تایم‌اوت.

### ۴. اثر انگشت کلودفلر با شناسایی مرکز داده (Colo)
```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --script cloudflare \
  -o cloudflare-scan.txt
```
فراخوانی `/cdn-cgi/trace` برای شناسایی کدهای مرکز داده کلودفلر (مانند `cloudflare/LAX`)، هدرهای CF-Ray و اطلاعات سرور.

### ۵. اسکن گره‌های لبه فستلی (Fastly)
```bash
./cf-knife scan \
  --fastly-ranges \
  --script fastly \
  --sni www.fastly.com \
  -p 443 \
  -o fastly-results.txt
```
- `--fastly-ranges` به‌طور خودکار محدوده IPهای عمومی فستلی را از `api.fastly.com/public-ip-list` دریافت می‌کند.
- `--script fastly` هدرهای `X-Served-By` (شناسه POP)، `X-Cache` و `Via` را تحلیل می‌کند.
- شناسایی مکان‌های POP فستلی (مانند `fastly/cache-lax-123`).

### ۶. معیارهای عملکرد با تست سرعت
```bash
./cf-knife scan \
  --ips 1.1.1.1,1.0.0.1 \
  -p 443 \
  --speed-test \
  -o speed-results.txt
```
برای هر هدفی که در تست TCP موفق شود، موارد زیر اندازه‌گیری می‌شوند:
- **پینگ**: RTT پاسخ ICMP (لینوکس/macOS) یا RTT اتصال TCP (ویندوز).
- **ژیتر**: انحراف معیار RTTها.
- **دانلود**: پهنای باند HTTP GET بر حسب Mbps.
- **آپلود**: پهنای باند HTTP POST بر حسب Mbps.

### ۷. تحلیل دور زدن DPI
```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --dpi \
  --fragment-sizes "10,50,100,200,500,1000" \
  -o dpi-results.txt
```
برای هر هدف:
- **شناسایی تکه‌تکه‌ها**: TLS ClientHello را به تکه‌هایی با اندازه‌های مختلف تقسیم کرده و اندازه تکه‌ای که کمترین تأخیر در Handshake را ایجاد می‌کند (برای دور زدن DPI) شناسایی می‌کند.
- **SNI fronting**: ۱۰ دامنه شناخته شده که توسط کلودفلر سرویس می‌شوند را تست می‌کند تا دامنه‌ای را بیابد که از شبکه‌های سانسور شده عبور کند.

### ۸. اعتبارسنجی گواهینامه TLS (ضد-MITM)
```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --script cloudflare \
  --output-format csv \
  -o cert-audit.csv
```
پس از Handshake، زنجیره گواهینامه را بررسی می‌کند:
- استخراج سازمان صادرکننده، CN موضوع و تاریخ انقضا.
- اعتبارسنجی در برابر صادرکنندگان شناخته شده CDN (مانند DigiCert, Google Trust, Let's Encrypt و ...).
- اگر صادرکننده با ارائه‌دهنده مورد انتظار مطابقت نداشته باشد، تگ `cert_mitm=true` ثبت می‌شود.

### ۹. تکرار هوشمند با آستانه‌های تسهیل شده
```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443 \
  --max-latency 200ms \
  --smart-retry \
  -o results.txt
```
اگر فیلتر سخت‌گیرانه ۲۰۰ میلی‌ثانیه هیچ نتیجه‌ای ندهد اما اهداف زنده باشند:
- دور اول: `max-latency` را به ۴۰۰ میلی‌ثانیه افزایش و `timeout` را ۵۰٪ بالا می‌برد.
- دور دوم: در صورت عدم نتیجه، دوباره ۲ برابر می‌کند.
- فقط اهدافی را دوباره اسکن می‌کند که در TCP زنده بودند اما توسط فیلتر حذف شدند.

### ۱۰. اسکن نقاط پایانی WARP
```bash
./cf-knife scan \
  --warp \
  --warp-port 2408 \
  -t 100 \
  -o warp.txt
```
کاوش نقاط پایانی UDP کلودفلر WARP (شروع Handshake در WireGuard):
- اسکن ۸ محدوده CIDR پیش‌فرض WARP (حدود ۲۰۴۸ نقطه پایانی).
- گزارش نقاط پایانی قابل دسترس مرتب شده بر اساس RTT.

### ۱۱. اسکن قابل ازسرگیری با صف پایدار
شروع یک اسکن حجیم که وضعیت را در SQLite ذخیره می‌کند:
```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443 \
  --timing 4 \
  --db my-scan.db \
  -o results.txt
```
اگر اسکن متوقف شود (Ctrl-C، کرش، قطع برق)، دقیقاً از جایی که مانده بود ادامه دهید:
```bash
./cf-knife scan \
  --resume \
  --db my-scan.db \
  -p 443,80,8443 \
  --timing 4 \
  -o results.txt
```

### ۱۲. اسکن با محدودیت نرخ (Rate-limited)
```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443 \
  --rate 5000 \
  --threads 500 \
  -o result.txt
```
تراکم کلی را روی ۵۰۰۰ اتصال در ثانیه محدود می‌کند، صرف‌نظر از تعداد نخ‌ها.

### ۱۳. خروجی JSON برای استفاده برنامه‌نویسی
```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443,80 \
  --output-format json \
  -o scan-results.json
```
هر نتیجه یک شیء JSON است که تمام فیلدهای کاوش را دارد:
```json
{
  "ip": "104.16.0.1",
  "port": "443",
  "latency_ms": 33000000,
  "tcp_success": true,
  "tls_success": true,
  "http_success": true,
  "http2_success": true,
  "http3_success": true,
  "tls_version": "TLS1.3",
  "tls_cipher": "TLS_AES_128_GCM_SHA256",
  "alpn": "h2",
  "service_name": "cloudflare/LAX",
  "cert_issuer": "DigiCert Inc",
  "cert_mitm": false
}
```

### ۱۴. خروجی CSV برای اکسل
```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --speed-test \
  --output-format csv \
  -o full-audit.csv
```

### ۱۵. ذخیره و استفاده مجدد از پیکربندی
ذخیره یک پروفایل اسکن:
```bash
./cf-knife scan \
  --ips 1.1.1.0/24 \
  --threads 500 \
  --timing 4 \
  --cert-check \
  --smart-retry \
  --save-config \
  --config my-profile.json
```
استفاده مجدد (پرچم‌های CLI همچنان اولویت دارند):
```bash
./cf-knife scan --config my-profile.json
```

### ۱۶. اسکن جامع (Full kitchen-sink)
```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443,2053,2083 \
  --timing 4 \
  --script cloudflare \
  --speed-test \
  --dpi \
  --cert-check \
  --smart-retry \
  --db scan-state.db \
  --shuffle \
  --output-format csv \
  -o full-scan.csv
```
این دستور همه‌چیز را اجرا می‌کند: کاوش‌های TCP/TLS/HTTP/H2/H3، اثر انگشت کلودفلر، تست سرعت، تحلیل DPI، اعتبارسنجی گواهینامه، تکرار هوشمند و وضعیت پایدار — همگی در یک مرحله.

### ۱۷. اسکن ماتریسی Multi-SNI
تست هر IP و پورت در مقابل چندین نام میزبان. تعداد اهداف عبارت است از: $\text{آدرس‌ها} \times \text{پورت‌ها} \times \text{SNIها}$.
```bash
./cf-knife scan \
  --ips 104.16.0.0/25 \
  -p 443,8443 \
  --sni "www.cloudflare.com,cf-ns.com,www.example.com" \
  --timing 4 \
  -o sni-matrix.txt
```

### ۱۸. نمونه‌گیری زیرشبکه (`--sample`)
زمانی که یک CIDR ورودی برای اسکن کامل بیش از حد بزرگ است؛ تا $N$ IP تصادفی **به ازای هر خط CIDR** قبل از اعمال پورت‌ها نگه می‌دارد.
```bash
./cf-knife scan \
  -i cloudflare-ranges.txt \
  -p 443 \
  --sample 100 \
  --shuffle \
  -o spot-check.txt
```

### ۱۹. کاوش تکه‌تکه HTTP (`--http-fragment`)
کاوش HTTP/HTTPS را با نوشت‌های کوچک تکه‌تکه و تأخیر اجرا می‌کند به جای یک درخواست HEAD ساده. با `--mode http` (فقط HTTP/1.1) یا `--mode full` ترکیب کنید.
```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --mode full \
  --http-fragment \
  --http-url "https://www.cloudflare.com/cdn-cgi/trace" \
  -o fragment-probe.txt
```

### ۲۰. اسکن مبتنی بر دامنه (`--domain-file`)
یک فایل `domains.txt` ایجاد کنید — ترکیبی از فرمت‌های پشتیبانی شده در یک فایل:
```
# نام‌های میزبان ساده
example.com
myapp.workers.dev

# پیشوند برچسب اختیاری (label | host)
vpn-node | cf-node.example.com
my-app   | https://another.site.dev

# بلوک‌های CIDR به اهداف IP تک‌تک تبدیل می‌شوند
104.18.2.0/24
labeled-range | 104.18.4.0/30
```

**اسکن پایه دامنه** — DNS $\rightarrow$ اتصال به IP تحلیل شده، SNI = نام میزبان:
```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --mode full \
  -o domain-scan.txt
```
بعد از اسکن، سه فایل به‌طور خودکار نوشته می‌شوند:
- `domain-scan-TIMESTAMP.txt` — نتایج اصلی با فیلدهای label و http_status.
- `reachable-TIMESTAMP.txt` — نتایج باز مرتب شده بر اساس تأخیر.
- `full_log-TIMESTAMP.txt` — تمام اهداف با تگ‌های OPEN/DEAD.

**تست تمام ۱۳ پورت لبه کلودفلر** در یک مرحله:
```bash
./cf-knife scan \
  --domain-file domains.txt \
  --cf-all-ports \
  --timing 3 \
  -o domain-all-ports.txt
```

**با استفاده از کش نتایج** — اهداف موفق در اجرای اول ذخیره شده و در اجرای دوم ابتدا بارگذاری می‌شوند:
```bash
# اجرای اول — پر کردن domain-cache.txt
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --domain-cache domain-cache.txt \
  -o domain-scan.txt

# اجراهای بعدی — ابتدا میزبان‌های کش‌شده بررسی می‌شوند
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --domain-cache domain-cache.txt \
  -o domain-scan.txt
```

**جایگزینی HTTPS $\rightarrow$ HTTP** — به‌طور پیش‌فرض فعال است. اگر پیش‌برد (preflight) دامنه در HTTPS شکست بخورد، ابزار به‌طور خودکار روی پورت 80 با HTTP تلاش می‌کند.

**غیرفعال کردن Pre-flight** (سریع‌تر، بررسی DNS/TCP/TLS قبل از کاوش را حذف می‌کند):
```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --site-preflight=false \
  -o domain-no-preflight.txt
```

**حسابرسی کامل دامنه** — تحلیل DPI، بررسی گواهینامه، خروجی CSV:
```bash
./cf-knife scan \
  --domain-file domains.txt \
  --cf-all-ports \
  --dpi \
  --cert-check \
  --script cloudflare \
  --domain-cache domain-cache.txt \
  --output-format csv \
  -o domain-audit.csv
```

---

## فرمت خروجی

### نتایج مفصل (txt)
هر خط شامل تمام داده‌های موجود برای یک هدف است:
```
1.0.0.113:443 | sni=www.cloudflare.com | latency=33ms | range=1.0.0.0/24 | tcp=ok tls=ok https=ok http2=ok http3=ok | service=cloudflare/LAX | http_status=200
example.com:443 | sni=example.com | latency=45ms | range=domain | tcp=ok tls=ok https=ok http2=ok http3=fail | service=cloudflare/SIN | label=my-site | http_status=200
1.0.0.200:443 | sni=- | latency=89ms | range=1.0.0.0/24 | tcp=ok tls=ok https=fail http2=fail http3=fail | service=- | cert_issuer=Unknown CA | MITM_DETECTED
```

### گزارش‌های دامنه (فقط در حالت دامنه)
دو فایل اضافی در کنار خروجی اصلی نوشته می‌شوند:
**`reachable-TIMESTAMP.txt`** — نتایج باز مرتب شده بر اساس تأخیر.
**`full_log-TIMESTAMP.txt`** — تمام نتایج با تگ‌های OPEN/DEAD، مرتب شده بر اساس Brchell.

### لیست پاک (clean_list.txt)
در هر اجرا تولید می‌شود — جفت‌های `ip:port` برای استفاده مستقیم در تنظیمات پروکسی.

### خلاصه ترمینال
یک جدول رنگی بعد از هر اسکن چاپ می‌شود که برترین نتایج را بر اساس کمترین تأخیر نمایش می‌دهد.

---

## آمار زنده اسکن

در حین اسکن، آمار لحظه‌ای هر ۳ ثانیه چاپ می‌شود:
```
  1134/2048 scanned | TCP:1134 TLS:890 HTTP:456 H2:312 H3:104 | err:120 | 378/s
```

---

## خاموش‌شدن Graceful

فشردن Ctrl-C باعث می‌شود:
1. Workerهای فعال کاوش جاری را تمام کرده و از پذیرش اهداف جدید خودداری کنند.
2. نوار پیشرفت و گوروتین آمار متوقف شوند.
3. تمام نتایج جمع‌آوری شده تا آن لحظه فیلتر و روی دیسک ذخیره شوند.
4. اگر از `--db` استفاده شده باشد، نتایج تکمیل شده قبلاً ذخیره شده‌اند. با `--resume` ادامه دهید.

---

## نکات پلتفرم

### ویندوز
- **پینگ**: از RTT اتصال TCP به‌جای ICMP استفاده می‌کند (ساکت‌های خام در ویندوز نیاز به دسترسی Administrator دارند).
- **نوار پیشرفت**: به جای نوار گرافیکی، آمار متنی را نمایش می‌دهد.
- **رنگ‌های ANSI**: به‌طور خودکار از طریق Windows Virtual Terminal Processing فعال می‌شوند.
- **اجرا**: همیشه `cf-knife.exe` را از طریق PowerShell یا CMD اجرا کنید.

### لینوکس
- **پینگ**: از درخواست‌های ICMP echo استفاده می‌کند. نیاز به root یا قابلیت `CAP_NET_RAW` دارد.
- **اسکن SYN**: پرچم `--scan-type syn` یک استاب (stub) است که با یک هشدار به connect scan باز می‌گردد.

### macOS
- **پینگ**: از ICMP مبتنی بر UDP بدون نیاز به root استفاده می‌کند.

---

## نکاتی برای اسکن‌های حجیم

- با `--timing 2` (محترمانه) شروع کنید تا محدودیت‌های نرخ ISP را رعایت کنید و سپس آن را افزایش دهید.
- از `--rate 10000` برای محدود کردن کلی تراکم عملیات صرف‌نظر از تعداد نخ‌ها استفاده کنید.
- `--scan-type fast` تایم‌اوت TCP را نصف می‌کند تا Sweepهای سریع‌تری داشته باشید.
- `--mode tcp-only` برای حداکثر سرعت، کاوش‌های TLS/HTTP را کاملاً حذف می‌کند.
- `--smart-retry` از اسکن‌های بیهوده در زمانی که آستانه‌ها بیش از حد سخت‌گیرانه هستند جلوگیری می‌کند.
- `--db scan.db` تضمین می‌کند که هرگز پیشرفت خود را در اسکن‌های بزرگ گم نمی‌کنید. با `--resume` ادامه دهید.
- محدوده‌های CIDR بزرگ (/12) تا سقف حدود ۱ میلیون IP در هر محدوده محدود می‌شوند. برای نمونه‌گیری تصادفی از `--shuffle` استفاده کنید.
- رفتار TLS/HTTP را بین نام‌های میزبان مختلف مقایسه کنید: `./cf-knife scan --ips 1.1.1.1 -p 443 --sni "h1.com,h2.com" -o m.txt`
- ترکیب `--cert-check` با `--script cloudflare` برای شناسایی پروکسی‌های MITM در شبکه شما.

---

## استفاده مسئولانه

این ابزار **صرفاً برای تست‌های شبکه مجاز** در نظر گرفته شده است. اسکن محدوده‌های IP که متعلق به شما نیست یا اجازه تست آن‌ها را ندارید، ممکن است شرایط خدمات ISP شما، قوانین محلی یا قوانین مربوط به کلاهبرداری‌های کامپیوتری را نقض کند. همیشه قبل از اسکن زیرساخت‌های شخص ثالث، مجوز کتبی دریافت کنید.

## مجوز

این پروژه تحت مجوز GNU General Public License v3.0 منتشر شده است — برای جزئیات بیشتر فایل [LICENSE](LICENSE) را ببینید.
