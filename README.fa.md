# cf-knife

**زبان‌ها:** [English — README.md](README.md)

اسکنر آدرس‌های IP لبهٔ CDN با کارایی بالا، نوشته‌شده با Go خالص. یک باینری استاتیک، کراس‌پلتفرم، با کاوش چندلایهٔ شبکه، گزارش پیشرفت لحظه‌ای و قابلیت‌های تحلیل پیشرفته.

## نگاه کلی

cf-knife آدرس‌های IP را روی چند پورت با رویکرد لایه‌ای آزمایش می‌کند: اتصال TCP، دست‌دهی TLS، HTTP/1.1 و HTTP/2. برای اسکن گستردهٔ محدوده‌های IP کلودفلر و Fastly طراحی شده است؛ با قالب‌های زمان‌بندی شبیه nmap، همزمانی قابل تنظیم و چند فرمت خروجی.

### ویژگی‌های اصلی

- **پشتیبانی چند-CDN**: اثر انگشت لبهٔ Cloudflare و Fastly با واکشی خودکار محدوده‌های IP
- **کاوش چندلایه**: TCP، TLS، HTTP/1.1 (برچسب HTTPS)، HTTP/2، HTTP/3 (QUIC) — هر ترکیبی روی هر هدف
- **اسکن ماتریس چند-SNI**: نام‌های میزبان `--sni` جدا با ویرگول به اهداف جدا گسترش می‌یابند (هر IP×پورت یک‌بار به ازای هر SNI)
- **نمونه‌گیری زیرشبکه**: `--sample N` حداکثر *N* آدرس تصادفی را از هر CIDR قبل از اسکن نگه می‌دارد (برای محدوده‌های بسیار بزرگ)
- **کاوش HTTP تکه‌تکه**: با `--http-fragment` بار HTTP در تکه‌های کوچک با تأخیر ارسال می‌شود (آزمایش DPI/فیلترینگ لایهٔ کاربرد)
- **موتورهای اسکن**: `connect` (پیش‌فرض)، `fast` (تایم‌اوت تهاجمی)، `syn` (نیمه‌کاره با بازگشت به connect)
- **معیارهای کارایی**: پینگ/ژیتر واقعی (ICMP یا مبتنی بر TCP) و آزمایش سرعت دانلود/آپلود
- **تحلیل دور زدن DPI**: تکه‌تکه‌سازی TLS ClientHello و شمارش SNI fronting
- **اسکنر نقطهٔ پایانی WARP**: اسکنر اختصاصی WireGuard/UDP برای نقاط پایانی Cloudflare WARP
- **اعتبارسنجی گواهی TLS**: تشخیص ضد-MITM با بررسی زنجیرهٔ گواهی
- **منطق تلاش مجدد هوشمند**: در صورت صفر شدن نتایج با آستانه‌های سخت، آستانه‌ها را خودکار شل می‌کند
- **صف پایدار SQLite**: با `--resume` وضعیت اسکن پس از بستن برنامه حفظ می‌شود
- **کنترل نرخ**: سقف توان عملیات سراسری و محدودیت نرخ به ازای هر worker
- **قالب‌های زمان‌بندی ۰–۵**: از Paranoid تا Insane، الگوبرداری از پرچم `-T` در nmap
- **فرمت‌های خروجی**: txt، json، csv، به‌علاوهٔ `clean_list.txt` برای استفادهٔ مستقیم در پروکسی
- **نوار پیشرفت لحظه‌ای** با آمار زنده (شمارنده‌های TCP/TLS/HTTP/H2 و نرخ اسکن)
- **خاموش‌شدن تمیز** با Ctrl-C و ذخیرهٔ نتایج جزئی
- **کراس‌پلتفرم**: لینوکس، macOS، ویندوز — باینری از پیش ساخته در هر انتشار

## نصب

### دانلود باینری از پیش ساخته

آخرین انتشار را از [GitHub Releases](https://github.com/Danialsamadi/cf-knife/releases) بگیرید:

| پلتفرم | باینری |
|----------|--------|
| Linux amd64 | `cf-knife-linux-amd64` |
| Linux arm64 | `cf-knife-linux-arm64` |
| Linux 386 | `cf-knife-linux-386` |
| macOS amd64 | `cf-knife-darwin-amd64` |
| macOS arm64 (Apple Silicon) | `cf-knife-darwin-arm64` |
| Windows amd64 | `cf-knife-windows-amd64.exe` |

**لینوکس / macOS** — پس از دانلود، باینری را قابل اجرا کنید:

```bash
chmod +x cf-knife-*
```

**ویندوز** — `chmod` لازم نیست. از پوشه‌ای که `.exe` در آن است (در صورت تغییر نام، نام فایل را تنظیم کنید):

```powershell
.\cf-knife-windows-amd64.exe scan --help
```

### ساخت از سورس

به Go نسخهٔ ۱.۲۵ یا بالاتر نیاز است.

**لینوکس / macOS:**

```bash
go build -o cf-knife .
```

**ویندوز (PowerShell یا CMD):**

```powershell
go build -o cf-knife.exe .
```

مثال‌های کراس‌کامپایل:

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-linux-arm64 .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife.exe .
```

## شروع سریع

در لینوکس و macOS از **`./cf-knife`** و در ویندوز از **`.\cf-knife.exe`** استفاده کنید (یا `.\cf-knife-windows-amd64.exe` اگر نام انتشار را نگه داشته‌اید). پرچم‌ها در همهٔ پلتفرم‌ها یکسان است.

**شکستن خط:** در bash از `\` در انتهای خط استفاده می‌شود. در **PowerShell** از بک‌تیک `` ` `` در انتهای خط؛ در **CMD** از `^`.

### لینوکس / macOS

اسکن یک IP روی دو پورت:

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

اسکن از فایل با زمان‌بندی تهاجمی:

```bash
./cf-knife scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```

اسکن گره‌های لبهٔ Fastly به‌جای Cloudflare:

```bash
./cf-knife scan --fastly-ranges --script fastly -p 443
```

همان IPها، چند نام TLS (هر `--sni` یک هدف جدا):

```bash
./cf-knife scan --ips 1.1.1.1,1.0.0.1 -p 443 \
  --sni "www.cloudflare.com,example.com" \
  -o multi-sni.txt
```

نمونه‌گیری تصادفی از میزبان‌ها در هر CIDR:

```bash
./cf-knife scan --ips 104.16.0.0/16 -p 443 --sample 200 --timing 4 -o sampled.txt
```

کاوش HTTP/HTTPS با نوشتن تکه‌تکهٔ درخواست:

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

cf-knife یک زیرفرمان دارد: `scan`.

```
# Linux / macOS
./cf-knife scan [flags]

# Windows (PowerShell / CMD)
.\cf-knife.exe scan [flags]
```

### پرچم‌های ورودی

| پرچم | کوتاه | پیش‌فرض | شرح |
|------|-------|---------|-------------|
| `--ips` | | _(خالی)_ | IP یا محدودهٔ CIDR با ویرگول. مثال: `1.1.1.0/24,104.16.0.0/20` |
| `--input-file` | `-i` | _(خالی)_ | مسیر فایل حاوی IP یا CIDR، هر خط یک مورد. خطوط با `#` نادیده گرفته می‌شوند. |
| `--ipv4-only` | | `false` | فقط IPv4 |
| `--ipv6-only` | | `false` | فقط IPv6 |
| `--shuffle` | | `false` | ترتیب تصادفی اهداف قبل از اسکن |
| `--sample` | | `0` | حداکثر *N* IP تصادفی به ازای هر زیرشبکهٔ CIDR (`0` = گسترش همهٔ آدرس‌ها) |
| `--fastly-ranges` | | `false` | استفاده از محدودهٔ IP لبهٔ Fastly به‌جای Cloudflare (از `api.fastly.com`) |

اگر هیچ‌کدام از `--ips`، `--input-file` یا `--fastly-ranges` داده نشود، cf-knife خودکار محدودهٔ رسمی Cloudflare را واکشی می‌کند.

### پرچم‌های کاوش

| پرچم | کوتاه | پیش‌فرض | شرح |
|------|-------|---------|-------------|
| `--port` | `-p` | `443,80,8443,2053,2083` | فهرست پورت‌ها با ویرگول |
| `--mode` | | `full` | حالت: `tcp-only`، `tls`، `http`، `http2`، `http3`، `full` |
| `--test-tcp` | | `false` | اجبار تست TCP صرف‌نظر از mode |
| `--test-tls` | | `false` | اجبار TLS |
| `--test-http` | | `false` | اجبار HTTP/1.1 |
| `--test-http2` | | `false` | اجبار HTTP/2 |
| `--test-http3` | | `false` | اجبار HTTP/3 (QUIC) |
| `--sni` | | `www.cloudflare.com` | نام میزبان SNI؛ چند مقدار با ویرگول **اسکن ماتریس** ایجاد می‌کند |
| `--http-url` | | `https://www.cloudflare.com/cdn-cgi/trace` | URL واکشی‌شده در کاوش HTTP/HTTP2 |
| `--scan-type` | | `connect` | موتور: `connect`، `fast`، `syn` |
| `--script` | | _(خالی)_ | اسکریپت تشخیص: `cloudflare` یا `fastly` |

### پرچم‌های کارایی

| پرچم | کوتاه | پیش‌فرض | شرح |
|------|-------|---------|-------------|
| `--threads` | `-t` | `200` | تعداد worker همزمان (۱–۱۰۰۰۰) |
| `--timeout` | | `3s` | تایم‌اوت هر عملیات شبکه |
| `--retries` | | `2` | تلاش مجدد برای هر کاوش ناموفق |
| `--rate` | | `0` | سقف عملیات/ثانیه سراسری (۰ = نامحدود) |
| `--rate-limit` | | `0` | سقف به ازای هر worker (۰ = نامحدود) |
| `--timing` | | `3` | قالب زمان‌بندی شبیه nmap (۰–۵)؛ پرچم‌هایی که خودتان می‌دهید بر قالب اولویت دارند |
| `--max-latency` | | `800ms` | حذف نتایج با تأخیر بالاتر از این آستانه |

### قالب‌های زمان‌بندی

| سطح | نام | نخ‌ها | تایم‌اوت | حداکثر تأخیر | نرخ |
|-------|------|---------|---------|-------------|------|
| 0 | Paranoid | 1 | 10s | 5s | 1/s |
| 1 | Sneaky | 5 | 8s | 3s | 10/s |
| 2 | Polite | 50 | 5s | 2s | 100/s |
| 3 | Normal | 200 | 3s | 800ms | نامحدود |
| 4 | Aggressive | 2000 | 2s | 500ms | نامحدود |
| 5 | Insane | 8000 | 1s | 300ms | نامحدود |

### پرچم‌های تحلیل

| پرچم | پیش‌فرض | شرح |
|------|---------|-------------|
| `--speed-test` | `false` | پینگ ICMP، ژیتر و سرعت دانلود/آپلود HTTP به ازای هر هدف |
| `--dpi` | `false` | شمارش اندازهٔ تکه‌های DPI و بهترین SNI front |
| `--fragment-sizes` | `10,50,100,200,500` | اندازهٔ تکه‌ها (بایت) با ویرگول |
| `--http-fragment` | `false` | HTTP تکه‌تکه به‌جای HEAD معمولی |
| `--cert-check` | `false` | اعتبارسنجی گواهی در برابر صادرکنندگان شناخته‌شدهٔ CDN و علامت MITM |
| `--smart-retry` | `false` | شل کردن خودکار `max-latency` (۲×) و `timeout` (۱.۵×) اگر هیچ نتیجه‌ای از فیلتر رد نشود |
| `--warp` | `false` | اسکن نقاط پایانی UDP قابل دسترس Cloudflare WARP |
| `--warp-port` | `2408` | پورت UDP برای کاوش WARP |

### پرچم‌های پایداری

| پرچم | پیش‌فرض | شرح |
|------|---------|-------------|
| `--db` | `cf-knife.db` | مسیر پایگاه SQLite برای وضعیت اسکن |
| `--resume` | `false` | ادامهٔ آخرین اسکن قطع‌شده از صف SQLite |

### پرچم‌های خروجی

| پرچم | کوتاه | پیش‌فرض | شرح |
|------|-------|---------|-------------|
| `--output` | `-o` | `clean_ips.txt` | نام پایهٔ فایل خروجی؛ برچسب زمانی خودکار اضافه می‌شود |
| `--output-format` | | `txt` | `txt`، `json`، `csv` |
| `--verbose` | | `false` | جزئیات بیشتر در stdout |
| `--progress` | | `true` | نوار پیشرفت و آمار زنده |

### پرچم‌های پیکربندی

| پرچم | پیش‌فرض | شرح |
|------|---------|-------------|
| `--config` | _(خالی)_ | مسیر JSON؛ پرچم‌های CLI فایل را override می‌کنند |
| `--save-config` | `false` | ذخیرهٔ پرچم‌های جاری در JSON و خروج |

### مثال‌های مرجع (کپی-پیست)

چند-SNI (ماتریس):

```bash
./cf-knife scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```

```powershell
.\cf-knife.exe scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```

نمونه‌گیری زیرشبکه:

```bash
./cf-knife scan -i ranges.txt -p 443 --sample 25 -o out.txt
```

```powershell
.\cf-knife.exe scan -i ranges.txt -p 443 --sample 25 -o out.txt
```

کاوش HTTP تکه‌تکه (نیاز به لایهٔ HTTP، مثلاً `--mode http` یا `full`):

```bash
./cf-knife scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```

```powershell
.\cf-knife.exe scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```

---

## مثال‌ها

در این بخش **`./cf-knife`** یعنی باینری ساخته‌شده یا دانلودشده روی لینوکس/macOS. در ویندوز همان پرچم‌ها را با **`.\cf-knife.exe`** اجرا کنید. در bash چندخطی از `\` استفاده شده؛ در **PowerShell** از `` ` `` در انتهای خط یا یک خط کامل.

### ۱. اسکن پایهٔ یک IP

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
```

TCP، TLS، HTTP/1.1، HTTP/2 و HTTP/3 روی هر دو پورت با زمان‌بندی پیش‌فرض (سطح ۳: ۲۰۰ نخ، تایم‌اوت ۳ ثانیه).

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

- CIDR از فایل؛ ۵ پورت به ازای هر IP
- ۲۰۰۰ نخ، تایم‌اوت ۲ ثانیه، حداکثر تأخیر ۵۰۰ میلی‌ثانیه
- خروجی مثلاً `result-20260413-163902.txt`
- `--shuffle` بار را پخش می‌کند

### ۳. فقط TCP — دسترس‌پذیری سریع

```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443 \
  --mode tcp-only \
  --timing 5
```

TLS/HTTP حذف می‌شود برای حداکثر سرعت. سطح Insane: ۸۰۰۰ نخ، تایم‌اوت ۱ ثانیه.

### ۴. اثر انگشت Cloudflare و تشخیص colo

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --script cloudflare \
  -o cloudflare-scan.txt
```

`/cdn-cgi/trace` برای کدهای colo (مثلاً `cloudflare/LAX`)، هدر CF-Ray و اطلاعات سرور.

### ۵. اسکن گره‌های لبهٔ Fastly

```bash
./cf-knife scan \
  --fastly-ranges \
  --script fastly \
  --sni www.fastly.com \
  -p 443 \
  -o fastly-results.txt
```

- `--fastly-ranges` محدودهٔ عمومی Fastly را از `api.fastly.com/public-ip-list` می‌گیرد
- `--script fastly` هدرهای `X-Served-By`، `X-Cache`، `Via` را تجزیه می‌کند
- موقعیت POPهای Fastly (مثلاً `fastly/cache-lax-123`)

### ۶. معیارهای کارایی و speed test

```bash
./cf-knife scan \
  --ips 1.1.1.1,1.0.0.1 \
  -p 443 \
  --speed-test \
  -o speed-results.txt
```

برای هر هدف TCP-موفق:
- **Ping**: ICMP روی لینوکس/macOS یا RTT اتصال TCP روی ویندوز
- **Jitter**: انحراف معیار RTTها
- **دانلود**: توان HTTP GET به Mbps
- **آپلود**: توان HTTP POST به Mbps

نمونهٔ خروجی: `ping=12.3ms jitter=2.1ms | dl=45.67Mbps ul=12.34Mbps`

### ۷. تحلیل دور زدن DPI

```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --dpi \
  --fragment-sizes "10,50,100,200,500,1000" \
  -o dpi-results.txt
```

- **شمارش تکه‌ها**: ClientHello را به اندازه‌های مختلف می‌شکند و کم‌تأخیرترین را پیدا می‌کند
- **SNI fronting**: دامنه‌های شناخته‌شده برای عبور از شبکه‌های سانسور

خروجی نمونه: `frag=100 | sni_front=discord.com`

### ۸. اعتبارسنجی گواهی TLS (ضد-MITM)

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --script cloudflare \
  --output-format csv \
  -o cert-audit.csv
```

پس از TLS: زنجیرهٔ گواهی، سازمان صادرکننده، CN موضوع، انقضا؛ تطبیق با صادرکنندگان CDN؛ `cert_mitm=true` در صورت عدم تطابق.

ستون‌های CSV شامل `cert_issuer`، `cert_subject`، `cert_expiry`، `cert_mitm`

### ۹. تلاش مجدد هوشمند با آستانهٔ شل‌تر

```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443 \
  --max-latency 200ms \
  --smart-retry \
  -o results.txt
```

اگر فیلتر ۲۰۰ms صفر نتیجه بدهد ولی هدف‌ها زنده باشند: دور اول max-latency به ۴۰۰ms و تایم‌اوت +۵۰٪؛ دور دوم تا ۸۰۰ms؛ فقط هدف‌های TCP-زندهٔ حذف‌شده دوباره اسکن می‌شوند.

```
  0 results passed filters; retrying with relaxed thresholds (max-latency: 200ms -> 400ms, round 1/2)
  re-scanning 47 alive targets...
```

### ۱۰. اسکن نقطهٔ پایانی WARP

```bash
./cf-knife scan \
  --warp \
  --warp-port 2408 \
  -t 100 \
  -o warp.txt
```

کاوش UDP Cloudflare WARP (شروع دست‌دهی WireGuard): حدود ۸ محدودهٔ پیش‌فرض WARP (~۲۰۴۸ نقطه)، گزارش مرتب‌شده بر اساس RTT.

### ۱۱. اسکن قابل ازسرگیری با صف پایدار

شروع اسکن بزرگ با ذخیره در SQLite:

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443 \
  --timing 4 \
  --db my-scan.db \
  -o results.txt
```

پس از قطع (Ctrl-C، کرش، برق):

```bash
./cf-knife scan \
  --resume \
  --db my-scan.db \
  -p 443,80,8443 \
  --timing 4 \
  -o results.txt
```

```
  resuming scan #1: 15234 pending targets
  scanning...
```

پایگاه `my-scan.db`: پیکربندی اسکن (JSON)، وضعیت هر هدف (`pending` / `done`)، نتایج تکمیل‌شده.

### ۱۲. اسکن با محدودیت نرخ

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443 \
  --rate 5000 \
  --threads 500 \
  -o result.txt
```

سقف حدود ۵۰۰۰ اتصال/ثانیه سراسری صرف‌نظر از تعداد نخ.

### ۱۳. خروجی JSON برای اسکریپت

```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443,80 \
  --output-format json \
  -o scan-results.json
```

هر نتیجه یک شیء JSON با همهٔ فیلدهای کاوش:

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

### ۱۴. خروجی CSV برای صفحه‌گسترده

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --speed-test \
  --output-format csv \
  -o full-audit.csv
```

سطر سرستون شامل همهٔ فیلدها:

```
ip,port,latency_ms,source_range,tcp,tls,https,http2,http3,scan_type,server,tls_version,
tls_cipher,alpn,cf_ray,service,ping_ms,jitter_ms,download_mbps,upload_mbps,
best_fragment,sni_front,cert_issuer,cert_subject,cert_expiry,cert_mitm,error
```

### ۱۵. ذخیره و استفادهٔ مجدد از پیکربندی

ذخیرهٔ پروفایل:

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

استفادهٔ بعدی (CLI همچنان اولویت دارد):

```bash
./cf-knife scan --config my-profile.json
```

### ۱۶. اسکن «همه‌چیز در یک بار»

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

TCP/TLS/HTTP/H2/H3، اثر انگشت Cloudflare، speed test، DPI، گواهی، retry هوشمند، حالت پایدار — در یک اجرا.

### ۱۷. اسکن ماتریس چند-SNI

تعداد اهداف = *آدرس‌ها × پورت‌ها × تعداد SNI*.

```bash
./cf-knife scan \
  --ips 104.16.0.0/25 \
  -p 443,8443 \
  --sni "www.cloudflare.com,cf-ns.com,www.example.com" \
  --timing 4 \
  -o sni-matrix.txt
```

پیام بارگذاری (۱۲۸ آدرس × ۲ پورت × ۳ SNI = ۷۶۸ هدف):

```
loaded 768 targets (128 IPs × 2 ports × 3 SNIs)
```

### ۱۸. نمونه‌گیری زیرشبکه (`--sample`)

وقتی CIDR ورودی برای اسکن کامل بسیار بزرگ است؛ حداکثر *N* IP تصادفی **به ازای هر خط CIDR** قبل از اعمال پورت‌ها.

```bash
./cf-knife scan \
  -i cloudflare-ranges.txt \
  -p 443 \
  --sample 100 \
  --shuffle \
  -o spot-check.txt
```

معادل یک‌خطی برای یک محدودهٔ بزرگ:

```bash
./cf-knife scan --ips 104.16.0.0/14 -p 443 --sample 500 --rate 2000 -o sampled.txt
```

### ۱۹. کاوش HTTP تکه‌تکه (`--http-fragment`)

کاوش HTTP/HTTPS با نوشتن‌های کوچک و تأخیر به‌جای یک HEAD واحد. با `--mode http` یا `--mode full` ترکیب کنید.

```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --mode full \
  --http-fragment \
  --http-url "https://www.cloudflare.com/cdn-cgi/trace" \
  -o fragment-probe.txt
```

گردش کار ترکیبی (ماتریس + نمونه + fragment):

```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443 \
  --sni "www.cloudflare.com,www.example.com" \
  --sample 50 \
  --http-fragment \
  -o matrix-scan.txt
```

---

## فرمت خروجی

### نتایج تفصیلی (txt)

هر خط دادهٔ کامل یک هدف:

```
1.0.0.113:443 | latency=33ms | range=1.0.0.0/24 | tcp=ok tls=ok https=ok http2=ok http3=ok | service=cloudflare/LAX
1.0.0.54:443  | latency=45ms | range=1.0.0.0/24 | tcp=ok tls=ok https=ok http2=ok http3=fail | service=cloudflare/SIN | ping=12.3ms jitter=2.1ms | dl=45.67Mbps ul=12.34Mbps | frag=100 | sni_front=discord.com | cert_issuer=DigiCert Inc
1.0.0.200:443 | latency=89ms | range=1.0.0.0/24 | tcp=ok tls=ok https=fail http2=fail http3=fail | service=- | cert_issuer=Unknown CA | MITM_DETECTED
```

### فهرست تمیز (`clean_list.txt`)

در هر اجرا تولید می‌شود — جفت‌های `ip:port` برای پروکسی:

```
1.0.0.113:443
1.0.0.54:443
1.0.0.118:443
```

### جمع‌بندی ترمینال

جدول رنگی پس از هر اسکن:

```
=== cf-knife scan results ===

IP                                       PORT   LATENCY  RANGE                 TCP  TLS  HTTPS HTTP2 HTTP3  SERVICE
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
1.0.0.113                                443      33ms  1.0.0.0/24              ok   ok   ok    ok    ok    cloudflare/LAX
1.0.0.54                                 443      45ms  1.0.0.0/24              ok   ok   ok    ok   fail   cloudflare/SIN
...

Stats:  128 clean results  |  elapsed 5.199s  |  24 targets/sec
Files:  result-20260413-163902.txt  |  clean_list.txt
```

---

## آمار زندهٔ اسکن

هر ۳ ثانیه:

```
  1134/2048 scanned | TCP:1134 TLS:890 HTTP:456 H2:312 H3:104 | err:120 | 378/s
```

پس از پایان:

```
  Scan complete in 5.199s -- 2048 targets scanned
  TCP: 1928  TLS: 890  HTTP: 456  H2: 312  H3: 104  Errors: 120
```

---

## خاموش‌شدن تمیز

با Ctrl-C در حین اسکن:

1. workerهای فعال کاوش جاری را تمام می‌کنند و هدف جدید نمی‌گیرند.
2. نوار پیشرفت و goroutine آمار متوقف می‌شود.
3. همهٔ نتایج جمع‌آوری‌شده فیلتر و روی دیسک ذخیره می‌شود.
4. با `--db`، نتایج تکمیل‌شده از قبل ذخیره شده‌اند؛ با `--resume` ادامه دهید.
5. Ctrl-C دوم در فاز ذخیره نادیده گرفته می‌شود تا نوشتن فایل کامل شود.

---

## نکات پلتفرم

### ویندوز
- **Ping**: RTT اتصال TCP به‌جای ICMP (سوکت خام معمولاً نیازمند دسترسی مدیر)
- **نوار پیشرفت**: آمار متنی به‌جای نوار گرافیکی
- **رنگ ANSI**: از طریق Windows Virtual Terminal Processing
- **اجرا از ترمینال**: همیشه `cf-knife.exe` را از PowerShell یا CMD اجرا کنید — دوبار کلیک پنجره را فوراً می‌بندد

### لینوکس
- **Ping**: درخواست ICMP؛ نیاز به root یا قابلیت `CAP_NET_RAW`
- **اسکن SYN**: پرچم `--scan-type syn` نیمه‌کاره است و با هشدار به connect برمی‌گردد

### macOS
- **Ping**: ICMP مبتنی بر UDP بدون امتیاز root

---

## نکات برای اسکن حجیم

- با `--timing 2` شروع کنید، سپس افزایش دهید.
- `--rate 10000` برای سقف توان سراسری.
- `--scan-type fast` تایم‌اوت TCP را برای جاروب سریع‌تر نصف می‌کند.
- `--mode tcp-only` برای حداکثر سرعت بدون TLS/HTTP.
- `--smart-retry` از اسکن بیهوده با آستانهٔ خیلی سخت جلوگیری می‌کند.
- `--db scan.db` برای اسکن‌های بزرگ؛ ادامه با `--resume`.
- محدوده‌های CIDR بسیار بزرگ (/۱۲) حدود ~۱M IP به ازای هر محدوده محدود می‌شوند؛ `--shuffle` برای نمونه‌گیری تصادفی.
- `--sample N`: `./cf-knife scan --ips 104.24.0.0/13 -p 443 --sample 300 -o t.txt` (ویندوز: `.\cf-knife.exe scan ...`)
- مقایسهٔ رفتار TLS/HTTP روی نام‌های میزبان مختلف: `./cf-knife scan --ips 1.1.1.1 -p 443 --sni "h1.com,h2.com" -o m.txt`
- ترکیب `--cert-check` با `--script cloudflare` برای تشخیص پروکسی MITM

---

## استفادهٔ مسئولانه

این ابزار فقط برای آزمایش شبکه با **مجوز** است. اسکن محدوده‌های IP بدون مالکیت یا اجازهٔ کتبی می‌تواند شرایط ارائه‌دهندهٔ اینترنت، قوانین محلی یا قوانین مشابه CFAA را نقض کند. همیشه قبل از اسکن زیرساخت شخص ثالث، مجوز کتبی بگیرید.

## مجوز

MIT
