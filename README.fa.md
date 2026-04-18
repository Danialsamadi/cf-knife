# cf-knife

**زبان‌ها:** [English — README.md](README.md)

**اسکنر آدرس‌های IP لبهٔ CDN با کارایی بالا** — نوشته‌شده با Go خالص.  
یک باینری استاتیک، کراس‌پلتفرم و بسیار سریع که با کاوش چندلایهٔ شبکه (TCP + TLS + HTTP/1.1 + HTTP/2 + HTTP/3) و گزارش پیشرفت لحظه‌ای، بهترین تجربهٔ اسکن Cloudflare و Fastly را ارائه می‌دهد.

---

## فهرست مطالب

- [نگاه کلی](#نگاه-کلی)
- [ویژگی‌های اصلی](#ویژگی‌های-اصلی)
- [نصب](#نصب)
- [شروع سریع](#شروع-سریع)
- [مرجع دستورات](#مرجع-دستورات)
- [مثال‌ها](#مثال‌ها)
- [فرمت خروجی](#فرمت-خروجی)
- [آمار زندهٔ اسکن](#آمار-زندهٔ-اسکن)
- [خاموش‌شدن تمیز](#خاموش‌شدن-تمیز)
- [نکات پلتفرم](#نکات-پلتفرم)
- [نکات برای اسکن حجیم](#نکات-برای-اسکن-حجیم)
- [استفادهٔ مسئولانه](#استفادهٔ-مسئولانه)
- [مجوز](#مجوز)

---

## نگاه کلی

این ابزار به صورت لایه‌به‌لایه کار می‌کند و شامل مراحل زیر است:
- اتصال TCP
- دست‌دادن TLS
- درخواست HTTP/1.1
- پشتیبانی از HTTP/2
- پشتیبانی از HTTP/3 (QUIC)


### ویژگی‌های اصلی

- **پشتیبانی چند-CDN** — اثر انگشت لبهٔ Cloudflare و Fastly با واکشی خودکار محدوده‌های IP
- **کاوش چندلایه** — TCP، TLS، HTTP/1.1 (با برچسب HTTPS)، HTTP/2، HTTP/3 (QUIC)؛ هر ترکیبی روی هر هدف
- **اسکن ماتریس چند-SNI** — هر SNI جداگانه با `--sni`، یک هدف مستقل ایجاد می‌کند (هر IP × پورت × SNI)
- **نمونه‌گیری هوشمند زیرشبکه** — `--sample N` حداکثر *N* آدرس تصادفی از هر CIDR نگه می‌دارد
- **کاوش HTTP تکه‌تکه** — با `--http-fragment` درخواست HTTP را در تکه‌های کوچک با تأخیر ارسال می‌کند (مناسب تست DPI)
- **موتورهای اسکن** — `connect` (پیش‌فرض)، `fast` (تایم‌اوت تهاجمی)، `syn` (نیمه‌کاره با بازگشت خودکار به connect)
- **معیارهای کارایی** — پینگ واقعی، ژیتر و تست سرعت دانلود/آپلود
- **تحلیل دور زدن DPI** — تکه‌تکه‌سازی TLS ClientHello + بهترین SNI fronting
- **اسکنر اختصاصی WARP** — کاوش نقاط پایانی WireGuard/UDP کلودفلر
- **اعتبارسنجی گواهی TLS** — تشخیص ضد-MITM با بررسی زنجیرهٔ گواهی
- **تلاش مجدد هوشمند** — در صورت صفر شدن نتایج، آستانه‌ها را خودکار شل می‌کند
- **صف پایدار SQLite** — با `--resume` اسکن را دقیقاً از همان نقطه ادامه می‌دهد
- **کنترل دقیق نرخ** — سقف سراسری + محدودیت به ازای هر worker
- **قالب‌های زمان‌بندی ۰–۵** — دقیقاً مثل `-T` در nmap (Paranoid تا Insane)
- **فرمت‌های خروجی** — txt، json، csv + `clean_list.txt` آماده برای پروکسی
- **نوار پیشرفت لحظه‌ای** با آمار زنده (TCP/TLS/HTTP/H2/H3 + نرخ اسکن)
- **خاموش‌شدن تمیز** — Ctrl+C همه‌چیز را ذخیره می‌کند
- **کراس‌پلتفرم کامل** — Linux، macOS، Windows (باینری آماده در هر انتشار)

---

## نصب

### دانلود باینری آماده (توصیه‌شده)

آخرین نسخه را از [GitHub Releases](https://github.com/Danialsamadi/cf-knife/releases) دانلود کنید:

| پلتفرم              | باینری                          |
|---------------------|----------------------------------|
| Linux amd64         | `cf-knife-linux-amd64`           |
| Linux arm64         | `cf-knife-linux-arm64`           |
| Linux 386           | `cf-knife-linux-386`             |
| macOS amd64         | `cf-knife-darwin-amd64`          |
| macOS arm64         | `cf-knife-darwin-arm64`          |
| Windows amd64       | `cf-knife-windows-amd64.exe`     |

**لینوکس / macOS:**
```bash
chmod +x cf-knife-*
```

**ویندوز:** نیازی به `chmod` نیست.

### ساخت از سورس (Go ≥ 1.25)

```bash
go build -o cf-knife .
```

**کراس‌کامپایل (مثال):**
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .
```

---

## شروع سریع

در لینوکس/macOS از `./cf-knife` و در ویندوز از `.\cf-knife.exe` استفاده کنید.

### لینوکس / macOS

```bash
# اسکن ساده یک IP
./cf-knife scan --ips 1.1.1.1 --port 443,80

# اسکن از فایل با زمان‌بندی تهاجمی
./cf-knife scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt

# اسکن Fastly به‌جای Cloudflare
./cf-knife scan --fastly-ranges --script fastly -p 443

# چند SNI (ماتریس)
./cf-knife scan --ips 1.1.1.1 -p 443 --sni "www.cloudflare.com,example.com" -o multi-sni.txt
```

### ویندوز (PowerShell)

```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
.\cf-knife.exe scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```

---

## مرجع دستورات

### پرچم‌های ورودی

| پرچم              | کوتاه | پیش‌فرض          | توضیح |
|-------------------|-------|------------------|------|
| `--ips`           | —     | —                | IP یا CIDR (جدا با کاما) |
| `--input-file`    | `-i`  | —                | فایل حاوی IP/CIDR (هر خط یکی، `#` کامنت) |
| `--ipv4-only`     | —     | `false`          | فقط IPv4 |
| `--ipv6-only`     | —     | `false`          | فقط IPv6 |
| `--shuffle`       | —     | `false`          | ترتیب تصادفی اهداف |
| `--sample`        | —     | `0`              | حداکثر N IP تصادفی از هر CIDR |
| `--fastly-ranges` | —     | `false`          | استفاده از محدودهٔ Fastly |

### پرچم‌های کاوش

| پرچم              | کوتاه | پیش‌فرض                     | توضیح |
|-------------------|-------|-----------------------------|------|
| `--port`          | `-p`  | `443,80,8443,2053,2083`    | پورت‌ها با کاما |
| `--mode`          | —     | `full`                      | `tcp-only`, `tls`, `http`, `http2`, `http3`, `full` |
| `--sni`           | —     | `www.cloudflare.com`        | چند SNI = ماتریس |
| `--scan-type`     | —     | `connect`                   | `connect`, `fast`, `syn` |
| `--script`        | —     | —                           | `cloudflare` یا `fastly` |

### پرچم‌های کارایی و تحلیل (مهم‌ترین‌ها)

| پرچم                | پیش‌فرض     | توضیح |
|---------------------|-------------|------|
| `--threads`         | `200`       | تعداد worker |
| `--timing`          | `3`         | ۰–۵ (شبیه nmap) |
| `--speed-test`      | `false`     | پینگ + ژیتر + سرعت دانلود/آپلود |
| `--dpi`             | `false`     | تحلیل تکه‌تکه TLS و SNI fronting |
| `--cert-check`      | `false`     | اعتبارسنجی گواهی ضد-MITM |
| `--smart-retry`     | `false`     | شل کردن خودکار آستانه‌ها |
| `--warp`            | `false`     | اسکن نقاط پایانی WARP |
| `--http-fragment`   | `false`     | ارسال HTTP تکه‌تکه |

**قالب‌های زمان‌بندی:**

| سطح | نام       | نخ‌ها | تایم‌اوت | حداکثر تأخیر | نرخ       |
|-----|-----------|-------|----------|---------------|-----------|
| 0   | Paranoid  | 1     | 10s      | 5s            | 1/s       |
| 1   | Sneaky    | 5     | 8s       | 3s            | 10/s      |
| 2   | Polite    | 50    | 5s       | 2s            | 100/s     |
| 3   | Normal    | 200   | 3s       | 800ms         | نامحدود   |
| 4   | Aggressive| 2000  | 2s       | 500ms         | نامحدود   |
| 5   | Insane    | 8000  | 1s       | 300ms         | نامحدود   |

---

## مثال‌ها

(در ویندوز به جای `./cf-knife` از `.\cf-knife.exe` استفاده کنید)

1. **اسکن پایه**
   ```bash
   ./cf-knife scan --ips 1.1.1.1 --port 443,80
   ```

2. **اسکن کامل با زمان‌بندی تهاجمی**
   ```bash
   ./cf-knife scan -i Cloudflare-IP.txt -p 443,80,8443,2053,2083 --timing 4 --shuffle -o result.txt
   ```

3. **اسکن Fastly**
   ```bash
   ./cf-knife scan --fastly-ranges --script fastly -p 443
   ```

4. **اسکن ماتریس چند-SNI**
   ```bash
   ./cf-knife scan --ips 104.16.0.0/28 -p 443 --sni "www.cloudflare.com,example.com"
   ```

5. **نمونه‌گیری + سرعت تست**
   ```bash
   ./cf-knife scan --ips 104.16.0.0/16 -p 443 --sample 200 --speed-test --timing 4
   ```

6. **تحلیل DPI**
   ```bash
   ./cf-knife scan --ips 1.1.1.1 -p 443 --dpi --http-fragment
   ```

7. **اسکن WARP**
   ```bash
   ./cf-knife scan --warp --warp-port 2408 -t 100
   ```

8. **اسکن قابل ازسرگیری**
   ```bash
   ./cf-knife scan -i ranges.txt --db my-scan.db --timing 4   # شروع
   ./cf-knife scan --resume --db my-scan.db                    # ادامه
   ```

---

## فرمت خروجی

- **txt** → خط به خط با تمام جزئیات  
- **json** / **csv** → مناسب اسکریپت و اکسل  
- **clean_list.txt** → همیشه تولید می‌شود (فقط `ip:port` برای پروکسی)

نمونه خروجی txt:
```
1.0.0.113:443 | latency=33ms | tcp=ok tls=ok https=ok http2=ok http3=ok | service=cloudflare/LAX | ping=12.3ms | dl=45.67Mbps
```

---

## آمار زندهٔ اسکن

هر ۳ ثانیه:
```
1134/2048 scanned | TCP:1134 TLS:890 HTTP:456 H2:312 H3:104 | err:120 | 378/s
```

پس از پایان، جدول رنگی خلاصه نمایش داده می‌شود.

---

## خاموش‌شدن تمیز

با `Ctrl+C`:
- workerهای جاری تمام می‌شوند
- تمام نتایج ذخیره می‌شود
- با `--db` و `--resume` دقیقاً از همان نقطه ادامه می‌دهید

---

## نکات پلتفرم

**لینوکس:** برای پینگ ICMP نیاز به `CAP_NET_RAW` یا root دارد.  
**macOS:** پینگ بدون root کار می‌کند.  
**ویندوز:** پینگ از طریق TCP (بدون نیاز به admin).

---

## نکات برای اسکن حجیم

- با `--timing 2` شروع کنید و به تدریج افزایش دهید.
- از `--sample` برای CIDRهای خیلی بزرگ استفاده کنید.
- `--rate` و `--threads` را با هم تنظیم کنید تا شبکه‌تان را خفه نکند.
- `--smart-retry` + `--db` = ترکیب طلایی برای اسکن‌های طولانی.

---

## استفادهٔ مسئولانه

این ابزار **فقط برای تست شبکه با مجوز** است. اسکن بدون اجازه می‌تواند قوانین ارائه‌دهنده اینترنت یا قوانین محلی را نقض کند.

## مجوز

**GNU General Public License v3.0** — جزئیات در فایل [LICENSE](LICENSE).

---
 
[GitHub Repository](https://github.com/Danialsamadi/cf-knife)