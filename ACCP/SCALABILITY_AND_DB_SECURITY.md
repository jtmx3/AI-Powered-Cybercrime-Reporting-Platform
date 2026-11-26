# دليل تشفير قاعدة البيانات، حماية EXIF، وتوسّع الأداء تحت الضغط العالي

## 1. تشفير قاعدة البيانات الموثّق (AES-256-GCM + عزل المفاتيح بالـ HKDF)
تم تطبيق تشفير **AES-256-GCM** على **9 أعمدة حساسة في 5 جداول** بالإضافة إلى جميع ملفات الأدلة المخزّنة:

| الجدول | العمود المشفّر | غرض المفتاح المعزول (HKDF Purpose) |
|---|---|---|
| `CyberCases` | `Title` | `db:cybercase:title` |
| `CyberCases` | `Description` | `db:cybercase:description` |
| `CyberCases` | `DisclosedReporterName` | `db:cybercase:identity` |
| `CyberCases` | `DisclosedReporterEmail` | `db:cybercase:identity` |
| `CaseMessages` | `Content` | `db:casemessage:content` |
| `CaseNotes` | `Content` | `db:casenote:content` |
| `IntakeConversationMessages` | `Content` | `db:intake:message` |
| `IntakeRiskAssessments` | `Summary` | `db:intake:assessment:summary` |
| `IntakeRiskAssessments` | `RiskExplanation` | `db:intake:assessment:explanation` |
| `App_Data/Evidence/*` | جميع الملفات والنسخ | `evidence-file-at-rest` |

### ضمان عدم العرض إلا للمخوّل له:
- كل عمود يشتق مفتاحاً فريداً 256-bit عبر `HKDF-SHA256` مع AAD مخصص — أي محاولة لنسخ قيمة مشفرة من عمود لآخر تفشل تشفيرياً (`AuthenticationTagMismatchException`).
- فك التشفير يتم داخل طبقة التطبيق فقط بعد مرور الطلب على `CaseAuthorizationService` و`CaseAccessPolicy` و`StaffTwoFactorFlow` (حتى الـ `ADMIN` لا يملك صلاحية قراءة تفاصيل الشكاوى أو الأدلة أو هوية المشتكي).
- **خطوة مطلوبة في SSMS:** افتح ملف `ACCP/SQL/SSMS_Security_Hardening.sql` في SQL Server Management Studio واضغط **Execute** لتوسيع الأعمدة إلى `NVARCHAR(MAX)` وتفعيل Trigger منع التلاعب بـ `AuditLogs` (بدون مسح أي بيانات قديمة).

---

## 2. إزالة بيانات EXIF والبيانات الوصفية من الصور المرفوعة
عند رفع أي صورة عبر `EvidenceService` (سواء دليل أصلي أو نسخة معدّلة):
1. يتم التحقق من التوقيع الرقمي (Magic Bytes) ثم فحص البرمجيات والـ Polyglots (`HeuristicEvidenceMalwareScanner`).
2. يمر الملف عبر `EvidenceMetadataSanitizer`:
   - **JPEG:** يحذف جميع مقاطع `APP1`–`APP15` (EXIF، GPS، XMP، IPTC، MakerNotes، المصغرات المضمّنة) و`COM` (التعليقات) وأي `APP0` يحتوي Thumbnail، ويقص أي بايتات بعد `EOI (0xFFD9)`.
   - **PNG:** يحذف جميع المقاطع الوصفية (`eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, `iCCP` بصمة ألوان الجهاز) ويقص أي بايتات بعد `IEND`.
3. بعد التنظيف الكامل فقط، تُحسب بصمة `SHA-256` ويتم تشفير الصورة بـ `AES-256-GCM` قبل حفظها على القرص.

---

## 3. حماية الموقع من ضغط الحمولة والتوسّع لملايين المستخدمين (3,000,000+)

### أ. ما تم إغلاقه وتطبيقه داخل كود التطبيق لمنع التعليق والانهيار (OOM / DoS):
1. **رفض الفيضانات عند البوابة قبل قاعدة البيانات:** تقديم `UseRateLimiter()` قبل `UseAuthentication()` و`UseRequiredOfficerTwoFactor()` بحيث تُرفض الهجمات بـ `429` خلال أجزاء من الملي ثانية **بدون استعلام SQL واحد**.
2. **منع استعلامات DB للملفات الثابتة:** استثناء الملفات الثابتة (`/_framework/`, `/lib/`, `.css`, `.js`, `.png`) من فحص `UseRequiredOfficerTwoFactor()`.
3. **تحصين Kestrel ضد ضغط الحمولة وSlowloris:**
   - سقف اتصالات متزامنة (`MaxConcurrentConnections = 2000`, `MaxConcurrentUpgradedConnections = 1000` للـ WebSockets).
   - سقف حجم الترويسات `16 KB` وخط الطلب `4 KB` ومهلة الترويسات `15s` ومعدل تدفق أدنى `MinRequestBodyDataRate` لإحباط هجمات Slow-POST.
4. **عزل العمليات الثقيلة (Bulkhead Pattern):**
   - تحديد العمليات المتزامنة لرفع ومعالجة ملفات الـ 10MB عبر `SemaphoreSlim(16)` في `AuthorizedEvidenceService`.
   - تحديد التنزيلات المتزامنة للأدلة المشفّرة عبر `ConcurrencyLimiter` في `Program.cs` لمنع استنزاف الرام (`OutOfMemoryException`).
5. **تقييد حجم الاستعلامات والـ Output Caching:**
   - إضافة `AddOutputCache` للصفحات العامة، وتقييد القوائم بـ `.Take(500)`، وتفعيل `EnableRetryOnFailure(3)` و`CommandTimeout(15)` على SQL Server.

### ب. المعمارية المطلوبة فعلياً لخدمة 3,000,000 مستخدم متزامن في الإنتاج:
لا يوجد خادم واحد (Single Server) في العالم يتحمل 3 ملايين اتصال Blazor Server متزامن في الذاكرة؛ للوصول لهذا الحجم مع الكود المحصّن أعلاه تُضاف البنية الأفقية (Horizontal Scaling):
1. **Edge CDN + WAF (مثل Cloudflare / AWS CloudFront):** تمتص 90%+ من الزيارات والملفات الثابتة وهجمات DDoS قبل وصولها للسيرفرات.
2. **Load Balancer (Nginx / HAProxy / Azure Front Door):** يوزع الحمل على عشرات/مئات النسخ (`Auto-Scaling App Nodes`) من `ACCP.Web`.
3. **Azure SignalR Service أو Redis Backplane + Distributed DataProtection Keys:** لفصل حمل اتصالات WebSocket عن ذاكرة خوادم الويب ومشاركة مفاتيح الجلسات.
4. **SQL Server Always On Availability Groups + Read Replicas + Object Storage (S3 / Azure Blob):** لتوزيع القراءة والكتابة وتخزين ملفات الأدلة المشفّرة خارج قرص الخادم المحلي.
