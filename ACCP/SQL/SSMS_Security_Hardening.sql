/* ============================================================================
   منظومة «وَثيق» (WATHIQ / ACCP) — سكربت التحصين الأمني لـ SQL Server (SSMS)
   ============================================================================
   الهدف:
   1. توسيع الأعمدة الحساسة إلى NVARCHAR(MAX) لدعم التشفير AES-256-GCM (enc:v1:...)
      بدون حذف أو فقدان أي بيانات حالية.
   2. حماية جدول سجل التدقيق (AuditLogs) ضد التعديل أو الحذف (Tamper-Resistant).
   3. قالب إنشاء مستخدم تطبيق بمبدأ أقل صلاحية (Least Privilege) لمنع العبث بالجداول.
   4. استعلام تحقق لعرض التشفير الفعلي داخل SSMS.
   ============================================================================ */

USE [ACCP_DB];
GO

SET NOCOUNT ON;
GO

/* ----------------------------------------------------------------------------
   1. توسيع الأعمدة الحساسة لدعم التشفير الموثّق AES-256-GCM (بدون فقدان بيانات)
   ---------------------------------------------------------------------------- */
BEGIN TRY
    BEGIN TRANSACTION;

    -- CyberCases: العنوان، الوصف، وبيانات الهوية المفصح عنها
    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CyberCases') AND name = 'Title')
        ALTER TABLE dbo.CyberCases ALTER COLUMN [Title] NVARCHAR(MAX) NOT NULL;

    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CyberCases') AND name = 'Description')
        ALTER TABLE dbo.CyberCases ALTER COLUMN [Description] NVARCHAR(MAX) NOT NULL;

    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CyberCases') AND name = 'DisclosedReporterName')
        ALTER TABLE dbo.CyberCases ALTER COLUMN [DisclosedReporterName] NVARCHAR(MAX) NULL;

    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CyberCases') AND name = 'DisclosedReporterEmail')
        ALTER TABLE dbo.CyberCases ALTER COLUMN [DisclosedReporterEmail] NVARCHAR(MAX) NULL;

    -- CaseMessages: رسائل التواصل بين المشتكي والمحقق
    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CaseMessages') AND name = 'Content')
        ALTER TABLE dbo.CaseMessages ALTER COLUMN [Content] NVARCHAR(MAX) NOT NULL;

    -- CaseNotes: الملاحظات الداخلية للمحققين
    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.CaseNotes') AND name = 'Content')
        ALTER TABLE dbo.CaseNotes ALTER COLUMN [Content] NVARCHAR(MAX) NOT NULL;

    -- IntakeRiskAssessments: ملخص وتفسير التقييم
    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.IntakeRiskAssessments') AND name = 'Summary')
        ALTER TABLE dbo.IntakeRiskAssessments ALTER COLUMN [Summary] NVARCHAR(MAX) NOT NULL;

    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.IntakeRiskAssessments') AND name = 'RiskExplanation')
        ALTER TABLE dbo.IntakeRiskAssessments ALTER COLUMN [RiskExplanation] NVARCHAR(MAX) NOT NULL;

    -- IntakeConversationMessages.Content هو أصلاً NVARCHAR(MAX)

    COMMIT TRANSACTION;
    PRINT N'✓ تم توسيع جميع الأعمدة الحساسة بنجاح لدعم تشفير AES-256-GCM.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    THROW;
END CATCH;
GO

/* ----------------------------------------------------------------------------
   2. حماية جدول AuditLogs ضد التعديل أو الحذف (حماية سلسلة الحيازة الجنائية)
   ---------------------------------------------------------------------------- */
IF OBJECT_ID('dbo.TR_AuditLogs_PreventTampering', 'TR') IS NOT NULL
    DROP TRIGGER dbo.TR_AuditLogs_PreventTampering;
GO

CREATE TRIGGER dbo.TR_AuditLogs_PreventTampering
ON dbo.AuditLogs
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    RAISERROR (N'سجل التدقيق الأمني (AuditLogs) محمي للقراءة والإضافة فقط؛ يُمنع تعديل أو حذف السجلات.', 16, 1);
    ROLLBACK TRANSACTION;
END;
GO

PRINT N'✓ تم تفعيل حماية عدم التلاعب على جدول AuditLogs.';
GO

/* ----------------------------------------------------------------------------
   3. (اختياري للإنتاج — مُوصى به بشدة) إنشاء مستخدم تطبيق بمبدأ أقل صلاحية
      استبدل كلمة المرور القوية قبل إزالة التعليق وتشغيل هذا القسم.
   ---------------------------------------------------------------------------- */
/*
USE [master];
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'wathiq_app_login')
BEGIN
    CREATE LOGIN [wathiq_app_login]
        WITH PASSWORD = N'REPLACE_WITH_STRONG_32_CHAR_PASSWORD!',
             CHECK_POLICY = ON,
             CHECK_EXPIRATION = OFF;
END;
GO

USE [ACCP_DB];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'wathiq_app_user')
BEGIN
    CREATE USER [wathiq_app_user] FOR LOGIN [wathiq_app_login];
END;
GO

ALTER ROLE [db_datareader] ADD MEMBER [wathiq_app_user];
ALTER ROLE [db_datawriter] ADD MEMBER [wathiq_app_user];

-- منع التطبيق صراحةً من تعديل أو حذف سجلات التدقيق أو تغيير بنية الجداول:
DENY UPDATE, DELETE ON dbo.AuditLogs TO [wathiq_app_user];
DENY ALTER, CONTROL, TAKE OWNERSHIP ON DATABASE::[ACCP_DB] TO [wathiq_app_user];
GO
*/

/* ----------------------------------------------------------------------------
   4. استعلام التحقق من تشفير البيانات المخزنة داخل SSMS
      أي قضية أو رسالة جديدة تُضاف عبر الموقع يجب أن تبدأ بـ enc:v1:
   ---------------------------------------------------------------------------- */
SELECT TOP 5
    Id,
    CaseNumber,
    LEFT([Title], 40) AS TitlePreview,
    LEFT([Description], 40) AS DescriptionPreview,
    CreatedAtUtc
FROM dbo.CyberCases
ORDER BY CreatedAtUtc DESC;
GO
