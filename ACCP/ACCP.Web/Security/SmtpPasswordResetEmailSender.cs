using System.Security.Authentication;
using System.Text.Encodings.Web;
using ACCP.Application.Security;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace ACCP.Web.Security;

public sealed class SmtpPasswordResetEmailSender : IPasswordResetEmailSender
{
    private readonly IOptions<SmtpPasswordResetOptions> _options;
    private readonly IHostEnvironment _environment;

    public SmtpPasswordResetEmailSender(
        IOptions<SmtpPasswordResetOptions> options,
        IHostEnvironment environment)
    {
        _options = options;
        _environment = environment;
    }

    public async Task SendPasswordResetLinkAsync(
        string recipientEmail,
        Uri resetLink,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var settings = _options.Value;
        var security = ValidateSettings(settings);
        var recipient = ParseAddress(recipientEmail);
        ValidateLink(resetLink);

        var message = CreateMessage(settings, recipient, resetLink);
        using var client = new SmtpClient
        {
            Timeout = settings.TimeoutSeconds * 1000,
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CheckCertificateRevocation = true
        };
        // No protocol logger and no certificate-validation bypass: neither
        // the SMTP password nor reset links belong in application logs.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        try
        {
            await client.ConnectAsync(
                settings.Host.Trim(), settings.Port, security, deadline.Token);
            await client.AuthenticateAsync(
                settings.Username.Trim(), settings.Password, deadline.Token);
            await client.SendAsync(message, deadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("انتهت مهلة إرسال رسالة الاستعادة.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Provider responses can contain recipient or message details.
            // Keep them out of exceptions consumed by public reset pages.
            throw new InvalidOperationException(
                "تعذر إرسال رسالة الاستعادة. راجع إعدادات خدمة البريد.");
        }
        finally
        {
            if (client.IsConnected)
            {
                // A failed QUIT must not report an already accepted message
                // as failed or trigger a duplicate email. Dispose closes it.
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try { await client.DisconnectAsync(true, cleanup.Token); }
                catch (Exception) { }
            }
        }
    }

    private static SecureSocketOptions ValidateSettings(SmtpPasswordResetOptions settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Host) || settings.Host.Length > 253 ||
            settings.Host.Any(char.IsWhiteSpace) || settings.Host.Any(char.IsControl) ||
            Uri.CheckHostName(settings.Host) == UriHostNameType.Unknown ||
            settings.Port is < 1 or > 65535 ||
            settings.TimeoutSeconds is < 5 or > 60 ||
            string.IsNullOrWhiteSpace(settings.Username) || settings.Username.Length > 256 ||
            settings.Username.Any(char.IsControl) ||
            string.IsNullOrEmpty(settings.Password) || settings.Password.Length > 4096 ||
            settings.FromName is null || settings.FromName.Length > 128 ||
            settings.FromName.Any(char.IsControl))
            throw new InvalidOperationException("إعدادات Email:Smtp ناقصة أو غير صالحة.");

        _ = ParseAddress(settings.FromEmail);
        return settings.SecurityMode?.Trim() switch
        {
            "StartTls" => SecureSocketOptions.StartTls,
            "SslOnConnect" => SecureSocketOptions.SslOnConnect,
            _ => throw new InvalidOperationException(
                "Email:Smtp:SecurityMode must be StartTls or SslOnConnect.")
        };
    }

    private static MailboxAddress ParseAddress(string? value)
    {
        var address = value?.Trim() ?? string.Empty;
        if (address.Length is 0 or > 256 || address.Any(char.IsControl) ||
            !MailboxAddress.TryParse(address, out var mailbox) ||
            !string.IsNullOrEmpty(mailbox.Name) ||
            !string.Equals(mailbox.Address, address, StringComparison.Ordinal))
            throw new InvalidOperationException("عنوان البريد غير صالح للإرسال.");
        return mailbox;
    }

    private void ValidateLink(Uri? resetLink)
    {
        if (resetLink is null || !resetLink.IsAbsoluteUri ||
            resetLink.AbsoluteUri.Length > 16_384 ||
            !string.IsNullOrEmpty(resetLink.UserInfo) ||
            !string.IsNullOrEmpty(resetLink.Fragment) ||
            (resetLink.Scheme != Uri.UriSchemeHttps &&
             !(_environment.IsDevelopment() && resetLink.IsLoopback &&
               resetLink.Scheme == Uri.UriSchemeHttp)))
            throw new InvalidOperationException("رابط استعادة كلمة المرور غير صالح للإرسال.");
    }

    private static MimeMessage CreateMessage(
        SmtpPasswordResetOptions settings, MailboxAddress recipient, Uri resetLink)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings.FromName.Trim(), settings.FromEmail.Trim()));
        message.To.Add(recipient);
        message.Subject = "ACCP | استعادة كلمة المرور";
        message.Date = DateTimeOffset.UtcNow;
        var link = resetLink.AbsoluteUri;
        var safeLink = HtmlEncoder.Default.Encode(link);
        message.Body = new BodyBuilder
        {
            TextBody = $"""
                استعادة كلمة المرور — ACCP

                وصلنا طلب لاستعادة كلمة مرور حسابك.
                افتح الرابط التالي لتعيين كلمة مرور جديدة:

                {link}

                الرابط صالح لمدة 30 دقيقة من وقت طلبه، ويُستخدم مرة واحدة بعد تغيير كلمة المرور.
                إذا لم تطلب الاستعادة، تجاهل هذه الرسالة؛ كلمة المرور لم تتغيّر.
                لا تشارك رابط الاستعادة مع أي شخص.
                """,
            HtmlBody = $"""
                <!DOCTYPE html>
                <html lang="ar" dir="rtl">
                <body style="margin:0;padding:24px;background:#f5f7fb;font-family:Arial,sans-serif;color:#163f59;line-height:1.9;">
                  <div style="max-width:560px;margin:auto;padding:28px;background:white;border:1px solid #dde6ee;border-radius:16px;">
                    <p style="margin:0;color:#0f766e;font-weight:bold;" dir="ltr">ACCP</p>
                    <h1 style="font-size:24px;">استعادة كلمة المرور</h1>
                    <p>وصلنا طلب لاستعادة كلمة مرور حسابك. اضغط الزر لتعيين كلمة مرور جديدة.</p>
                    <p style="margin:28px 0;"><a href="{safeLink}" style="display:inline-block;background:#0f766e;color:white;text-decoration:none;padding:12px 24px;border-radius:10px;">تعيين كلمة مرور جديدة</a></p>
                    <p>الرابط صالح لمدة <strong>30 دقيقة من وقت طلبه</strong>، ويُستخدم مرة واحدة بعد تغيير كلمة المرور.</p>
                    <p style="color:#596b7b;">إذا لم تطلب الاستعادة، تجاهل هذه الرسالة؛ كلمة المرور لم تتغيّر. لا تشارك الرابط مع أي شخص.</p>
                    <p style="font-size:13px;color:#596b7b;">إذا لم يعمل الزر، انسخ الرابط التالي إلى المتصفح:</p>
                    <p dir="ltr" style="font-size:12px;overflow-wrap:anywhere;"><a href="{safeLink}">{safeLink}</a></p>
                  </div>
                </body>
                </html>
                """
        }.ToMessageBody();
        return message;
    }
}

// Bind Email:Smtp to this class. Store the Password in user-secrets during
// development or in the hosting secret store, never in source-controlled JSON.
public sealed class SmtpPasswordResetOptions
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public string SecurityMode { get; set; } = "StartTls";
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = "ACCP";
    public int TimeoutSeconds { get; set; } = 30;
}