namespace ACCP.Application.Security;

/// <summary>
/// Delivers a password-reset link to the email stored on the eligible account.
/// Account eligibility and token generation belong to the reset service.
/// </summary>
public interface IPasswordResetEmailSender
{
    /// <summary>
    /// Sends the link through the configured email provider.
    /// </summary>
    /// <param name="recipientEmail">The account's current email address.</param>
    /// <param name="resetLink">
    /// An absolute HTTPS link created by the application using its configured
    /// public address. It must not be created from an untrusted request host.
    /// </param>
    /// <param name="cancellationToken">Cancels the send operation.</param>
    /// <remarks>
    /// Implementations must report delivery failures by throwing an exception.
    /// Never log or display the link or its token as a substitute for sending.
    /// </remarks>
    Task SendPasswordResetLinkAsync(
        string recipientEmail,
        Uri resetLink,
        CancellationToken cancellationToken = default);
}