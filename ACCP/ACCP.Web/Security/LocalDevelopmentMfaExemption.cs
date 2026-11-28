using System.Net;
using System.Globalization;
using System.Security.Claims;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace ACCP.Web.Security;

/// <summary>
/// Allows one explicitly named ADMIN-only account to skip MFA in local
/// Development, only when the login request is addressed to loopback.
/// This exemption is supplied by a per-process environment variable and is
/// never persisted to the account or database.
/// </summary>
public static class LocalDevelopmentMfaExemption
{
    public const string EmailEnvironmentVariable =
        "ACCP_LOCAL_MFA_EXEMPT_EMAIL";
    public const string ClaimType =
        "wathiq:local-development-mfa-exempt";
    public const string ClaimValue = "true";
    public const string ExpiresAtClaimType =
        "wathiq:local-development-mfa-exempt-until";
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(2);

    public static bool IsEnabledForLogin(
        HttpContext context,
        IWebHostEnvironment environment,
        string? accountEmail,
        bool isAdminOnly) =>
        IsConfigured(environment, accountEmail, isAdminOnly) &&
        IsLoopbackRequest(context);

    public static bool HasValidPrincipalClaim(
        ClaimsPrincipal principal,
        IWebHostEnvironment environment,
        string? accountEmail,
        bool isAdminOnly)
    {
        if (!IsConfigured(environment, accountEmail, isAdminOnly) ||
            principal.FindAll(ClaimType).Count() != 1 ||
            !principal.HasClaim(ClaimType, ClaimValue) ||
            principal.FindAll(ExpiresAtClaimType).Count() != 1)
        {
            return false;
        }

        var expiryValue = principal.FindFirstValue(ExpiresAtClaimType);
        return long.TryParse(
                expiryValue,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var expiryUnixSeconds) &&
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() <
                expiryUnixSeconds;
    }

    private static bool IsConfigured(
        IWebHostEnvironment environment,
        string? accountEmail,
        bool isAdminOnly)
    {
        if (!environment.IsDevelopment() || !isAdminOnly ||
            string.IsNullOrWhiteSpace(accountEmail))
        {
            return false;
        }

        var exemptEmail = Environment.GetEnvironmentVariable(
            EmailEnvironmentVariable)?.Trim();
        return !string.IsNullOrWhiteSpace(exemptEmail) &&
            string.Equals(
                exemptEmail,
                accountEmail.Trim(),
                StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsLoopbackRequest(HttpContext context)
    {
        var host = context.Request.Host.Host;
        var localHost = string.Equals(
                host,
                "localhost",
                StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(host, out var address) &&
                IPAddress.IsLoopback(address);
        if (!localHost)
        {
            return false;
        }

        var remoteAddress = context.Connection.RemoteIpAddress;
        return remoteAddress is not null &&
            (IPAddress.IsLoopback(remoteAddress) ||
            remoteAddress.IsIPv4MappedToIPv6 &&
                IPAddress.IsLoopback(remoteAddress.MapToIPv4()));
    }
}
