using System.Globalization;
using System.Net;
using System.Security.Claims;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace ACCP.Tests;

public sealed class LocalDevelopmentMfaExemptionTests
{
    [Fact]
    public void Exemption_IsLimitedToConfiguredAdminOnLocalDevelopmentRequest()
    {
        var previousValue = Environment.GetEnvironmentVariable(
            LocalDevelopmentMfaExemption.EmailEnvironmentVariable);

        try
        {
            Environment.SetEnvironmentVariable(
                LocalDevelopmentMfaExemption.EmailEnvironmentVariable,
                "local-admin@example.test");

            var environment = new TestWebHostEnvironment
            {
                EnvironmentName = Environments.Development
            };
            var context = NewLocalContext();

            Assert.True(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "LOCAL-ADMIN@example.test",
                hasAdminRole: true));
            Assert.False(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "another-admin@example.test",
                hasAdminRole: true));
            Assert.False(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "local-admin@example.test",
                hasAdminRole: false));

            var principal = NewExemptionPrincipal(
                DateTimeOffset.UtcNow.AddMinutes(5));
            Assert.True(LocalDevelopmentMfaExemption.HasValidPrincipalClaim(
                principal,
                environment,
                "local-admin@example.test",
                hasAdminRole: true));
            Assert.False(LocalDevelopmentMfaExemption.HasValidPrincipalClaim(
                NewExemptionPrincipal(DateTimeOffset.UtcNow.AddMinutes(-1)),
                environment,
                "local-admin@example.test",
                hasAdminRole: true));

            environment.EnvironmentName = Environments.Production;
            Assert.False(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "local-admin@example.test",
                hasAdminRole: true));
            Assert.False(LocalDevelopmentMfaExemption.HasValidPrincipalClaim(
                principal,
                environment,
                "local-admin@example.test",
                hasAdminRole: true));

            environment.EnvironmentName = Environments.Development;
            context.Request.Host = new HostString("dev.example.test");
            Assert.False(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "local-admin@example.test",
                hasAdminRole: true));

            context.Request.Host = new HostString("localhost");
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.8");
            Assert.False(LocalDevelopmentMfaExemption.IsEnabledForLogin(
                context,
                environment,
                "local-admin@example.test",
                hasAdminRole: true));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                LocalDevelopmentMfaExemption.EmailEnvironmentVariable,
                previousValue);
        }
    }

    private static DefaultHttpContext NewLocalContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("localhost");
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        return context;
    }

    private static ClaimsPrincipal NewExemptionPrincipal(
        DateTimeOffset expiresAt) =>
        new(new ClaimsIdentity(
        [
            new Claim(
                LocalDevelopmentMfaExemption.ClaimType,
                LocalDevelopmentMfaExemption.ClaimValue),
            new Claim(
                LocalDevelopmentMfaExemption.ExpiresAtClaimType,
                expiresAt.ToUnixTimeSeconds().ToString(
                    CultureInfo.InvariantCulture))
        ],
        "test"));

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "ACCP.Tests";
        public IFileProvider WebRootFileProvider { get; set; } =
            new NullFileProvider();
        public string WebRootPath { get; set; } = string.Empty;
        public string EnvironmentName { get; set; } = string.Empty;
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
