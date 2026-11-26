using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace ACCP.Web.Security;

/// <summary>
/// Global Zero-Trust HTTP security headers middleware.
/// Applies strict defense-in-depth headers to every response while respecting
/// even stricter endpoint-specific policies (such as evidence sandboxing or recovery pages).
/// </summary>
public static class SecurityHeadersMiddleware
{
    private const string DefaultCsp =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; " +
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self' ws: wss:; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'";

    public static IApplicationBuilder UseAccpSecurityHeaders(this IApplicationBuilder app)
    {
        return app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;

                headers.Remove("Server");
                headers.Remove("X-Powered-By");

                if (!headers.ContainsKey("X-Content-Type-Options"))
                {
                    headers["X-Content-Type-Options"] = "nosniff";
                }

                if (!headers.ContainsKey("X-Frame-Options"))
                {
                    headers["X-Frame-Options"] = "DENY";
                }

                if (!headers.ContainsKey("Referrer-Policy"))
                {
                    headers["Referrer-Policy"] = "no-referrer";
                }

                if (!headers.ContainsKey("Permissions-Policy"))
                {
                    headers["Permissions-Policy"] =
                        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
                }

                if (!headers.ContainsKey("Cross-Origin-Opener-Policy"))
                {
                    headers["Cross-Origin-Opener-Policy"] = "same-origin";
                }

                if (!headers.ContainsKey("Cross-Origin-Resource-Policy"))
                {
                    headers["Cross-Origin-Resource-Policy"] = "same-origin";
                }

                if (!headers.ContainsKey("Content-Security-Policy"))
                {
                    headers["Content-Security-Policy"] = DefaultCsp;
                }

                return Task.CompletedTask;
            });

            await next(context);
        });
    }
}
