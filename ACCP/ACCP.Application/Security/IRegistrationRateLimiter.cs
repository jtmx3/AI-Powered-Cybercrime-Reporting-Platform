namespace ACCP.Application.Security;

/// <summary>
/// Per-client sliding-window rate limiter and concurrency bulkhead for interactive
/// account registration flows (e.g., Blazor SignalR circuits that bypass HTTP-only limiters).
/// </summary>
public interface IRegistrationRateLimiter
{
    RegistrationRateLease TryAcquire(string? clientIp, DateTimeOffset? utcNow = null);
}

public sealed class RegistrationRateLease : IDisposable
{
    private Action? _onDispose;

    private RegistrationRateLease(bool isAllowed, int retryAfterSeconds, string? reason, Action? onDispose)
    {
        IsAllowed = isAllowed;
        RetryAfterSeconds = retryAfterSeconds;
        Reason = reason;
        _onDispose = onDispose;
    }

    public bool IsAllowed { get; }
    public int RetryAfterSeconds { get; }
    public string? Reason { get; }

    public static RegistrationRateLease Allow(Action? onDispose = null) =>
        new(true, 0, null, onDispose);

    public static RegistrationRateLease Reject(int retryAfterSeconds, string reason) =>
        new(false, Math.Max(1, retryAfterSeconds), reason, null);

    public void Dispose()
    {
        Interlocked.Exchange(ref _onDispose, null)?.Invoke();
    }
}
