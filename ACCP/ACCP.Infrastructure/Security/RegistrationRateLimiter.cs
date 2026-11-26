using System.Collections.Concurrent;
using ACCP.Application.Security;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// Thread-safe, memory-bounded sliding-window rate limiter and Argon2id concurrency bulkhead
/// protecting interactive registration endpoints against single-WebSocket floods and CPU/RAM exhaustion.
/// </summary>
public sealed class RegistrationRateLimiter : IRegistrationRateLimiter, IDisposable
{
    private readonly int _maxAttemptsPerWindow;
    private readonly TimeSpan _window;
    private readonly int _maxTrackedClients;
    private readonly SemaphoreSlim _concurrencyGate;
    private readonly ConcurrentDictionary<string, ClientBucket> _buckets = new(StringComparer.Ordinal);
    private int _disposed;

    public RegistrationRateLimiter(
        int maxAttemptsPerWindow = 5,
        TimeSpan? window = null,
        int maxConcurrentRegistrations = 4,
        int maxTrackedClients = 10_000)
    {
        if (maxAttemptsPerWindow <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxAttemptsPerWindow));
        if (maxConcurrentRegistrations <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentRegistrations));
        if (maxTrackedClients <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxTrackedClients));

        _maxAttemptsPerWindow = maxAttemptsPerWindow;
        _window = window ?? TimeSpan.FromMinutes(15);
        _maxTrackedClients = maxTrackedClients;
        _concurrencyGate = new SemaphoreSlim(maxConcurrentRegistrations, maxConcurrentRegistrations);
    }

    public RegistrationRateLease TryAcquire(string? clientIp, DateTimeOffset? utcNow = null)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        var now = utcNow ?? DateTimeOffset.UtcNow;
        var key = NormalizeKey(clientIp);

        PruneIfNeeded(now);

        // Enforce per-IP sliding window before consuming an expensive Argon2id concurrency slot.
        var bucket = _buckets.GetOrAdd(key, _ => new ClientBucket());
        lock (bucket.SyncRoot)
        {
            bucket.PruneExpired(now, _window);

            if (bucket.Timestamps.Count >= _maxAttemptsPerWindow)
            {
                var oldest = bucket.Timestamps.Peek();
                var retryAfter = Math.Max(1, (int)Math.Ceiling((oldest + _window - now).TotalSeconds));
                return RegistrationRateLease.Reject(retryAfter, "RegistrationRateLimitExceeded");
            }

            if (!_concurrencyGate.Wait(0))
            {
                return RegistrationRateLease.Reject(5, "RegistrationConcurrencySaturated");
            }

            bucket.Timestamps.Enqueue(now);
            bucket.LastSeenUtc = now;
        }

        return RegistrationRateLease.Allow(() =>
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                try
                {
                    _concurrencyGate.Release();
                }
                catch (ObjectDisposedException)
                {
                    // Ignore release during shutdown disposal.
                }
            }
        });
    }

    public int TrackedClientCount => _buckets.Count;

    private static string NormalizeKey(string? clientIp)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return "unknown";
        }

        var trimmed = clientIp.Trim();
        return trimmed.Length > 64 ? trimmed[..64] : trimmed;
    }

    private void PruneIfNeeded(DateTimeOffset now)
    {
        if (_buckets.Count < _maxTrackedClients)
        {
            return;
        }

        foreach (var pair in _buckets)
        {
            var bucket = pair.Value;
            bool isExpired;
            lock (bucket.SyncRoot)
            {
                bucket.PruneExpired(now, _window);
                isExpired = bucket.Timestamps.Count == 0 && (now - bucket.LastSeenUtc) >= _window;
            }

            if (isExpired)
            {
                _buckets.TryRemove(pair.Key, out _);
            }
        }

        // Hard safety cap against synthetic IP-spoofing floods within a single window.
        if (_buckets.Count >= _maxTrackedClients)
        {
            var excess = _buckets.Count - (_maxTrackedClients / 2);
            foreach (var key in _buckets.Keys)
            {
                if (excess <= 0) break;
                if (_buckets.TryRemove(key, out _))
                {
                    excess--;
                }
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _concurrencyGate.Dispose();
        }
    }

    private sealed class ClientBucket
    {
        public object SyncRoot { get; } = new();
        public Queue<DateTimeOffset> Timestamps { get; } = new();
        public DateTimeOffset LastSeenUtc { get; set; }

        public void PruneExpired(DateTimeOffset now, TimeSpan window)
        {
            var cutoff = now - window;
            while (Timestamps.Count > 0 && Timestamps.Peek() <= cutoff)
            {
                Timestamps.Dequeue();
            }
        }
    }
}
