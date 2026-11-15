using ACCP.Application.Auditing;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed class AuthorizedAuditService : IAuditService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AuditService _writer;

    public AuthorizedAuditService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory,
        AuditService writer)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
        _writer = writer;
    }

    // تسجيل الأحداث يستخدم نطاق العملية الأصلية.
    // يشمل ذلك محاولات الدخول الفاشلة قبل تسجيل الدخول.
    public Task<AuditLog> WriteAsync(
        AuditLogRequest request,
        CancellationToken cancellationToken = default) =>
        _writer.WriteAsync(
            request,
            cancellationToken);

    public Task<IReadOnlyList<AuditLog>> GetLatestAsync(
        int take = 200,
        CancellationToken cancellationToken = default) =>
        ReadAsAdminAsync(
            service => service.GetLatestAsync(
                take,
                cancellationToken),
            cancellationToken);

    public Task<IReadOnlyList<AuditLog>> GetForCaseAsync(
        Guid cyberCaseId,
        int take = 200,
        CancellationToken cancellationToken = default) =>
        ReadAsAdminAsync(
            service => service.GetForCaseAsync(
                cyberCaseId,
                take,
                cancellationToken),
            cancellationToken);

    public Task<IReadOnlyList<AuditLog>> SearchAsync(
        string? searchTerm = null,
        AuditAction? action = null,
        bool? isSuccessful = null,
        int take = 500,
        CancellationToken cancellationToken = default) =>
        ReadAsAdminAsync(
            service => service.SearchAsync(
                searchTerm,
                action,
                isSuccessful,
                take,
                cancellationToken),
            cancellationToken);

    private async Task<IReadOnlyList<AuditLog>> ReadAsAdminAsync(
        Func<AuditService, Task<IReadOnlyList<AuditLog>>> operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var actor = await _authorization.GetCurrentActorAsync(
            cancellationToken);

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(IdentityRoles.Admin))
        {
            throw new UnauthorizedAccessException(
                "قراءة سجل التدقيق متاحة للمدير فقط. " +
                "تأكد من صلاحية حسابك وسجّل الدخول مجددًا.");
        }

        await using var scope = _scopeFactory.CreateAsyncScope();

        var service = scope.ServiceProvider
            .GetRequiredService<AuditService>();

        return await operation(service);
    }
}