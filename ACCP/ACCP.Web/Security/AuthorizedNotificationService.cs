using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed class AuthorizedNotificationService : INotificationService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly NotificationService _writer;

    public event Action? ReadStateChanged;

    public AuthorizedNotificationService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory,
        NotificationService writer)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
        _writer = writer;
    }

    // تبقى كتابة الإشعار ضمن نطاق العملية الأصلية
    // للحفاظ على معاملتها مع تغييرات القضية.
    public Task<UserNotification> CreateAsync(
        Guid recipientUserId,
        Guid? cyberCaseId,
        NotificationType type,
        string title,
        string message) =>
        _writer.CreateAsync(
            recipientUserId,
            cyberCaseId,
            type,
            title,
            message);

    public Task<List<UserNotification>> GetForUserAsync(
        Guid recipientUserId) =>
        ExecuteForOwnerAsync(
            recipientUserId,
            (service, userId) =>
                service.GetForUserAsync(userId));

    public Task<int> GetUnreadCountAsync(
        Guid recipientUserId) =>
        ExecuteForOwnerAsync(
            recipientUserId,
            (service, userId) =>
                service.GetUnreadCountAsync(userId));

    public async Task<bool> MarkAsReadAsync(
        Guid notificationId,
        Guid recipientUserId)
    {
        var marked = await ExecuteForOwnerAsync(
            recipientUserId,
            (service, userId) =>
                service.MarkAsReadAsync(
                    notificationId,
                    userId));

        if (marked)
            NotifyReadStateChanged();

        return marked;
    }

    public async Task<int> MarkAllAsReadAsync(
        Guid recipientUserId)
    {
        var affected = await ExecuteForOwnerAsync(
            recipientUserId,
            (service, userId) =>
                service.MarkAllAsReadAsync(userId));

        NotifyReadStateChanged();

        return affected;
    }

    private void NotifyReadStateChanged()
    {
        var handlers = ReadStateChanged;

        if (handlers is null)
            return;

        foreach (Action handler in handlers.GetInvocationList())
        {
            try
            {
                handler();
            }
            catch
            {
                // فشل تحديث مكوّن واجهة لا يغيّر نتيجة الحفظ الناجح.
            }
        }
    }

    private async Task<T> ExecuteForOwnerAsync<T>(
        Guid requestedUserId,
        Func<NotificationService, Guid, Task<T>> operation)
    {
        var actor = await _authorization.GetCurrentActorAsync();

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            requestedUserId != actor.UserId)
        {
            throw new UnauthorizedAccessException(
                "لا تملك صلاحية الوصول لهذه الإشعارات، " +
                "أو انتهت صلاحية جلستك.");
        }

        await using var scope = _scopeFactory.CreateAsyncScope();

        var service = scope.ServiceProvider
            .GetRequiredService<NotificationService>();

        return await operation(service, actor.UserId);
    }
}