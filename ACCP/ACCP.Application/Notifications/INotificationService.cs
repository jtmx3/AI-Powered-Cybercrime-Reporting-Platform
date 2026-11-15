using ACCP.Domain.Entities;
using ACCP.Domain.Enums;

namespace ACCP.Application.Notifications;

public interface INotificationService
{
    Task<UserNotification> CreateAsync(
        Guid recipientUserId,
        Guid? cyberCaseId,
        NotificationType type,
        string title,
        string message);

    Task<List<UserNotification>> GetForUserAsync(
        Guid recipientUserId);

    Task<int> GetUnreadCountAsync(
        Guid recipientUserId);

    Task<bool> MarkAsReadAsync(
        Guid notificationId,
        Guid recipientUserId);

    Task<int> MarkAllAsReadAsync(
        Guid recipientUserId);
}