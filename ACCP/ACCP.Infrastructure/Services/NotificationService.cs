using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Infrastructure.Services;

public class NotificationService : INotificationService
{
    private readonly AccpDbContext _dbContext;

    public NotificationService(
        AccpDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<UserNotification> CreateAsync(
        Guid recipientUserId,
        Guid? cyberCaseId,
        NotificationType type,
        string title,
        string message)
    {
        if (recipientUserId == Guid.Empty)
        {
            throw new ArgumentException(
                "معرّف مستلم الإشعار غير صالح.",
                nameof(recipientUserId));
        }

        string cleanTitle = title.Trim();
        string cleanMessage = message.Trim();

        if (string.IsNullOrWhiteSpace(cleanTitle) ||
            cleanTitle.Length > 200)
        {
            throw new ArgumentException(
                "عنوان الإشعار غير صالح.",
                nameof(title));
        }

        if (string.IsNullOrWhiteSpace(cleanMessage) ||
            cleanMessage.Length > 1000)
        {
            throw new ArgumentException(
                "نص الإشعار غير صالح.",
                nameof(message));
        }

        var notification = new UserNotification
        {
            RecipientUserId = recipientUserId,
            CyberCaseId = cyberCaseId,
            Type = type,
            Title = cleanTitle,
            Message = cleanMessage,
            IsRead = false,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.UserNotifications.Add(notification);

        await _dbContext.SaveChangesAsync();

        return notification;
    }

    public async Task<List<UserNotification>> GetForUserAsync(
        Guid recipientUserId)
    {
        if (recipientUserId == Guid.Empty)
        {
            return [];
        }

        return await _dbContext.UserNotifications
            .AsNoTracking()
            .Where(notification =>
                notification.RecipientUserId == recipientUserId)
            .OrderByDescending(notification =>
                notification.CreatedAtUtc)
            .Take(100)
            .ToListAsync();
    }

    public async Task<int> GetUnreadCountAsync(
        Guid recipientUserId)
    {
        if (recipientUserId == Guid.Empty)
        {
            return 0;
        }

        return await _dbContext.UserNotifications
            .CountAsync(notification =>
                notification.RecipientUserId == recipientUserId &&
                !notification.IsRead);
    }

    public async Task<bool> MarkAsReadAsync(
        Guid notificationId,
        Guid recipientUserId)
    {
        if (notificationId == Guid.Empty ||
            recipientUserId == Guid.Empty)
        {
            return false;
        }

        UserNotification? notification =
            await _dbContext.UserNotifications
                .FirstOrDefaultAsync(notification =>
                    notification.Id == notificationId &&
                    notification.RecipientUserId ==
                        recipientUserId);

        if (notification is null)
        {
            return false;
        }

        if (!notification.IsRead)
        {
            notification.IsRead = true;
            notification.ReadAtUtc = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();
        }

        return true;
    }

    public async Task<int> MarkAllAsReadAsync(
        Guid recipientUserId)
    {
        if (recipientUserId == Guid.Empty)
        {
            return 0;
        }

        DateTime readAtUtc = DateTime.UtcNow;

        return await _dbContext.UserNotifications
            .Where(notification =>
                notification.RecipientUserId == recipientUserId &&
                !notification.IsRead)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(
                    notification => notification.IsRead,
                    true)
                .SetProperty(
                    notification => notification.ReadAtUtc,
                    readAtUtc));
    }
}