using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class PlatformUser
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string FullName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public UserRole Role { get; set; } =
        UserRole.User;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;
}