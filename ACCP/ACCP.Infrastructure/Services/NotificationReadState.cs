namespace ACCP.Web.Services;

public sealed class NotificationReadState
{
    public event Action? Changed;

    public void NotifyChanged()
    {
        Changed?.Invoke();
    }
}