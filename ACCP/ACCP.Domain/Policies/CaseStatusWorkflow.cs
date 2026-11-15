using ACCP.Domain.Enums;

namespace ACCP.Domain.Policies;

public static class CaseStatusWorkflow
{
    public const CaseStatus ReopenedStatus =
        CaseStatus.InProgress;

    // قواعد الحالات فقط؛ صلاحية المستخدم وسبب الإجراء
    // تتحقق منهما الخدمة التي تنفذ العملية.
    public static IReadOnlyList<CaseStatus>
        GetAllowedNextStatuses(CaseStatus current)
    {
        CaseStatus[] next = current switch
        {
            CaseStatus.New =>
                [
                    CaseStatus.UnderReview,
                    CaseStatus.Assigned
                ],

            CaseStatus.UnderReview =>
                [
                    CaseStatus.Assigned
                ],

            CaseStatus.Assigned =>
                [
                    CaseStatus.InProgress
                ],

            CaseStatus.InProgress =>
                [
                    CaseStatus.Resolved,
                    CaseStatus.Closed
                ],

            CaseStatus.Resolved =>
                [
                    CaseStatus.Closed
                ],

            _ => []
        };

        return Array.AsReadOnly(next);
    }

    public static bool CanTransition(
        CaseStatus current,
        CaseStatus next)
    {
        if (!Enum.IsDefined(current) ||
            !Enum.IsDefined(next) ||
            current == next)
        {
            return false;
        }

        return GetAllowedNextStatuses(current).Contains(next);
    }

    // تحديد قابلية الحالة لإعادة الفتح لا يمنح المستخدم صلاحية.
    public static bool IsReopenable(CaseStatus current) =>
        current is CaseStatus.Resolved or CaseStatus.Closed;
}