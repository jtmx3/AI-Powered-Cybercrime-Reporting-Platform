namespace ACCP.Domain.Enums;

/// <summary>
/// Distinguishes a request for assistance from a formal report.
/// These numeric values must remain stable once stored in the database.
/// </summary>
public enum CasePath
{
    /// <summary>
    /// Assistance that is not automatically submitted to the officer queue.
    /// </summary>
    Assistance = 1,

    /// <summary>
    /// A report submitted for review and assignment by authorized staff.
    /// </summary>
    FormalReport = 2
}