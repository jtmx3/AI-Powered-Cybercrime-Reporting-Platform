using System.ComponentModel.DataAnnotations;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace ACCP.Web.Pages.Account;

[AllowAnonymous]
[AutoValidateAntiforgeryToken]
[EnableRateLimiting("reporter-recovery-request")]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[RequestSizeLimit(16 * 1024)]
public sealed class ForgotPasswordModel : PageModel
{
    private readonly ReporterPasswordResetService _recovery;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(
        ReporterPasswordResetService recovery,
        ILogger<ForgotPasswordModel> logger)
    {
        _recovery = recovery;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool RequestCompleted { get; private set; }
    public string ConfirmationMessage { get; private set; } = string.Empty;

    public void OnGet()
    {
        PrepareResponse();
        Input = new InputModel();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        PrepareResponse();
        if (!ModelState.IsValid) return Page();

        var email = Input?.Email?.Trim() ?? string.Empty;
        if (email.Length is 0 or > 256 || email.Any(char.IsControl) ||
            !new EmailAddressAttribute().IsValid(email))
        {
            ModelState.AddModelError("Input.Email", "أدخل بريدًا إلكترونيًا صحيحًا.");
            return Page();
        }

        var started = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            // Eligibility is checked against current database roles by the
            // recovery service. Posted role/user identifiers are never used.
            await _recovery.RequestResetAsync(email, HttpContext.RequestAborted);
        }
        catch (Exception exception) when (!HttpContext.RequestAborted.IsCancellationRequested)
        {
            // Keep response/status identical for unknown emails, staff,
            // disabled accounts, and provider failures. Log only a category;
            // exception messages can contain recipients or reset links.
            _logger.LogWarning(new EventId(4710, "PasswordRecoveryRequestFailed"),
                "Password recovery request could not be processed. Failure category: {FailureCategory}.",
                exception.GetType().Name);
        }
        finally
        {
            Input = new InputModel();
            ModelState.Clear();
        }

        // Pad fast paths (unknown/staff email) to reduce timing side-channel against SMTP sends.
        var remainingMs = 650 - (int)started.ElapsedMilliseconds;
        if (remainingMs > 0 && !HttpContext.RequestAborted.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(remainingMs, HttpContext.RequestAborted);
            }
            catch (OperationCanceledException)
            {
            }
        }

        RequestCompleted = true;
        ConfirmationMessage = ReporterPasswordResetService.RequestConfirmation;
        return Page();
    }

    private void PrepareResponse()
    {
        RequestCompleted = false;
        ConfirmationMessage = string.Empty;
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Content-Security-Policy"] =
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
    }

    public sealed class InputModel
    {
        [Required(ErrorMessage = "أدخل البريد الإلكتروني.")]
        [EmailAddress(ErrorMessage = "أدخل بريدًا إلكترونيًا صحيحًا.")]
        [StringLength(256, ErrorMessage = "البريد الإلكتروني طويل جدًا.")]
        public string Email { get; set; } = string.Empty;
    }
}