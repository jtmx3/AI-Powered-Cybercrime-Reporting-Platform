using System.ComponentModel.DataAnnotations;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace ACCP.Web.Pages.Account;

[AllowAnonymous]
[AutoValidateAntiforgeryToken]
[EnableRateLimiting("reporter-recovery-reset")]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[RequestSizeLimit(64 * 1024)]
public sealed class ResetPasswordModel : PageModel
{
    private const string InvalidLink = "رابط الاستعادة غير صالح أو انتهت صلاحيته. اطلب رابطًا جديدًا.";
    private readonly ReporterPasswordResetService _recovery;
    private readonly ILogger<ResetPasswordModel> _logger;

    public ResetPasswordModel(ReporterPasswordResetService recovery, ILogger<ResetPasswordModel> logger)
    {
        _recovery = recovery;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();
    public bool ShowResetForm { get; private set; }
    public bool RequestCompleted { get; private set; }
    public string ConfirmationMessage { get; private set; } = string.Empty;

    public void OnGet(string? token)
    {
        PrepareResponse();
        ModelState.Clear();
        Input = new InputModel();
        if (!HasTokenShape(token))
        {
            ModelState.AddModelError(string.Empty, InvalidLink);
            return;
        }
        // Actual expiry, eligibility and single use are checked on POST.
        Input.Token = token!;
        ShowResetForm = true;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        PrepareResponse();
        Input ??= new InputModel();
        try
        {
            if (!HasTokenShape(Input.Token))
            {
                Input.Token = string.Empty;
                ModelState.Clear();
                ModelState.AddModelError(string.Empty, InvalidLink);
                return Page();
            }
            ShowResetForm = true;
            if (!ModelState.IsValid) return Page();
            var result = await _recovery.ResetPasswordAsync(
                Input.Token, Input.Password, HttpContext.RequestAborted);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, result.Message);
                return Page();
            }
            Input.Token = string.Empty;
            ModelState.Clear();
            ShowResetForm = false;
            RequestCompleted = true;
            ConfirmationMessage = result.Message;
            // Password recovery never signs the browser in automatically.
            return Page();
        }
        catch (Exception exception) when (!HttpContext.RequestAborted.IsCancellationRequested)
        {
            // Never log exception messages, tickets or passwords.
            _logger.LogWarning(new EventId(4711, "PasswordRecoveryResetFailed"),
                "Password recovery reset failed. Failure category: {FailureCategory}.",
                exception.GetType().Name);
            ModelState.AddModelError(string.Empty, "تعذر إكمال الاستعادة. حاول مرة أخرى.");
            return Page();
        }
        finally
        {
            Input.Password = string.Empty;
            Input.ConfirmPassword = string.Empty;
            ClearPostedValue("Input.Password");
            ClearPostedValue("Input.ConfirmPassword");
        }
    }

    private void ClearPostedValue(string key)
    {
        // Retain validation errors while erasing attempted and raw values.
        if (ModelState.ContainsKey(key))
            ModelState.SetModelValue(key, string.Empty, string.Empty);
    }

    private static bool HasTokenShape(string? token) =>
        !string.IsNullOrEmpty(token) && token.Length <= 16384 &&
        !token.Any(character => char.IsWhiteSpace(character) || char.IsControl(character));

    private void PrepareResponse()
    {
        ShowResetForm = false;
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
        [Required(ErrorMessage = InvalidLink)]
        [StringLength(16384, ErrorMessage = InvalidLink)]
        public string Token { get; set; } = string.Empty;

        [Required(ErrorMessage = "أدخل كلمة المرور الجديدة.")]
        [StringLength(128, MinimumLength = 8, ErrorMessage = "كلمة المرور يجب أن تكون بين 8 و128 حرفًا.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "أكّد كلمة المرور الجديدة.")]
        [StringLength(128, ErrorMessage = "تأكيد كلمة المرور طويل جدًا.")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "كلمتا المرور غير متطابقتين.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}