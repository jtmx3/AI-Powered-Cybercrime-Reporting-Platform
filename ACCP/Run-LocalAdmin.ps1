$ErrorActionPreference = 'Stop'

$projectPath = Join-Path $PSScriptRoot 'ACCP.Web\ACCP.Web.csproj'
if (-not (Test-Path -LiteralPath $projectPath)) {
    throw 'تعذر العثور على ACCP.Web. يجب أن يكون هذا الملف داخل مجلد ACCP في المشروع.'
}

$email = (Read-Host 'البريد الإلكتروني لحساب Admin').Trim()
if ([string]::IsNullOrWhiteSpace($email)) {
    throw 'البريد الإلكتروني مطلوب.'
}

$securePassword = Read-Host 'كلمة المرور (لن تظهر أثناء الكتابة)' -AsSecureString
$plainPassword = [System.Net.NetworkCredential]::new('', $securePassword).Password

$variables = @(
    'ASPNETCORE_ENVIRONMENT',
    'DOTNET_ENVIRONMENT',
    'ASPNETCORE_URLS',
    'ACCP_ADMIN_EMAIL',
    'ACCP_ADMIN_PASSWORD',
    'ACCP_LOCAL_MFA_EXEMPT_EMAIL'
)
$previousValues = @{}
foreach ($name in $variables) {
    $previousValues[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        'Process'
    )
}

try {
    $env:ASPNETCORE_ENVIRONMENT = 'Development'
    $env:DOTNET_ENVIRONMENT = 'Development'
    $env:ASPNETCORE_URLS = 'http://localhost:5221'
    $env:ACCP_ADMIN_EMAIL = $email
    $env:ACCP_ADMIN_PASSWORD = $plainPassword
    $env:ACCP_LOCAL_MFA_EXEMPT_EMAIL = $email

    Write-Host ''
    Write-Host 'Development local run; MFA exception applies only to this Admin email.'
    Write-Host 'Open: http://localhost:5221/login'
    Write-Host 'Press Ctrl+C in this window to stop the app.'
    Write-Host ''

    & dotnet run --no-launch-profile --project $projectPath
    if ($LASTEXITCODE -ne 0) {
        throw 'تعذر تشغيل التطبيق. راجع رسالة الخطأ أعلاه.'
    }
}
finally {
    foreach ($name in $variables) {
        $previousValue = $previousValues[$name]
        if ($null -eq $previousValue) {
            Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
        }
        else {
            [Environment]::SetEnvironmentVariable(
                $name,
                $previousValue,
                'Process'
            )
        }
    }

    $plainPassword = $null
    $securePassword.Dispose()
}
