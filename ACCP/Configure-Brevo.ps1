[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The SMTP key is read securely and passed to dotnet through stdin.
# Neither the key nor the JSON payload is printed or added to command arguments.
function Invoke-AccpSecretCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Arguments,
        [AllowNull()][string]$InputJson
    )

    $accpProcess = New-Object System.Diagnostics.Process
    $accpStarted = $false
    try {
        $accpProcess.StartInfo.FileName = $script:accpDotnetPath
        $accpProcess.StartInfo.Arguments = $Arguments
        $accpProcess.StartInfo.UseShellExecute = $false
        $accpProcess.StartInfo.CreateNoWindow = $true
        $accpProcess.StartInfo.RedirectStandardInput = $true
        $accpProcess.StartInfo.RedirectStandardOutput = $true
        $accpProcess.StartInfo.RedirectStandardError = $true
        $accpStarted = $accpProcess.Start()
        if (-not $accpStarted) { throw 'dotnet could not start.' }

        $accpOutputTask = $accpProcess.StandardOutput.ReadToEndAsync()
        $accpErrorTask = $accpProcess.StandardError.ReadToEndAsync()
        if ($null -ne $InputJson) {
            $accpInputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputJson)
            $accpProcess.StandardInput.BaseStream.Write($accpInputBytes, 0, $accpInputBytes.Length)
            $accpProcess.StandardInput.BaseStream.Flush()
            [Array]::Clear($accpInputBytes, 0, $accpInputBytes.Length)
        }
        $accpProcess.StandardInput.Close()
        if (-not $accpProcess.WaitForExit(60000)) {
            $accpProcess.Kill()
            throw 'dotnet timed out.'
        }
        # Discard output: malformed input/provider errors must never expose data.
        $null = $accpOutputTask.GetAwaiter().GetResult()
        $null = $accpErrorTask.GetAwaiter().GetResult()
        if ($accpProcess.ExitCode -ne 0) {
            throw 'dotnet user-secrets failed. Check the .NET SDK and project file.'
        }
    }
    catch {
        throw 'Could not update user-secrets. Check that dotnet build succeeds, then retry.'
    }
    finally {
        if ($accpStarted) {
            try { if (-not $accpProcess.HasExited) { $accpProcess.Kill() } } catch { }
        }
        $accpProcess.Dispose()
    }
}

$accpKeySecure = $null
$accpKeyPlain = $null
$accpPayload = $null
$accpJson = $null

try {
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw 'Save this script as Configure-Brevo.ps1 in the ACCP folder and run it with -File.'
    }
    $accpProject = Join-Path $PSScriptRoot 'ACCP.Web\ACCP.Web.csproj'
    if (-not (Test-Path -LiteralPath $accpProject -PathType Leaf)) {
        throw 'ACCP.Web\ACCP.Web.csproj was not found. Place this script in the ACCP project root.'
    }
    $accpProject = (Resolve-Path -LiteralPath $accpProject).Path
    $script:accpDotnetPath = (Get-Command dotnet -CommandType Application -ErrorAction Stop).Source

    $accpLogin = (Read-Host 'Brevo SMTP login (copy the Login field from the SMTP page)').Trim()
    $accpSender = (Read-Host 'Verified From email in Brevo').Trim()
    foreach ($accpAddress in @($accpLogin, $accpSender)) {
        if ([string]::IsNullOrWhiteSpace($accpAddress) -or $accpAddress.Length -gt 256 -or
            $accpAddress -match '[\r\n]' -or $accpAddress -notmatch '@') {
            throw 'Enter a valid SMTP login and verified sender email.'
        }
        $accpParsed = New-Object System.Net.Mail.MailAddress($accpAddress)
        if ($accpParsed.Address -cne $accpAddress -or $accpParsed.DisplayName.Length -gt 0) {
            throw 'Enter the email address only, without a display name.'
        }
    }

    # Offer the HTTP launch profile as a local development default, if present.
    $accpDefaultUrl = ''
    $accpLaunchFile = Join-Path (Split-Path -Parent $accpProject) 'Properties\launchSettings.json'
    if (Test-Path -LiteralPath $accpLaunchFile -PathType Leaf) {
        try {
            $accpLaunch = Get-Content -LiteralPath $accpLaunchFile -Raw | ConvertFrom-Json
            $accpProfile = $accpLaunch.profiles.PSObject.Properties['http']
            if ($null -ne $accpProfile) {
                $accpUrlProperty = $accpProfile.Value.PSObject.Properties['applicationUrl']
                if ($null -ne $accpUrlProperty) {
                    $accpDefaultUrl = ([string]$accpUrlProperty.Value).Split(';')[0].Trim()
                }
            }
        }
        catch { $accpDefaultUrl = '' }
    }
    $accpPrompt = 'App base URL, including port (example: http://localhost:5221)'
    if ($accpDefaultUrl) { $accpPrompt += " - Enter uses $accpDefaultUrl" }
    $accpBaseUrl = (Read-Host $accpPrompt).Trim()
    if ([string]::IsNullOrWhiteSpace($accpBaseUrl)) { $accpBaseUrl = $accpDefaultUrl }
    $accpUri = $null
    if (-not [Uri]::TryCreate($accpBaseUrl, [UriKind]::Absolute, [ref]$accpUri) -or
        $accpUri.UserInfo.Length -gt 0 -or $accpUri.Query.Length -gt 0 -or
        $accpUri.Fragment.Length -gt 0 -or $accpUri.AbsolutePath -ne '/' -or
        ($accpUri.Scheme -ne 'https' -and
         -not ($accpUri.Scheme -eq 'http' -and $accpUri.IsLoopback))) {
        throw 'Use the app root URL with its port; HTTPS or local-development HTTP only.'
    }

    $accpKeySecure = Read-Host 'Paste the FULL Brevo SMTP key (input is hidden)' -AsSecureString
    $accpKeyPlain = [System.Net.NetworkCredential]::new('', $accpKeySecure).Password.Trim()
    if ($accpKeyPlain.Length -lt 15 -or $accpKeyPlain.Length -gt 4096 -or
        $accpKeyPlain -match '\s') {
        throw 'The SMTP key is empty, incomplete, or contains whitespace. Retry with the full key.'
    }

    Invoke-AccpSecretCommand -Arguments ('user-secrets init --project "' + $accpProject + '"')
    $accpPayload = [ordered]@{
        'Email:Smtp:Host' = 'smtp-relay.brevo.com'
        'Email:Smtp:Port' = '587'
        'Email:Smtp:SecurityMode' = 'StartTls'
        'Email:Smtp:Username' = $accpLogin
        'Email:Smtp:Password' = $accpKeyPlain
        'Email:Smtp:FromEmail' = $accpSender
        'Email:Smtp:FromName' = 'ACCP'
        'Email:Smtp:TimeoutSeconds' = '30'
        'AccountRecovery:PublicBaseUrl' = $accpUri.AbsoluteUri.TrimEnd('/')
    }
    $accpJson = $accpPayload | ConvertTo-Json -Compress
    Invoke-AccpSecretCommand -Arguments ('user-secrets set --project "' + $accpProject + '"') -InputJson $accpJson
    Write-Host 'Brevo settings saved successfully for local development.' -ForegroundColor Green
    Write-Host 'No email was sent. Next: register the email services in Program.cs.'
}
finally {
    if ($null -ne $accpKeySecure) { $accpKeySecure.Dispose() }
    if ($null -ne $accpPayload) { $accpPayload['Email:Smtp:Password'] = $null; $accpPayload.Clear() }
    $accpKeyPlain = $null
    $accpJson = $null
}