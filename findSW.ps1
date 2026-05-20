<#
.SYNOPSIS
    ESRM Agent v1.0.0 - Enterprise Software Risk Monitor
.DESCRIPTION
    Scans locally installed software and generates a JSON file for upload to ESRM.
.PARAMETER Username
    Your ESRM system username (default: Windows login name).
.PARAMETER OutputPath
    Path where the JSON file will be saved (default: Desktop\esrm-scan.json).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File esrm-agent.ps1
    powershell -ExecutionPolicy Bypass -File esrm-agent.ps1 -Username "john"
#>
param(
    [string]$Username = $env:USERNAME.ToLower(),
    [string]$OutputPath   = "scan.json"
)

Write-Host "==================================="
Write-Host " NISTCVECheck Scan PC Software v1.0.0"
Write-Host "==================================="
Write-Host ""
Write-Host "[INFO] ESRM Username : $Username"
Write-Host "[INFO] Hostname      : $env:COMPUTERNAME"
Write-Host "[INFO] Scanning installed software..."

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$rawList = @()
foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayVersion }
        foreach ($app in $apps) {
            $rawList += [PSCustomObject]@{
                name        = $app.DisplayName.Trim()
                version     = $app.DisplayVersion.Trim()
                publisher   = if ($app.Publisher)       { $app.Publisher.Trim() }               else { $null }
                installDate = if ($app.InstallDate)     { $app.InstallDate }                    else { $null }
                installPath = if ($app.InstallLocation) { $app.InstallLocation.TrimEnd('\') }   else { $null }
            }
        }
    }
}

# Deduplicate by name+version
$seen      = @{}
$softwares = @()
foreach ($sw in $rawList) {
    $key = "$($sw.name)|$($sw.version)"
    if (-not $seen.ContainsKey($key)) {
        $seen[$key] = $true
        $softwares += $sw
    }
}
$softwares = $softwares | Sort-Object name

Write-Host "[INFO] Found $($softwares.Count) installed software entries."

$output = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    hostname    = $env:COMPUTERNAME
    username    = $Username
    softwares   = $softwares
}

# Write UTF-8 without BOM so it can be parsed by any JSON reader
$json = $output | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "[OK] Saved to: $OutputPath"
Write-Host ""
Write-Host "==================================="
Write-Host " Next steps"
Write-Host "==================================="
Write-Host ""
Write-Host " 1. Log in to the ESRM system."
Write-Host " 2. Go to [My Software] in the left sidebar."
Write-Host " 3. Click [Upload Scan Result] and select:"
Write-Host "    $OutputPath"
Write-Host ""
Write-Host " NOTE: The username inside the JSON must match your ESRM login."
Write-Host "       Current value: $Username"
Write-Host "       To override, run with: -Username yourESRMaccount"
Write-Host ""
