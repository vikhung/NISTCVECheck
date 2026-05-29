<#
.SYNOPSIS
    findSW.ps1 v1.0.0 - Software Inventory Scanner
.DESCRIPTION
    Scans locally installed software and generates a JSON file for CVE scanning.
.PARAMETER Username
    Your username (default: Windows login name).
.PARAMETER OutputPath
    Path where the JSON file will be saved (default: scan.json).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File findSW.ps1
    powershell -ExecutionPolicy Bypass -File findSW.ps1 -Username "john"
#>
param(
    [string]$Username = $env:USERNAME.ToLower(),
    [string]$OutputPath   = "scan.json"
)

Write-Host "==================================="
Write-Host " NISTCVECheck Scan PC Software v1.0.0"
Write-Host "==================================="
Write-Host ""
$localIP = try {
    ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
     Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
     Select-Object -First 1).IPAddressToString
} catch { '' }

Write-Host "[INFO] Username      : $Username"
Write-Host "[INFO] Hostname      : $env:COMPUTERNAME"
Write-Host "[INFO] IP            : $localIP"
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
    ip          = $localIP
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
Write-Host " 1. Copy $OutputPath to the machine running NISTCVECheck."
Write-Host " 2. Run: node cve-checker.js $OutputPath"
Write-Host "    Or upload via the web scanner (web-client.html)."
Write-Host ""
