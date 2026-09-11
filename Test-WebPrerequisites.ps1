[CmdletBinding()]
param(
    [switch]$RepairAspNet
)

$ErrorActionPreference = "Stop"

$frameworkRoot = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"
$requiredAssemblies = @(
    "System.DirectoryServices.dll",
    "System.DirectoryServices.AccountManagement.dll"
)

$missingAssemblies = $requiredAssemblies | Where-Object {
    -not (Test-Path (Join-Path $frameworkRoot $_))
}

if ($missingAssemblies) {
    throw "Missing .NET Framework assemblies in '$frameworkRoot': $($missingAssemblies -join ', '). Install .NET Framework 4.8 (full), then run this check again."
}

$framework = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
if (-not $framework -or [int]$framework.Release -lt 528040) {
    throw ".NET Framework 4.8 or later is required on the IIS server."
}

if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $frameworkFeature = Get-WindowsFeature NET-Framework-45-Core
    if (-not $frameworkFeature.Installed) {
        if ($RepairAspNet) {
            Install-WindowsFeature NET-Framework-45-Core | Out-Host
        } else {
            throw "The IIS server does not have the full .NET Framework feature installed. Run this script with -RepairAspNet from an elevated PowerShell session."
        }
    }

    $aspNet = Get-WindowsFeature Web-Asp-Net45
    if (-not $aspNet.Installed) {
        if ($RepairAspNet) {
            Install-WindowsFeature Web-Asp-Net45 | Out-Host
        } else {
            throw "The IIS ASP.NET 4.x feature is not installed. Run this script with -RepairAspNet from an elevated PowerShell session."
        }
    }
}

$gacPaths = @(
    "$env:WINDIR\Microsoft.NET\assembly\GAC_MSIL\System.DirectoryServices\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.DirectoryServices.dll",
    "$env:WINDIR\Microsoft.NET\assembly\GAC_MSIL\System.DirectoryServices.AccountManagement\v4.0_4.0.0.0__b77a5c561934e089\System.DirectoryServices.AccountManagement.dll"
)
if (@($gacPaths | Where-Object { -not (Test-Path $_) }).Count -gt 0) {
    throw "The required DirectoryServices assemblies are not registered in the .NET Framework GAC. Repair or reinstall .NET Framework 4.8 on the IIS server, then run this check again."
}

$aspNetReg = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe"
if ($RepairAspNet -and (Test-Path $aspNetReg)) {
    & $aspNetReg -iru
    if ($LASTEXITCODE -ne 0) {
        throw "ASP.NET registration failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Web Forms prerequisites are present." -ForegroundColor Green
Write-Host "Set the IIS application pool to .NET CLR v4.0, enable 64-bit applications, and recycle the pool."
