<#
    testEdgePolicyOnly.ps1

    DIAGNOSTIC ONLY — not part of the kiosk deployment.

    Applies just the Microsoft Edge registry policy portion of
    kioskMode.ps1 (no Assigned Access / multi-app kiosk config, no
    per-user Task Manager lockdown, no shortcuts) so it can be run on a
    normal, non-kiosked machine/account to test whether the Edge policy
    registry values get silently reverted with Assigned Access entirely
    out of the picture.

    Logs an [OK]/[VERIFY FAILED] line immediately after every write (same
    as kioskMode.ps1), then re-checks everything once more at the end.

    USAGE (run elevated):
      .\testEdgePolicyOnly.ps1

    Nothing here is destructive to existing Edge policy — run
    testEdgePolicyOnly.ps1 -Remove afterward to clean up everything this
    script added.
#>

param(
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must run elevated (local admin)."
    exit 1
}

$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$HomepageUrl = "https://m365.cloud.microsoft/apps"
$StateFile = Join-Path $env:TEMP "testEdgePolicyOnly-state.json"

function Confirm-RegistryValue {
    param($Path, $Name, $ExpectedValue)
    $actual = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($actual -and "$($actual.$Name)" -eq "$ExpectedValue") {
        Write-Host "  [OK] $Path\$Name = $ExpectedValue"
        return $true
    } else {
        $gotStr = if ($actual) { "$($actual.$Name)" } else { "<missing>" }
        Write-Warning "  [VERIFY FAILED] $Path\$Name — expected '$ExpectedValue', found '$gotStr' immediately after writing it"
        return $false
    }
}

function Set-TrackedValue {
    param($Path, $Name, $Value, $Type, [ref]$Changes)
    New-Item -Path $Path -Force | Out-Null
    $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    $Changes.Value += [PSCustomObject]@{
        Path     = $Path
        Name     = $Name
        Existed  = $null -ne $existing
        Previous = if ($existing) { $existing.$Name } else { $null }
        NewValue = $Value
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Confirm-RegistryValue -Path $Path -Name $Name -ExpectedValue $Value | Out-Null
}

if ($Remove) {
    if (-not (Test-Path $StateFile)) {
        Write-Warning "No state file at $StateFile — nothing recorded to revert."
        exit 0
    }
    $state = Get-Content -Path $StateFile -Raw | ConvertFrom-Json
    foreach ($change in $state.RegistryChanges) {
        if ($change.Existed) {
            Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Previous -Force -ErrorAction SilentlyContinue
        } else {
            Remove-ItemProperty -Path $change.Path -Name $change.Name -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $state.UrlBlocklistKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\URLBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $state.UrlAllowlistKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\URLAllowlist" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $state.RestoreUrlsKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "Reverted."
    exit 0
}

$changes = @()

# --- URLBlocklist ---
$urlBlocklistExisted = (Get-Item "$EdgePolicyPath\URLBlocklist" -ErrorAction SilentlyContinue).Property.Count -gt 0
New-Item -Path "$EdgePolicyPath\URLBlocklist" -Force | Out-Null
New-ItemProperty -Path "$EdgePolicyPath\URLBlocklist" -Name "1" -Value "*" -PropertyType String -Force | Out-Null
Confirm-RegistryValue -Path "$EdgePolicyPath\URLBlocklist" -Name "1" -ExpectedValue "*" | Out-Null
$blockedInternalPages = @(
    "edge://settings", "edge://settings/*", "edge://extensions",
    "edge://extensions/*", "edge://flags", "edge://flags/*",
    "edge://version", "edge://net-internals", "edge://net-internals/*"
)
$i = 2
foreach ($page in $blockedInternalPages) {
    Set-TrackedValue -Path "$EdgePolicyPath\URLBlocklist" -Name "$i" -Value $page -Type String -Changes ([ref]$changes)
    $i++
}

# --- URLAllowlist (small fixed test set — no need to hit the M365 endpoint list for this test) ---
$testDomains = @("*.cloud.microsoft", "*.microsoft.com", "*.office.com", "login.microsoftonline.com")
$urlAllowlistExisted = Test-Path "$EdgePolicyPath\URLAllowlist"
if (-not $urlAllowlistExisted) { New-Item -Path "$EdgePolicyPath\URLAllowlist" -Force | Out-Null }
$i = 1
foreach ($domain in $testDomains) {
    New-ItemProperty -Path "$EdgePolicyPath\URLAllowlist" -Name "$i" -Value $domain -PropertyType String -Force | Out-Null
    $i++
}
$appliedAllowlistCount = (Get-Item "$EdgePolicyPath\URLAllowlist" -ErrorAction SilentlyContinue).Property.Count
Write-Host "  URLAllowlist entries present right after write: $appliedAllowlistCount (expected $($testDomains.Count))"

# --- RestoreOnStartupURLs ---
Set-TrackedValue -Path $EdgePolicyPath -Name "RestoreOnStartup" -Value 4 -Type DWord -Changes ([ref]$changes)
$restoreUrlsExisted = Test-Path "$EdgePolicyPath\RestoreOnStartupURLs"
if (-not $restoreUrlsExisted) { New-Item -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Force | Out-Null }
New-ItemProperty -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Name "1" -Value $HomepageUrl -PropertyType String -Force | Out-Null
Confirm-RegistryValue -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Name "1" -ExpectedValue $HomepageUrl | Out-Null

# --- Scalar Edge policies (same set kioskMode.ps1 writes) ---
Set-TrackedValue -Path $EdgePolicyPath -Name "HomepageLocation" -Value $HomepageUrl -Type String -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "HomepageIsNewTabPage" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "NewTabPageLocation" -Value $HomepageUrl -Type String -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "NewTabPageOverrideEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ShowHomeButton" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "HideFirstRunExperience" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -Type String -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "HideExtensionsMenu" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "DeveloperToolsAvailability" -Value 2 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserAddPersonEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserGuestModeEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "EditFavoritesEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserSignin" -Value 2 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "AADWebSiteSSOUsingThisProfileEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ConfigureOnPremisesAccountAutoSignIn" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "DownloadRestrictions" -Value 1 -Type DWord -Changes ([ref]$changes)

# --- Save state so -Remove can clean up precisely ---
$state = [PSCustomObject]@{
    UrlBlocklistKeyPreExisted = $urlBlocklistExisted
    UrlAllowlistKeyPreExisted = $urlAllowlistExisted
    RestoreUrlsKeyPreExisted  = $restoreUrlsExisted
    RegistryChanges           = $changes
}
$state | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding UTF8

# --- Final re-verification pass, same as kioskMode.ps1 ---
Write-Host ""
Write-Host "Re-checking all tracked registry values..."
$verifyFailures = 0
foreach ($change in $changes) {
    if (-not (Confirm-RegistryValue -Path $change.Path -Name $change.Name -ExpectedValue $change.NewValue)) {
        $verifyFailures++
    }
}
$finalBlocklistCount = (Get-Item "$EdgePolicyPath\URLBlocklist" -ErrorAction SilentlyContinue).Property.Count
$finalAllowlistCount = (Get-Item "$EdgePolicyPath\URLAllowlist" -ErrorAction SilentlyContinue).Property.Count
Write-Host "  URLBlocklist entries present: $finalBlocklistCount (expected $($blockedInternalPages.Count + 1))"
Write-Host "  URLAllowlist entries present: $finalAllowlistCount (expected $($testDomains.Count))"
if ($verifyFailures -gt 0 -or $finalBlocklistCount -ne ($blockedInternalPages.Count + 1) -or $finalAllowlistCount -ne $testDomains.Count) {
    Write-Warning "$verifyFailures tracked value(s) and/or the URLBlocklist/URLAllowlist counts no longer match what was just written."
} else {
    Write-Host "  All tracked values still present immediately after the run completed."
}

Write-Host ""
Write-Host "Done. Wait a bit and re-run 'reg query `"$EdgePolicyPath`" /s' manually to see if anything disappears later."
Write-Host "Run '.\testEdgePolicyOnly.ps1 -Remove' to clean up when finished testing."
