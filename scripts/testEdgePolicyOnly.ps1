<#
    testEdgePolicyOnly.ps1

    DIAGNOSTIC ONLY - not part of the kiosk deployment.

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

    Nothing here is destructive to existing Edge policy - run
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

# --- Allowlist domains: copied verbatim from kioskMode.ps1 (keep in sync) ---
$DefaultAllowedDomains = @(
    # --- Core Microsoft / Office ---
    "*.cloud.microsoft", "*.microsoft.com", "*.office.com", "*.office.net",
    "*.office365.com", "*.officeapps.live.com", "*.microsoftonline.com",
    "*.microsoftonline-p.com", "*.msocdn.com", "*.onmicrosoft.com",
    "*.static.microsoft", "*.usercontent.microsoft", "*cdn.onenote.net",
    "*.onenote.com", "*.online.office.com", "*.o365weve.com",
    "aka.ms", "www.microsoft.com", "www.microsoft365.com",
    "admin.microsoft.com", "compliance.microsoft.com", "purview.microsoft.com",
    "security.microsoft.com", "defender.microsoft.com", "*.security.microsoft.com",
    "*.protection.office.com", "*.protection.outlook.com", "protection.office.com",
    "support.microsoft.com", "docs.microsoft.com", "msdn.microsoft.com",
    "technet.microsoft.com", "go.microsoft.com", "c1.microsoft.com",
    "officeredir.microsoft.com", "officepreviewredir.microsoft.com",
    "officeclient.microsoft.com", "office15client.microsoft.com",
    "officecdn.microsoft.com", "o15.officeredir.microsoft.com",
    "appsforoffice.microsoft.com", "r.office.microsoft.com",
    "officespeech.platform.bing.com", "oneclient.sfx.ms",
    "activation.sls.microsoft.com", "amp.azure.net", "dgps.support.microsoft.com",
    "partnerservices.getmicrosoftkey.com", "ocos-office365-s2s.msedge.net",
    "dc.services.visualstudio.com", "*.events.data.microsoft.com",
    "*.aria.microsoft.com", "assets.onestore.ms", "adl.windows.com",

    # --- Sign-in / identity / Entra ID ---
    "login.microsoftonline.com", "login-us.microsoftonline.com",
    "login.microsoft.com", "login.live.com", "login.windows.net",
    "login.windows-ppe.net", "login.microsoftonline-p.com",
    "loginex.microsoftonline.com", "logincert.microsoftonline.com",
    "device.login.microsoftonline.com", "ccs.login.microsoftonline.com",
    "clientconfig.microsoftonline-p.net", "nexus.microsoftonline-p.com",
    "account.live.com", "account.activedirectory.windowsazure.com",
    "accounts.accesscontrol.windows.net", "activity.windows.com",
    "*.activity.windows.com", "adminwebservice.microsoftonline.com",
    "becws.microsoftonline.com", "companymanager.microsoftonline.com",
    "provisioningapi.microsoftonline.com", "passwordreset.microsoftonline.com",
    "api.passwordreset.microsoftonline.com", "signup.live.com",
    "autologon.microsoftazuread-sso.com", "enterpriseregistration.windows.net",
    "graph.microsoft.com", "graph.windows.net", "*.msftidentity.com",
    "*.msidentity.com", "*.msauth.net", "*.msauthimages.net",
    "*.msftauth.net", "*.msftauthimages.net", "*.auth.microsoft.com",
    "auth.gfx.ms", "mem.gfx.ms", "*.aadrm.com", "*.azurerms.com",
    "*.informationprotection.azure.com",
    "informationprotection.hosting.portal.azure.net",
    "*.portal.cloudappsecurity.com", "*.phonefactor.net",

    # --- Outlook / Exchange Online ---
    "*.outlook.com", "outlook.cloud.microsoft", "outlook.office.com",
    "outlook.office365.com", "www.outlook.com", "*.outlookmobile.com",
    "office.live.com", "apis.live.net", "storage.live.com", "c.live.com",
    "g.live.com", "*.acompli.net", "*.hip.live.com",

    # --- SharePoint / OneDrive ---
    "*.sharepoint.com", "*.sharepointonline.com", "admin.onedrive.com",
    "www.onedrive.com", "spoprod-a.akamaihd.net",

    # --- Teams / Skype / Yammer / Viva Engage ---
    "*.teams.microsoft.com", "*.teams.cloud.microsoft", "teams.microsoft.com",
    "teams.cloud.microsoft", "*.skype.com", "*.lync.com",
    "join.secure.skypeassets.com", "*.yammer.com", "*.yammerusercontent.com",
    "*.assets-yammer.com",

    # --- Power Platform / Sway ---
    "*.powerapps.com", "*.powerautomate.com", "*.flow.microsoft.com",
    "sway.com", "www.sway.com", "*.sway-cdn.com", "*.sway-extensions.com",
    "eus-www.sway-cdn.com", "eus-www.sway-extensions.com",
    "wus-www.sway-cdn.com", "wus-www.sway-extensions.com",

    # --- CDN / media / misc first-party ---
    "ajax.aspnetcdn.com", "*.appex.bing.com", "*.appex-rf.msn.com",
    "c.bing.com", "c.bing.net", "tse1.mm.bing.net", "www.bing.com",
    "*.virtualearth.net", "ecn.dev.virtualearth.net", "*.cortana.ai",
    "*.wns.windows.com", "*.msecnd.net", "prod.msocdn.com",
    "shellprod.msocdn.com", "cdn.odc.officeapps.live.com",
    "cdn.uci.officeapps.live.com", "*.streaming.mediaservices.windows.net",
    "*.keydelivery.mediaservices.windows.net", "mlccdnprod.azureedge.net",
    "otelrules.azureedge.net", "*.svc.ms", "*.azure-apim.net",
    "*.microsoftusercontent.com", "platform.linkedin.com",
    "autodiscover.*.onmicrosoft.com",

    # --- Certificate validation (OCSP/CRL) needed for TLS to the above ---
    "*.entrust.net", "*.geotrust.com", "*.omniroot.com", "*.public-trust.com",
    "*.verisign.com", "*.verisign.net", "*.symcb.com", "*.symcd.com",
    "cacerts.digicert.com", "crl3.digicert.com", "crl4.digicert.com",
    "ocsp.digicert.com", "ocspx.digicert.com", "www.digicert.com",
    "crl.globalsign.com", "crl.globalsign.net", "ocsp.globalsign.com",
    "ocsp2.globalsign.com", "secure.globalsign.com", "crl.identrust.com",
    "isrg.trustid.ocsp.identrust.com", "cert.int-x3.letsencrypt.org",
    "crl.microsoft.com", "mscrl.microsoft.com", "oneocsp.microsoft.com",
    "ocsp.msocsp.com"
)

function Get-M365AllowedDomains {
    # Fetches Microsoft's official Worldwide M365 endpoint list and returns
    # every domain served over HTTPS (443) - i.e. the set relevant to a
    # browser allowlist. Returns $null (never a partial/empty list) on any
    # failure so the caller can fall back cleanly.
    try {
        $uri = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$([guid]::NewGuid().ToString())&format=json"
        $endpoints = Invoke-RestMethod -Uri $uri -TimeoutSec 20 -ErrorAction Stop
        $domains = @(
            $endpoints |
                Where-Object { $_.urls -and "$($_.tcpPorts)" -match "443" } |
                ForEach-Object { $_.urls } |
                Sort-Object -Unique
        )
        if ($domains.Count -eq 0) { return $null }
        return $domains
    } catch {
        Write-Warning "Failed to fetch the Microsoft 365 endpoint list: $($_.Exception.Message)"
        return $null
    }
}

function Test-M365AllowedDomains {
    # Sanity-checks a fetched domain list before it's allowed to replace
    # whatever allowlist is already in place, guarding against a malformed,
    # truncated, or unexpectedly-shaped response being applied verbatim.
    param([string[]]$Domains)

    if (-not $Domains -or $Domains.Count -lt 100 -or $Domains.Count -gt 500) {
        return $false
    }
    $hostnamePattern = '^[A-Za-z0-9*][A-Za-z0-9.\-*]*\.[A-Za-z*]{2,}$'
    foreach ($d in $Domains) {
        if ([string]::IsNullOrWhiteSpace($d) -or $d.Length -gt 253 -or $d -notmatch $hostnamePattern) {
            return $false
        }
    }
    $mustContain = @("login.microsoftonline.com", "*.office.com", "*.sharepoint.com", "*.microsoftonline.com")
    foreach ($required in $mustContain) {
        if ($Domains -notcontains $required) { return $false }
    }
    return $true
}

function ConvertTo-EdgeUrlPatterns {
    # Edge's URL filter format only allows '*' as the entire host, so
    # "*.office.com" matches nothing. A bare host already covers all of its
    # subdomains, so reduce each wildcard to the nearest whole parent domain.
    param([string[]]$Domains)
    @(
        $Domains | ForEach-Object {
            $d = $_
            $star = $d.LastIndexOf('*')
            if ($star -ge 0) {
                $d = $d.Substring($star + 1)
                if (-not $d.StartsWith('.')) { $d = $d.Substring([Math]::Max($d.IndexOf('.'), 0)) }
                $d = $d.TrimStart('.')
            }
            if ($d) { $d.ToLowerInvariant() }
        } | Sort-Object -Unique
    )
}

function Confirm-RegistryValue {
    param($Path, $Name, $ExpectedValue)
    $actual = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($actual -and "$($actual.$Name)" -eq "$ExpectedValue") {
        Write-Host "  [OK] $Path\$Name = $ExpectedValue"
        return $true
    } else {
        $gotStr = if ($actual) { "$($actual.$Name)" } else { "<missing>" }
        Write-Warning "  [VERIFY FAILED] $Path\$Name - expected '$ExpectedValue', found '$gotStr' immediately after writing it"
        return $false
    }
}

function Set-TrackedValue {
    param($Path, $Name, $Value, $Type, [ref]$Changes)
    # New-Item -Force on an existing registry key recreates it empty, wiping all values and subkeys.
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
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
        Write-Warning "No state file at $StateFile - nothing recorded to revert."
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
if (-not (Test-Path "$EdgePolicyPath\URLBlocklist")) { New-Item -Path "$EdgePolicyPath\URLBlocklist" -Force | Out-Null }
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

# --- URLAllowlist (live M365 endpoint list, falling back to the built-in list) ---
$fetchedDomains = Get-M365AllowedDomains
if ($fetchedDomains -and (Test-M365AllowedDomains -Domains $fetchedDomains)) {
    Write-Host "Using live Microsoft 365 endpoint list ($($fetchedDomains.Count) entries)."
    $testDomains = $fetchedDomains
} else {
    Write-Warning "Live Microsoft 365 endpoint list unavailable - using the built-in fallback list ($($DefaultAllowedDomains.Count) entries)."
    $testDomains = $DefaultAllowedDomains
}
$testDomains = ConvertTo-EdgeUrlPatterns -Domains $testDomains
Write-Host "  $($testDomains.Count) allowlist patterns after conversion to Edge format."
$urlAllowlistExisted = Test-Path "$EdgePolicyPath\URLAllowlist"
if ($urlAllowlistExisted) {
    Get-Item "$EdgePolicyPath\URLAllowlist" | Select-Object -ExpandProperty Property | ForEach-Object {
        Remove-ItemProperty -Path "$EdgePolicyPath\URLAllowlist" -Name $_ -Force -ErrorAction SilentlyContinue
    }
} else {
    New-Item -Path "$EdgePolicyPath\URLAllowlist" -Force | Out-Null
}
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
Set-TrackedValue -Path $EdgePolicyPath -Name "DownloadRestrictions" -Value 3 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "InPrivateModeAvailability" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ClearBrowsingDataOnExit" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "SyncDisabled" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "PasswordManagerEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "AutofillAddressEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "AutofillCreditCardEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "AutoImportAtFirstRun" -Value 4 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "HubsSidebarEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "EdgeShoppingAssistantEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ShowMicrosoftRewards" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "EdgeCollectionsEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "EdgeWorkspacesEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "ShowRecommendationsEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "SpotlightExperiencesAndRecommendationsEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "PromotionalTabsEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "UserFeedbackAllowed" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "DefaultSearchProviderEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "SearchSuggestEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "TaskManagerEndProcessEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
Set-TrackedValue -Path $EdgePolicyPath -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)

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
