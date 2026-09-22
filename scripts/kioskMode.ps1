<#
    kioskMode.ps1

    Deploys (or fully removes) a Windows 11 25H2+ multi-app kiosk: OneAuth + a
    restricted, non-InPrivate Microsoft Edge locked to Microsoft 365 domains,
    both pinned to Start and the taskbar.
    Also disables Task Manager and "Change a password" on the Ctrl+Alt+Del
    screen for the kiosk account only, via that user's own registry hive -
    no other account on the machine is affected.
    If OneAuth isn't already installed for the kiosk account (or provisioned
    for the machine), it's provisioned machine-wide from the Microsoft Store
    via winget, and removed again on -Enabled false.
    Fully self-contained - writes the Assigned Access XML it needs to
    C:\ProgramData\Kiosk\, plus the Edge shortcut Start/taskbar pinning
    requires into the All Users Start Menu, at runtime.
    Reversing (-Enabled false) deletes those files, clears the Assigned Access
    config, and removes/restores only the registry values this script itself
    touched, leaving no trace.

    Every time -Enabled true runs (including re-runs against an
    already-kiosked machine), it tries to refresh the Microsoft 365 domain
    allowlist from Microsoft's official endpoint list
    (endpoints.office.com/endpoints/worldwide) and sanity-checks the result
    (plausible domain count, valid-looking hostnames, a handful of
    known-required domains present) before applying it. If the fetch or the
    sanity check fails, the currently-applied allowlist (or, on a first run,
    the built-in $DefaultAllowedDomains fallback below) is left untouched -
    the list is never wiped just because Microsoft's endpoint isn't
    reachable.

    USAGE
      Standalone:   .\kioskMode.ps1 -Enabled true [-KioskUser "AzureAD\user@tenant.com"]
                    .\kioskMode.ps1 -Enabled false
      SyncroRMM:    set a script variable named "enabled" to true / false, and
                    optionally "KioskUser" - both are picked up automatically,
                    no parameters needed.

      Both parameters default so that running the script with no arguments at
      all (either standalone or from Syncro with no variables set) enables
      kiosk mode for whichever user is currently logged on:
        -Enabled    defaults to "true"
        -KioskUser  defaults to "CurrentUser" - whichever user is currently
                    logged on interactively (resolved at runtime). Other
                    accepted values:
                      "AzureAD\user@tenant.com"  - an Azure AD account (a UPN)
                      "DOMAIN\User"              - an on-prem AD account
                      "COMPUTERNAME\LocalUser"   - a local account

    Must run elevated (SYSTEM or local admin). Edit the CONFIGURATION block
    below (OneAuth AUMID, homepage, allowed domains) before first use.
#>

# ===========================================================================
# Re-launch under 64-bit PowerShell if we're running as a 32-bit process on a
# 64-bit OS. HKLM:\SOFTWARE\Policies\... (everything this script writes to,
# including the Edge policy keys) is subject to WOW64 registry redirection -
# a 32-bit process writing there is silently redirected to
# HKLM:\SOFTWARE\WOW6432Node\..., which 64-bit Edge never reads. 
# Some RMM agents run scripts under a 32-bit
# PowerShell host even on 64-bit Windows, so this can't be assumed away.
# ===========================================================================
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Warning "Running as a 32-bit process on a 64-bit OS - re-launching under 64-bit PowerShell so registry writes land in the real (non-WOW6432Node) hive."
    $sysnativePwsh = Join-Path $env:WINDIR "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    $relaunchArgs = @($args)
    if (-not ($relaunchArgs -contains '-Enabled')) {
        if (Get-Variable -Name enabled -Scope Global -ErrorAction SilentlyContinue) {
            $relaunchArgs += @('-Enabled', "$((Get-Variable -Name enabled -Scope Global).Value)")
        } elseif ($env:enabled) {
            $relaunchArgs += @('-Enabled', "$env:enabled")
        }
    }
    if (-not ($relaunchArgs -contains '-KioskUser')) {
        if (Get-Variable -Name KioskUser -Scope Global -ErrorAction SilentlyContinue) {
            $relaunchArgs += @('-KioskUser', "$((Get-Variable -Name KioskUser -Scope Global).Value)")
        } elseif ($env:KioskUser) {
            $relaunchArgs += @('-KioskUser', "$env:KioskUser")
        }
    }
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { $scriptPath = $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path $sysnativePwsh)) {
        Write-Error "Could not re-launch under 64-bit PowerShell (script path or Sysnative host unavailable) - aborting rather than risk writing policy to the wrong registry view."
        exit 1
    }
    $relaunchArgList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath) + $relaunchArgs
    $proc = Start-Process -FilePath $sysnativePwsh -ArgumentList $relaunchArgList -NoNewWindow -Wait -PassThru
    exit $proc.ExitCode
}

$Enabled = $null
$KioskUser = $null
for ($i = 0; $i -lt $args.Count; $i++) {
    switch -Regex ("$($args[$i])") {
        '^-Enabled$'   { $Enabled = "$($args[++$i])" }
        '^-KioskUser$' { $KioskUser = "$($args[++$i])" }
        default {
            if ($null -eq $Enabled) { $Enabled = "$($args[$i])" }
            elseif ($null -eq $KioskUser) { $KioskUser = "$($args[$i])" }
        }
    }
}

# Make cmdlet failures (not just uncaught .NET exceptions) terminating, so
# every risky operation below is actually caught by its surrounding try/catch
# instead of printing an error and silently continuing.
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION - edit before first use
# ===========================================================================
$OneAuthAUMID   = "ZohoCorp.44386D730E544_hfrrf6a1akhx2!App"   # Zoho OneAuth
# Microsoft Store product ID for OneAuth (apps.microsoft.com/detail/<id>) -
# used to provision it machine-wide via winget if it's missing.
$OneAuthStoreId = "9NPG98QLH8JN"
$HomepageUrl    = "https://lbssheet-my.sharepoint.com/favorites"
# Fallback only - used when the live fetch from Microsoft's endpoint list
# (see Get-M365AllowedDomains below) fails or fails its sanity check AND
# there is no already-applied allowlist on the machine to fall back to
# instead (i.e. this is a first run with no network access). Otherwise
# this list is not used; keep it reasonably fresh but don't rely on it.
# Sourced from Microsoft's official Worldwide M365 endpoint list
# (https://endpoints.office.com/endpoints/worldwide), filtered to HTTPS (443)
# entries - i.e. every domain a browser may need to reach to use M365 web
# apps (Office, Outlook, SharePoint/OneDrive, Teams, sign-in, and the CDN/
# cert-validation domains those pages depend on).
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

$MinBuild = 26200   # Windows 11 25H2
$WorkDir  = Join-Path $env:ProgramData "Kiosk"
$XmlPath  = Join-Path $WorkDir "AssignedAccessConfig.xml"
$StateFile = Join-Path $WorkDir "kiosk-state.json"
# The multi-app kiosk AllowedApps schema has no attribute for passing launch
# arguments to a desktop app (confirmed via Microsoft-Windows-AssignedAccess/
# Admin: both "rs5:Arguments" and unprefixed "DesktopAppArguments" are
# rejected as undefined) - the only way to launch Edge at a specific
# homepage/with specific flags is to point DesktopAppPath at a prebuilt
# shortcut that already has those arguments baked in, rather than at
# msedge.exe directly.
# StartPins' desktopAppLink (and TaskbarLayout's DesktopApplicationLinkPath)
# only resolve a shortcut that actually lives under a Start Menu "Programs"
# folder - per Microsoft's own examples they're always
# %APPDATA%\...\Start Menu\Programs\... or %ALLUSERSPROFILE%\...\Start
# Menu\Programs\...  A shortcut anywhere else (e.g. our own WorkDir) is
# silently ignored, which is why Edge previously had no Start tile.
$EdgeShortcutName = "Edge-Kiosk.lnk"
$StartMenuProgramsDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$EdgeShortcutPath = Join-Path $StartMenuProgramsDir $EdgeShortcutName
# The %ALLUSERSPROFILE% env-var form (rather than the resolved path above) is
# what's embedded in the AssignedAccess XML/JSON, matching Microsoft's
# documented examples and staying correct even if ProgramData isn't at its
# default location.
$EdgeShortcutEnvPath = "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\$EdgeShortcutName"
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ProfileGuid = "{4c9a1e2b-6f3d-4a8e-9c2f-8b1d5e7a3c90}"
# Package name (e.g. "ZohoCorp.44386D730E544"), as Get-AppxPackage/
# Get-AppxProvisionedPackage report it - the AUMID minus publisher hash and app ID.
$OneAuthPackageName = (($OneAuthAUMID -split '!')[0] -split '_')[0]

# ===========================================================================
# Resolve desired state:
# -Enabled param > pre-existing $enabled (Syncro) > env var > "true"
# ===========================================================================
if ([string]::IsNullOrWhiteSpace($Enabled)) {
    if (Get-Variable -Name enabled -Scope Global -ErrorAction SilentlyContinue) {
        $Enabled = (Get-Variable -Name enabled -Scope Global).Value
    } elseif ($env:enabled) {
        $Enabled = $env:enabled
    }
}
if ([string]::IsNullOrWhiteSpace($Enabled)) {
    $Enabled = "true"
}
switch (("$Enabled").Trim().ToLower()) {
    { $_ -in @("true", "1") }  { $EnableKiosk = $true }
    { $_ -in @("false", "0") } { $EnableKiosk = $false }
    default {
        Write-Error "Specify -Enabled true|false, or set the Syncro 'enabled' script variable to true/false."
        exit 1
    }
}

# ===========================================================================
# Pre-flight checks
# ===========================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must run elevated (SYSTEM or local admin)."
    exit 1
}
try {
    $build = [int](Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber)
} catch {
    Write-Error "Could not determine the Windows build number: $($_.Exception.Message)"
    exit 1
}
if ($build -lt $MinBuild) {
    Write-Error "This script targets Windows 11 25H2 (build $MinBuild) or later. Detected build $build."
    exit 1
}
# Multi-app Assigned Access is not supported on Windows Home - EditionID is
# "Core"/"CoreN" there (vs. "Professional", "Enterprise", "Education", etc.),
# and attempting it anyway fails deep inside Enable-Kiosk with an opaque MDM
# error, so fail fast here with a clear reason instead.
try {
    $editionId = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name EditionID
} catch {
    Write-Error "Could not determine the Windows edition: $($_.Exception.Message)"
    exit 1
}
if ($editionId -match '^Core') {
    Write-Error "Windows $editionId (Home) does not support multi-app Assigned Access kiosk mode - Pro, Enterprise, or Education is required."
    exit 1
}

# ===========================================================================
# Resolve target kiosk user (only needed when enabling):
# -KioskUser param > pre-existing $KioskUser (Syncro) > env var > "CurrentUser"
# ===========================================================================
if ($EnableKiosk) {
    if ([string]::IsNullOrWhiteSpace($KioskUser)) {
        if (Get-Variable -Name KioskUser -Scope Global -ErrorAction SilentlyContinue) {
            $KioskUser = (Get-Variable -Name KioskUser -Scope Global).Value
        } elseif ($env:KioskUser) {
            $KioskUser = $env:KioskUser
        }
    }
    if ([string]::IsNullOrWhiteSpace($KioskUser)) {
        $KioskUser = "CurrentUser"
    }
    if ($KioskUser.Trim().ToLower() -eq "currentuser") {
        $currentUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
        if ([string]::IsNullOrWhiteSpace($currentUser)) {
            Write-Error "No user is currently logged on interactively - sign in first, or pass -KioskUser explicitly (e.g. 'AzureAD\user@tenant.com')."
            exit 1
        }
        $KioskUser = $currentUser
        Write-Host "Targeting currently logged-in user: $KioskUser"
    }
}

# ===========================================================================
# Helpers
# ===========================================================================
function Confirm-RegistryValue {
    # Re-reads a value right after writing it. Diagnostic only: catches values
    # silently lost after a successful write, which try/catch can't surface
    # (e.g. New-Item -Force recreating an existing key and wiping its values).
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

function Get-CurrentAllowlistDomains {
    # Reads back whatever domains are already applied in the Edge
    # URLAllowlist registry key, in their existing numeric order.
    if (-not (Test-Path "$EdgePolicyPath\URLAllowlist")) { return @() }
    $props = Get-ItemProperty -Path "$EdgePolicyPath\URLAllowlist" -ErrorAction SilentlyContinue
    if (-not $props) { return @() }
    return @(
        $props.PSObject.Properties |
            Where-Object { $_.Name -match '^\d+$' } |
            Sort-Object { [int]$_.Name } |
            ForEach-Object { $_.Value }
    )
}

function Resolve-KioskUserSid {
    # Resolves a KioskUser string (DOMAIN\User, COMPUTERNAME\LocalUser, or
    # AzureAD\user@tenant.com) to that account's Windows SID, so per-user
    # settings can be scoped to exactly that account and no other.
    param([string]$KioskUser)

    if ($KioskUser -notmatch '^(?i)AzureAD\\') {
        try {
            return (New-Object System.Security.Principal.NTAccount($KioskUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
    }

    # Fall back to matching against local profile folders - handles Azure AD
    # accounts (and anything NTAccount couldn't resolve directly), since a
    # signed-in AAD user's profile folder is named after their UPN's local part.
    $shortName = ($KioskUser -split '\\')[-1]
    $aliasStem = ($shortName -split '@')[0]
    return Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object {
            -not $_.Special -and $_.LocalPath -and
            (Split-Path $_.LocalPath -Leaf) -match "^$([regex]::Escape($aliasStem))(\.\w+)?$"
        } |
        Select-Object -First 1 -ExpandProperty SID
}

function Get-SystemWingetPath {
    # winget isn't on PATH for SYSTEM (it's a per-user App Execution Alias),
    # so find the newest App Installer package directly. Run as SYSTEM,
    # winget.exe also can't resolve its VC++ runtime dependency and exits
    # immediately with 0xC0000135 (STATUS_DLL_NOT_FOUND) - confirmed by
    # testing - so the VCLibs package folder is prepended to PATH as well.
    $windowsApps = Join-Path $env:ProgramFiles "WindowsApps"
    $newest = {
        param($Filter)
        Get-ChildItem -Path $windowsApps -Directory -Filter $Filter -ErrorAction SilentlyContinue |
            Sort-Object { [version](($_.Name -split '_')[1]) } -Descending |
            Select-Object -First 1
    }
    $wingetDir = & $newest "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if (-not $wingetDir -or -not (Test-Path (Join-Path $wingetDir.FullName "winget.exe"))) { return $null }
    $vclibsDir = & $newest "Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe"
    if ($vclibsDir -and $env:PATH -notlike "*$($vclibsDir.FullName)*") {
        $env:PATH = "$($vclibsDir.FullName);$env:PATH"
    }
    return Join-Path $wingetDir.FullName "winget.exe"
}

function Install-OneAuth {
    # Makes sure OneAuth will be available to the kiosk account. Skips if
    # it's already installed for that account or already provisioned for
    # the machine; otherwise provisions it machine-wide from the Microsoft
    # Store via winget (--scope machine), so Windows installs it for the
    # kiosk account at its next sign-in. Returns a state object describing
    # what it did (so Disable-Kiosk can undo only that), or $null if nothing
    # was installed. Never throws - failure only means a missing OneAuth
    # tile, which isn't worth aborting the rest of the kiosk setup over.
    param([string]$KioskSid)
    try {
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $OneAuthPackageName
        if ($provisioned) {
            Write-Host "OneAuth is already provisioned for this machine ($($provisioned.Version)) - skipping install."
            return $null
        }
        # Filtered from -AllUsers rather than using Get-AppxPackage -User
        # $KioskSid, which throws "No valid SID could be determined" for an
        # Azure AD account's SID on a machine that can't resolve it.
        # Also recorded so Disable-Kiosk only removes OneAuth from accounts
        # this install added it to, not from anyone who already had it.
        $preExistingUserSids = @(
            Get-AppxPackage -AllUsers -Name $OneAuthPackageName |
                ForEach-Object { $_.PackageUserInformation } |
                ForEach-Object { $_.UserSecurityId.Sid }
        )
        if ($KioskSid -and $preExistingUserSids -contains $KioskSid) {
            Write-Host "OneAuth is already installed for '$KioskUser' - skipping install."
            return $null
        }

        $winget = Get-SystemWingetPath
        if (-not $winget) {
            Write-Warning "OneAuth isn't installed and winget (App Installer) couldn't be found - the OneAuth tile will be missing until it's installed."
            return $null
        }
        Write-Host "OneAuth not found - provisioning it machine-wide from the Microsoft Store ($OneAuthStoreId)..."
        $wingetOutput = & $winget install --id $OneAuthStoreId --source msstore --scope machine `
            --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-String
        $wingetExit = $LASTEXITCODE
        Write-Host $wingetOutput.Trim()

        # Judge success by the actual provisioned state, not winget's exit
        # code alone (it has several non-zero "nothing to do" codes).
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $OneAuthPackageName
        if (-not $provisioned) {
            Write-Warning ("OneAuth install failed (winget exit code 0x{0:X8}) - the OneAuth tile will be missing until it's installed." -f $wingetExit)
            return $null
        }
        Write-Host "  [OK] OneAuth $($provisioned.Version) provisioned for all users."
        return [PSCustomObject]@{
            ProvisionedPackageName = $provisioned.PackageName
            PreExistingUserSids    = $preExistingUserSids
        }
    } catch {
        Write-Warning "OneAuth install check/install failed: $($_.Exception.Message) - the OneAuth tile will be missing until it's installed."
        return $null
    }
}

function Enable-Kiosk {
    Write-Host "Enabling kiosk configuration..."
    $workDirPreExisted = Test-Path $WorkDir
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

    # Populated as changes are made below. Saved in the `finally` block so
    # that a failure partway through still leaves an accurate state file
    # behind - otherwise a crash here would apply some registry/hive changes
    # but leave nothing to revert them, since the state file used to only be
    # written after everything succeeded.
    $changes = @()
    $previousAssignedAccessConfig = $null
    $urlBlocklistExisted = $false
    $urlAllowlistExisted = $false
    $restoreUrlsExisted = $false
    $perUserHiveState = $null
    $demotedFromAdmin = $null
    $oneAuthInstalled = $null

    function Save-KioskState {
        $state = [PSCustomObject]@{
            EnabledAt                    = (Get-Date).ToString("o")
            WorkDirPreExisted             = $workDirPreExisted
            PreviousAssignedAccessConfig  = $previousAssignedAccessConfig
            UrlBlocklistKeyPreExisted     = $urlBlocklistExisted
            UrlAllowlistKeyPreExisted     = $urlAllowlistExisted
            RestoreUrlsKeyPreExisted      = $restoreUrlsExisted
            RegistryChanges               = $changes
            PerUserHive                   = $perUserHiveState
            DemotedFromAdmin              = $demotedFromAdmin
            OneAuthInstalled              = $oneAuthInstalled
        }
        $state | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding UTF8
    }

    $succeeded = $false
    try {

    # --- Capture existing Assigned Access config so it can be restored exactly ---
    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_AssignedAccess"
    try {
        $aaObj = Get-CimInstance -Namespace $namespaceName -ClassName $className
    } catch {
        throw "Could not access the Assigned Access (MDM_AssignedAccess) WMI class - this Windows edition/SKU likely doesn't support multi-app kiosk mode. $($_.Exception.Message)"
    }
    $previousAssignedAccessConfig = $aaObj.Configuration

    # --- Resolve the kiosk account's SID up front (also used for the
    # per-user Task Manager lockdown below), and demote it out of
    # Administrators if it's currently a member: Assigned Access refuses to
    # configure an admin account and Windows surfaces that refusal as an
    # opaque "general error" from Set-CimInstance below rather than a clear
    # message, so this has to happen before that call, not after it fails.
    $kioskSid = Resolve-KioskUserSid -KioskUser $KioskUser
    if ($kioskSid) {
        $isAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
            Where-Object { $_.SID.Value -eq $kioskSid })
        if ($isAdmin) {
            Write-Host "'$KioskUser' is a local administrator - Assigned Access requires a standard account, so removing it from Administrators."
            Remove-LocalGroupMember -Group "Administrators" -Member $kioskSid
            $demotedFromAdmin = [PSCustomObject]@{ Sid = $kioskSid; WasAdmin = $true }
        }
    } else {
        Write-Warning "Could not resolve a SID for '$KioskUser' - cannot verify it isn't a local administrator (Assigned Access will fail with an opaque error if it is)."
    }

    # --- Make sure OneAuth (the kiosk's packaged app) is available to the
    # kiosk account - Assigned Access doesn't install apps, it just shows
    # nothing for an AUMID that isn't installed. ---
    $oneAuthInstalled = Install-OneAuth -KioskSid $kioskSid

    # --- Build a dedicated Edge shortcut with the homepage/flags baked in
    # (see the note above $EdgeShortcutPath - the CSP has no attribute for
    # this, so a shortcut is the only way to pass launch arguments). This is
    # only usable as the StartPins tile target, not as the AllowedApps entry
    # itself - AllowedApps must declare the real msedge.exe path (pointing it
    # at the .lnk instead fails later, at "Profile element validation", once
    # the XML is schema-valid but semantically wrong) - Windows resolves a
    # pinned shortcut's target back to an AllowedApps entry to validate it. ---
    $edgeExePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    New-Item -Path $StartMenuProgramsDir -ItemType Directory -Force | Out-Null
    $wshShell = New-Object -ComObject WScript.Shell
    $edgeShortcut = $wshShell.CreateShortcut($EdgeShortcutPath)
    $edgeShortcut.TargetPath = $edgeExePath
    $edgeShortcut.Arguments = "$HomepageUrl --no-first-run"
    $edgeShortcut.Save()

    # --- Write the Assigned Access XML ---
    # StartPins/TaskbarLayout are JSON/XML inside CDATA blocks, so any path
    # substituted into the JSON one needs its backslashes doubled (a lone
    # "\" is an invalid JSON escape); the XML one takes a plain backslash.
    $edgeShortcutPathJson = $EdgeShortcutEnvPath.Replace('\', '\\')
    $xml = @"
<?xml version="1.0" encoding="utf-8" ?>
<AssignedAccessConfiguration
    xmlns="http://schemas.microsoft.com/AssignedAccess/2017/config"
    xmlns:rs5="http://schemas.microsoft.com/AssignedAccess/201810/config"
    xmlns:win11="http://schemas.microsoft.com/AssignedAccess/2022/config">
    <Profiles>
        <Profile Id="$ProfileGuid">
            <AllAppsList>
                <AllowedApps>
                    <App AppUserModelId="$OneAuthAUMID" />
                    <App DesktopAppPath="$edgeExePath" />
                </AllowedApps>
            </AllAppsList>
            <win11:StartPins>
                <![CDATA[
                { "pinnedList": [
                    { "packagedAppId": "$OneAuthAUMID" },
                    { "desktopAppLink": "$edgeShortcutPathJson" }
                ] }
                ]]>
            </win11:StartPins>
            <Taskbar ShowTaskbar="true" />
            <win11:TaskbarLayout>
                <![CDATA[
                <?xml version="1.0" encoding="utf-8"?>
                <LayoutModificationTemplate
                    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
                    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
                    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
                    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
                    Version="1">
                    <CustomTaskbarLayoutCollection PinListPlacement="Replace">
                        <defaultlayout:TaskbarLayout>
                            <taskbar:TaskbarPinList>
                                <taskbar:DesktopApp DesktopApplicationID="$OneAuthAUMID" />
                                <taskbar:DesktopApp DesktopApplicationLinkPath="$EdgeShortcutEnvPath" />
                            </taskbar:TaskbarPinList>
                        </defaultlayout:TaskbarLayout>
                    </CustomTaskbarLayoutCollection>
                </LayoutModificationTemplate>
                ]]>
            </win11:TaskbarLayout>
        </Profile>
    </Profiles>
    <Configs>
        <Config>
            <Account>$KioskUser</Account>
            <DefaultProfile Id="$ProfileGuid" />
        </Config>
    </Configs>
</AssignedAccessConfiguration>
"@
    Set-Content -Path $XmlPath -Value $xml -Encoding UTF8

    # --- Apply via WMI Bridge ---
    Add-Type -AssemblyName System.Web
    $aaObj.Configuration = [System.Web.HttpUtility]::HtmlEncode((Get-Content -Path $XmlPath -Raw))
    Set-CimInstance -CimInstance $aaObj

    # --- Edge policy (registry), tracking every value touched ---
    $urlBlocklistExisted = (Get-Item "$EdgePolicyPath\URLBlocklist" -ErrorAction SilentlyContinue).Property.Count -gt 0
    if (-not (Test-Path "$EdgePolicyPath\URLBlocklist")) { New-Item -Path "$EdgePolicyPath\URLBlocklist" -Force | Out-Null }
    New-ItemProperty -Path "$EdgePolicyPath\URLBlocklist" -Name "1" -Value "*" -PropertyType String -Force | Out-Null
    Confirm-RegistryValue -Path "$EdgePolicyPath\URLBlocklist" -Name "1" -ExpectedValue "*" | Out-Null
    # URLBlocklist's "*" only covers web content - internal edge:// pages
    # aren't reliably caught by it (confirmed by testing: edge://settings
    # stayed reachable), and there's no dedicated "hide Settings" policy, so
    # Microsoft's own guidance is to blocklist these edge:// URLs explicitly.
    # Tracked individually via Set-TrackedValue (rather than the manual
    # urlBlocklistExisted/"1" handling above) so each is cleanly restored on
    # disable regardless of whether URLBlocklist itself pre-existed.
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

    # --- Refresh the Microsoft 365 domain allowlist ---
    $existingDomains = Get-CurrentAllowlistDomains
    $fetchedDomains = Get-M365AllowedDomains
    if ($fetchedDomains -and (Test-M365AllowedDomains -Domains $fetchedDomains)) {
        Write-Host "Refreshed Microsoft 365 domain allowlist from Microsoft ($($fetchedDomains.Count) domains)."
        $domainsToApply = $fetchedDomains
    } elseif ($existingDomains.Count -gt 0) {
        Write-Warning "Could not refresh the Microsoft 365 domain list (fetch failed or failed sanity check) - keeping the $($existingDomains.Count) domains already applied on this machine."
        $domainsToApply = $existingDomains
    } else {
        Write-Warning "Could not refresh the Microsoft 365 domain list - using the built-in fallback list ($($DefaultAllowedDomains.Count) domains)."
        $domainsToApply = $DefaultAllowedDomains
    }
    $domainsToApply = ConvertTo-EdgeUrlPatterns -Domains $domainsToApply

    $urlAllowlistExisted = Test-Path "$EdgePolicyPath\URLAllowlist"
    if ($urlAllowlistExisted) {
        Get-Item "$EdgePolicyPath\URLAllowlist" | Select-Object -ExpandProperty Property | ForEach-Object {
            Remove-ItemProperty -Path "$EdgePolicyPath\URLAllowlist" -Name $_ -Force -ErrorAction SilentlyContinue
        }
    } else {
        New-Item -Path "$EdgePolicyPath\URLAllowlist" -Force | Out-Null
    }
    $i = 1
    foreach ($domain in $domainsToApply) {
        New-ItemProperty -Path "$EdgePolicyPath\URLAllowlist" -Name "$i" -Value $domain -PropertyType String -Force | Out-Null
        $i++
    }
    $appliedAllowlistCount = (Get-Item "$EdgePolicyPath\URLAllowlist" -ErrorAction SilentlyContinue).Property.Count
    if ($appliedAllowlistCount -eq $domainsToApply.Count) {
        Write-Host "  [OK] $EdgePolicyPath\URLAllowlist - $appliedAllowlistCount domains verified present immediately after write"
    } else {
        Write-Warning "  [VERIFY FAILED] $EdgePolicyPath\URLAllowlist - expected $($domainsToApply.Count) domains, found $appliedAllowlistCount immediately after write"
    }

    Set-TrackedValue -Path $EdgePolicyPath -Name "RestoreOnStartup" -Value 4 -Type DWord -Changes ([ref]$changes)
    $restoreUrlsExisted = Test-Path "$EdgePolicyPath\RestoreOnStartupURLs"
    if ($restoreUrlsExisted) {
        # Clear any pre-existing entries first (e.g. leftover "2", "3", ...
        # from a prior run with a different/longer URL list) - otherwise
        # they'd survive alongside our "1" below and Edge would restore
        # those extra tabs too instead of opening only the homepage.
        Get-Item "$EdgePolicyPath\RestoreOnStartupURLs" | Select-Object -ExpandProperty Property | ForEach-Object {
            Remove-ItemProperty -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Name $_ -Force -ErrorAction SilentlyContinue
        }
    } else {
        New-Item -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Force | Out-Null
    }
    New-ItemProperty -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Name "1" -Value $HomepageUrl -PropertyType String -Force | Out-Null
    Confirm-RegistryValue -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Name "1" -ExpectedValue $HomepageUrl | Out-Null

    Set-TrackedValue -Path $EdgePolicyPath -Name "HomepageLocation" -Value $HomepageUrl -Type String -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "HomepageIsNewTabPage" -Value 0 -Type DWord -Changes ([ref]$changes)
    # HomepageLocation only covers the Home button/startup page - new tabs
    # (Ctrl+T, new windows) are a separate policy surface and would otherwise
    # open Edge's default New Tab page instead of the M365 start page.
    Set-TrackedValue -Path $EdgePolicyPath -Name "NewTabPageLocation" -Value $HomepageUrl -Type String -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "NewTabPageOverrideEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
    # Shows the Home button on the toolbar, pointed at HomepageLocation -
    # off by default in Edge, and the kiosk has no other easy way back to
    # the M365 start page from deep inside a site.
    Set-TrackedValue -Path $EdgePolicyPath -Name "ShowHomeButton" -Value 1 -Type DWord -Changes ([ref]$changes)
    # Microsoft's own guidance: on a brand-new Edge profile (exactly the
    # kiosk account's first sign-in), HomepageLocation/RestoreOnStartup(URLs)
    # are documented to be skipped on the very first launch - Edge shows its
    # first-run welcome/splash experience instead and only starts honoring
    # these policies from the second launch onward. HideFirstRunExperience
    # suppresses that splash screen so RestoreOnStartup/HomepageLocation take
    # effect immediately, which is what testing showed was otherwise missing.
    Set-TrackedValue -Path $EdgePolicyPath -Name "HideFirstRunExperience" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -Type String -Changes ([ref]$changes)
    # Belt-and-suspenders alongside ExtensionInstallBlocklist="*" above:
    # that policy blocks the install itself, while this one hides the
    # "Extensions" entry point (toolbar puzzle-piece icon and edge://extensions
    # UI) so there's no visible path to attempt adding one in the first place.
    Set-TrackedValue -Path $EdgePolicyPath -Name "HideExtensionsMenu" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "DeveloperToolsAvailability" -Value 2 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserAddPersonEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserGuestModeEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "EditFavoritesEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "BrowserSignin" -Value 2 -Type DWord -Changes ([ref]$changes)
    # "Automatically sign in to sites with your current work or school
    # account" (Settings > Profiles > Profile preferences) - lets M365 web
    # apps SSO the kiosk account in via the device's AAD credentials instead
    # of prompting for a password on every site.
    Set-TrackedValue -Path $EdgePolicyPath -Name "AADWebSiteSSOUsingThisProfileEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
    # Automatic sign-in into the Edge profile itself (not just SSO to
    # websites, above). BrowserSignin=2 (forced, set below) already covers
    # this for Azure AD/hybrid-joined machines automatically. This policy is
    # the on-prem-AD equivalent, needed when $KioskUser is a plain
    # "DOMAIN\User" account on a domain-joined (non-hybrid) machine: it signs
    # that account into Edge automatically and makes the resulting profile
    # non-removable.
    Set-TrackedValue -Path $EdgePolicyPath -Name "ConfigureOnPremisesAccountAutoSignIn" -Value 1 -Type DWord -Changes ([ref]$changes)
    # 3 = block all downloads; files stay in OneDrive/SharePoint.
    Set-TrackedValue -Path $EdgePolicyPath -Name "DownloadRestrictions" -Value 3 -Type DWord -Changes ([ref]$changes)

    # Keep the shared M365 session: no InPrivate, nothing cleared on exit.
    Set-TrackedValue -Path $EdgePolicyPath -Name "InPrivateModeAvailability" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "ClearBrowsingDataOnExit" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "SyncDisabled" -Value 1 -Type DWord -Changes ([ref]$changes)

    # Password manager stays on so the shared M365 account password can be saved.
    Set-TrackedValue -Path $EdgePolicyPath -Name "PasswordManagerEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
    # ...but not on SharePoint/OneDrive, so it doesn't offer to save passwords of
    # encrypted Office files opened in the browser. The M365 sign-in page is
    # login.microsoftonline.com, so it's unaffected.
    $passwordManagerBlockedOrigins = @("https://lbssheet-my.sharepoint.com", "https://lbssheet.sharepoint.com", "https://ukc-excel.officeapps.live.com", "https://ukw-excel.officeapps.live.com", "https://excel.officeapps.live.com")
    $i = 1
    foreach ($origin in $passwordManagerBlockedOrigins) {
        Set-TrackedValue -Path "$EdgePolicyPath\PasswordManagerBlocklist" -Name "$i" -Value $origin -Type String -Changes ([ref]$changes)
        $i++
    }
    Set-TrackedValue -Path $EdgePolicyPath -Name "AutofillAddressEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "AutofillCreditCardEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "AutoImportAtFirstRun" -Value 4 -Type DWord -Changes ([ref]$changes)

    # Declutter: sidebar/Copilot, shopping, rewards, promos, and address-bar search.
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

    # Security
    Set-TrackedValue -Path $EdgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord -Changes ([ref]$changes)
    Set-TrackedValue -Path $EdgePolicyPath -Name "TaskManagerEndProcessEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)
    # Closing Edge fully exits it, so the next launch starts fresh at the homepage.
    Set-TrackedValue -Path $EdgePolicyPath -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Changes ([ref]$changes)

    # Silently deny M365 pages access to localhost/LAN (only used to reach the
    # OneDrive sync client), which suppresses the "connect to local devices" prompt.
    # Uses content-settings pattern syntax ([*.]), unlike URLAllowlist.
    $lnaBlockedOrigins = @("https://[*.]sharepoint.com", "https://[*.]cloud.microsoft", "https://[*.]office.com", "https://onedrive.live.com")
    $i = 1
    foreach ($origin in $lnaBlockedOrigins) {
        Set-TrackedValue -Path "$EdgePolicyPath\LocalNetworkAccessBlockedForUrls" -Name "$i" -Value $origin -Type String -Changes ([ref]$changes)
        $i++
    }

    # --- Disable the Windows Copilot taskbar button ---
    # Not an app pin (CustomTaskbarLayoutCollection/AllowedApps has no effect
    # on it) - it's a separate shell UI element gated by its own policy, and
    # Copilot isn't in AllowedApps, so it must be turned off here instead.
    Set-TrackedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Changes ([ref]$changes)

    # --- Per-user: disable Task Manager, scoped only to the kiosk account ---
    # (HKU\<their SID>, not the machine-wide HKLM policy - no other user is affected)
    # ($kioskSid was already resolved above, for the admin-demotion check)
    if (-not $kioskSid) {
        Write-Warning "Could not resolve a SID for '$KioskUser' - skipping the per-user Task Manager lockdown (rest of kiosk setup still applied)."
    } else {
        $profilePath = (Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$kioskSid'" -ErrorAction SilentlyContinue).LocalPath
        $hiveRoot = "Registry::HKEY_USERS\$kioskSid"
        $hiveWasLoaded = Test-Path $hiveRoot
        $loadedHere = $false
        if (-not $hiveWasLoaded) {
            $ntUserDat = if ($profilePath) { Join-Path $profilePath "NTUSER.DAT" } else { $null }
            if ($ntUserDat -and (Test-Path $ntUserDat)) {
                & reg.exe load "HKU\$kioskSid" $ntUserDat *> $null
                if ($LASTEXITCODE -eq 0) {
                    $loadedHere = $true
                } else {
                    Write-Warning "Failed to load the registry hive for $KioskUser - skipping the per-user Task Manager lockdown."
                }
            } else {
                Write-Warning "Could not find a profile (NTUSER.DAT) for $KioskUser - skipping the per-user Task Manager lockdown."
            }
        }
        if ($hiveWasLoaded -or $loadedHere) {
            $perUserPolicyPath = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-TrackedValue -Path $perUserPolicyPath -Name "DisableTaskMgr" -Value 1 -Type DWord -Changes ([ref]$changes)
            Set-TrackedValue -Path $perUserPolicyPath -Name "DisableChangePassword" -Value 1 -Type DWord -Changes ([ref]$changes)

            # --- Clear any taskbar pins left over from before kiosk mode ---
            # Windows only fully re-applies an Assigned Access TaskbarLayout
            # pin list on a profile's first-ever sign-in. On an account that
            # already used the desktop normally, its previously-pinned Edge
            # icon (plain, no baked-in homepage) survives alongside the new
            # kiosk shortcut pin, producing two Edge icons on the taskbar.
            # Both the Taskband registry key (pin order/metadata) and the
            # Quick Launch "User Pinned\TaskBar" folder (the actual pinned
            # .lnk files) are backed up here - not deleted - so Disable-Kiosk
            # can put the account's original taskbar back exactly.
            $taskbandKeyPath = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
            $taskbandKeyExisted = Test-Path $taskbandKeyPath
            $taskbandBackupFile = Join-Path $WorkDir "TaskbandBackup-$kioskSid.reg"
            if ($taskbandKeyExisted) {
                & reg.exe export "HKU\$kioskSid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" $taskbandBackupFile /y *> $null
                Remove-Item -Path $taskbandKeyPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            $pinnedTaskbarDir = if ($profilePath) { Join-Path $profilePath "AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" } else { $null }
            $pinnedTaskbarBackupDir = Join-Path $WorkDir "TaskbarPinsBackup-$kioskSid"
            $pinnedTaskbarExisted = [bool]($pinnedTaskbarDir -and (Test-Path $pinnedTaskbarDir))
            if ($pinnedTaskbarExisted) {
                Remove-Item -Path $pinnedTaskbarBackupDir -Recurse -Force -ErrorAction SilentlyContinue
                Move-Item -Path $pinnedTaskbarDir -Destination $pinnedTaskbarBackupDir -Force
            }

            $perUserHiveState = [PSCustomObject]@{
                Sid                    = $kioskSid
                LoadedHere             = $loadedHere
                TaskbandKeyExisted     = $taskbandKeyExisted
                TaskbandBackupFile     = if ($taskbandKeyExisted) { $taskbandBackupFile } else { $null }
                PinnedTaskbarDir       = $pinnedTaskbarDir
                PinnedTaskbarExisted   = $pinnedTaskbarExisted
                PinnedTaskbarBackupDir = if ($pinnedTaskbarExisted) { $pinnedTaskbarBackupDir } else { $null }
            }
            if ($loadedHere) {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()
                & reg.exe unload "HKU\$kioskSid" *> $null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Failed to unload the registry hive for $KioskUser after editing it - it may remain loaded until reboot, which can block that user from signing in."
                }
            }
        }
    }

    # --- Final re-verification pass ---
    # Something on some machines has been observed to delete these registry
    # values within seconds of them being written (all but the last one set
    # were gone by the next reboot, with no Intune/GPO in play) - the
    # per-write Confirm-RegistryValue checks above wouldn't catch that since
    # they run immediately after each individual write. Re-reading
    # everything once more here, after all writes are done, narrows down
    # whether the loss happens during this run or only afterward (at
    # reboot/logon/some later background process).
    Write-Host "Re-checking all tracked registry values..."
    $verifyFailures = 0
    foreach ($change in ($changes | Where-Object { $null -ne $_.NewValue })) {
        if (-not (Confirm-RegistryValue -Path $change.Path -Name $change.Name -ExpectedValue $change.NewValue)) {
            $verifyFailures++
        }
    }
    $finalBlocklistCount = (Get-Item "$EdgePolicyPath\URLBlocklist" -ErrorAction SilentlyContinue).Property.Count
    $finalAllowlistCount = (Get-Item "$EdgePolicyPath\URLAllowlist" -ErrorAction SilentlyContinue).Property.Count
    Write-Host "  URLBlocklist entries present: $finalBlocklistCount (expected $($blockedInternalPages.Count + 1))"
    Write-Host "  URLAllowlist entries present: $finalAllowlistCount (expected $($domainsToApply.Count))"
    if ($verifyFailures -gt 0 -or $finalBlocklistCount -ne ($blockedInternalPages.Count + 1) -or $finalAllowlistCount -ne $domainsToApply.Count) {
        Write-Warning "$verifyFailures tracked value(s) and/or the URLBlocklist/URLAllowlist counts no longer match what was just written - something is reverting these registry values during the script run itself, not just afterward."
    } else {
        Write-Host "  All tracked values still present immediately after the run completed."
    }

    $succeeded = $true

    } catch {
        # Include the failing line and exception type/HResult - generic COM
        # errors from the Assigned Access WMI Bridge (e.g. "A general error
        # occurred that is not covered by a more specific error code") give
        # no detail otherwise, making it impossible to tell which step failed.
        $detail = "[$($_.Exception.GetType().FullName), HResult 0x$($_.Exception.HResult.ToString('X8'))] $($_.Exception.Message)"

        # CimException wraps the real MDM/CSP failure reason in properties
        # that $_.Exception.Message never includes (Message is always the
        # same generic "A general error occurred..." string for this
        # provider) - NativeErrorCode/StatusCode are the actual MI_RESULT
        # code, and ErrorData (when present) is a CimInstance carrying the
        # CSP's own error text and URI, which is what actually explains a
        # rejected Assigned Access config.
        if ($_.Exception -is [Microsoft.Management.Infrastructure.CimException]) {
            $cimEx = $_.Exception
            $detail += " | NativeErrorCode=$($cimEx.NativeErrorCode) StatusCode=$($cimEx.StatusCode)"
            if ($cimEx.ErrorData) {
                $errorDataProps = $cimEx.ErrorData.CimInstanceProperties |
                    ForEach-Object { "$($_.Name)=$($_.Value)" }
                $detail += " | ErrorData: $($errorDataProps -join '; ')"
            }
        }

        Write-Error "Enable-Kiosk failed partway through, at line $($_.InvocationInfo.ScriptLineNumber) ($($_.InvocationInfo.Line.Trim())): $detail"
    } finally {
        # Always persist whatever changes were made, even on failure, so
        # -Enabled false can cleanly revert a partial run instead of finding
        # no state file and only being able to do best-effort cleanup.
        Save-KioskState
    }

    if (-not $succeeded) {
        Write-Error "Partial changes were recorded to $StateFile. Run '.\kioskMode.ps1 -Enabled false' to revert them, then re-run to retry."
        exit 1
    }

    Write-Host "Kiosk configuration applied. Reboot (or sign the kiosk account out/in) to take effect."
}

function Disable-Kiosk {
    Write-Host "Removing kiosk configuration..."
    if (-not (Test-Path $StateFile)) {
        Write-Warning "No state file found at $StateFile - nothing recorded to precisely revert. Attempting best-effort cleanup only."
        Remove-Item -Path $XmlPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $EdgeShortcutPath -Force -ErrorAction SilentlyContinue
        return
    }
    try {
        $state = Get-Content -Path $StateFile -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "State file at $StateFile is corrupt or unreadable ($($_.Exception.Message)) - nothing recorded to precisely revert. Attempting best-effort cleanup only."
        Remove-Item -Path $XmlPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $EdgeShortcutPath -Force -ErrorAction SilentlyContinue
        return
    }

    try {

    # --- Restore Assigned Access to exactly what it was before ---
    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_AssignedAccess"
    $aaObj = Get-CimInstance -Namespace $namespaceName -ClassName $className
    $aaObj.Configuration = $state.PreviousAssignedAccessConfig
    Set-CimInstance -CimInstance $aaObj

    # --- Restore the kiosk account to Administrators if enabling demoted it ---
    if ($state.DemotedFromAdmin -and $state.DemotedFromAdmin.WasAdmin -and $state.DemotedFromAdmin.Sid) {
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $state.DemotedFromAdmin.Sid -ErrorAction Stop
        } catch {
            Write-Warning "Failed to restore the kiosk account to Administrators: $($_.Exception.Message)"
        }
    }

    # --- Remove OneAuth if enabling installed it: deprovision it first (so
    # it isn't reinstalled at anyone's next sign-in), then uninstall it only
    # from accounts that didn't already have it before. ---
    if ($state.OneAuthInstalled -and $state.OneAuthInstalled.ProvisionedPackageName) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $state.OneAuthInstalled.ProvisionedPackageName -ErrorAction Stop | Out-Null
            $preExistingSids = @($state.OneAuthInstalled.PreExistingUserSids | Where-Object { $_ })
            if ($preExistingSids.Count -eq 0) {
                # Nobody had it before, so remove it for everyone - avoids
                # Remove-AppxPackage -User, which can't resolve an Azure AD
                # account's SID on some machines.
                Get-AppxPackage -AllUsers -Name $OneAuthPackageName |
                    ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop }
            } else {
                foreach ($pkg in (Get-AppxPackage -AllUsers -Name $OneAuthPackageName)) {
                    foreach ($userInfo in $pkg.PackageUserInformation) {
                        $sid = $userInfo.UserSecurityId.Sid
                        if ($sid -and $preExistingSids -notcontains $sid) {
                            Remove-AppxPackage -Package $pkg.PackageFullName -User $sid -ErrorAction Stop
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to fully remove OneAuth installed by kiosk mode: $($_.Exception.Message)"
        }
    }

    # --- Reload the kiosk user's hive if needed, so its Task Manager value can be restored ---
    $perUserHiveReloadedHere = $false
    if ($state.PerUserHive -and $state.PerUserHive.Sid) {
        $hiveRoot = "Registry::HKEY_USERS\$($state.PerUserHive.Sid)"
        if (-not (Test-Path $hiveRoot)) {
            $profilePath = (Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($state.PerUserHive.Sid)'" -ErrorAction SilentlyContinue).LocalPath
            $ntUserDat = if ($profilePath) { Join-Path $profilePath "NTUSER.DAT" } else { $null }
            if ($ntUserDat -and (Test-Path $ntUserDat)) {
                & reg.exe load "HKU\$($state.PerUserHive.Sid)" $ntUserDat *> $null
                if ($LASTEXITCODE -eq 0) {
                    $perUserHiveReloadedHere = $true
                } else {
                    Write-Warning "Failed to reload the kiosk user's registry hive - their Task Manager value may not be restored."
                }
            } else {
                Write-Warning "Could not find the kiosk user's profile - their Task Manager value may not be restored."
            }
        }
    }

    # --- Restore any taskbar pins backed up when kiosk mode was enabled ---
    if ($state.PerUserHive -and $state.PerUserHive.Sid) {
        $taskbandKeyPath = "Registry::HKEY_USERS\$($state.PerUserHive.Sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if ($state.PerUserHive.TaskbandKeyExisted -and $state.PerUserHive.TaskbandBackupFile -and (Test-Path $state.PerUserHive.TaskbandBackupFile)) {
            Remove-Item -Path $taskbandKeyPath -Recurse -Force -ErrorAction SilentlyContinue
            & reg.exe import $state.PerUserHive.TaskbandBackupFile *> $null
            Remove-Item -Path $state.PerUserHive.TaskbandBackupFile -Force -ErrorAction SilentlyContinue
        }
        if ($state.PerUserHive.PinnedTaskbarExisted -and $state.PerUserHive.PinnedTaskbarBackupDir -and (Test-Path $state.PerUserHive.PinnedTaskbarBackupDir)) {
            Remove-Item -Path $state.PerUserHive.PinnedTaskbarDir -Recurse -Force -ErrorAction SilentlyContinue
            Move-Item -Path $state.PerUserHive.PinnedTaskbarBackupDir -Destination $state.PerUserHive.PinnedTaskbarDir -Force
        }
    }

    # --- Revert each tracked registry value ---
    foreach ($change in $state.RegistryChanges) {
        if ($change.Existed) {
            Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Previous -Force -ErrorAction SilentlyContinue
        } else {
            Remove-ItemProperty -Path $change.Path -Name $change.Name -Force -ErrorAction SilentlyContinue
        }
    }

    if ($perUserHiveReloadedHere) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$($state.PerUserHive.Sid)" *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to unload the kiosk user's registry hive after reverting it - it may remain loaded until reboot, which can block that user from signing in."
        }
    }

    # --- Remove list-style keys we created (or just our added values, if the key pre-existed) ---
    if (-not $state.UrlBlocklistKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\URLBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Remove-ItemProperty -Path "$EdgePolicyPath\URLBlocklist" -Name "1" -Force -ErrorAction SilentlyContinue
    }
    if (-not $state.UrlAllowlistKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\URLAllowlist" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $state.RestoreUrlsKeyPreExisted) {
        Remove-Item -Path "$EdgePolicyPath\RestoreOnStartupURLs" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # --- Remove files this script created ---
    Remove-Item -Path $XmlPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $EdgeShortcutPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
    if (-not $state.WorkDirPreExisted) {
        Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    } catch {
        Write-Error "Kiosk disable failed partway through: $($_.Exception.Message). The recorded state at $StateFile was left in place - re-run '.\kioskMode.ps1 -Enabled false' to retry."
        exit 1
    }

    Write-Host "Kiosk configuration removed and machine restored to its pre-enabled state. Reboot to complete."
}

# ===========================================================================
# Run
# ===========================================================================
if ($EnableKiosk) { Enable-Kiosk } else { Disable-Kiosk }