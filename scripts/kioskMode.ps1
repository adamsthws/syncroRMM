<#
    kioskMode.ps1

    Deploys (or fully removes) a Windows 11 25H2+ multi-app kiosk: OneAuth + a
    restricted, non-InPrivate Microsoft Edge locked to Microsoft 365 domains,
    both pinned to Start and the taskbar. Edge auto-launches at sign-in and,
    via two \Kiosk\ scheduled tasks, whenever the kiosk session is unlocked
    with Edge closed.
    The Edge policies, plus disabling Task Manager and "Change a password" on
    the Ctrl+Alt+Del screen, are written to the kiosk account's own registry
    hive (HKU\<SID>\SOFTWARE\Policies\...) - no other account on the machine
    is affected.
    If OneAuth isn't already installed for the kiosk account (or provisioned
    for the machine), it's provisioned machine-wide from the Microsoft Store
    via winget.
    Fully self-contained - writes the Assigned Access XML it needs to
    C:\ProgramData\Kiosk\ at runtime. Edge is pinned via its stock "Microsoft
    Edge" shortcut; its start page comes from the Edge policies below.
    Reversing (-Enabled false) removes everything this script adds - the
    Assigned Access config, scheduled tasks, C:\ProgramData\Kiosk\, and every
    policy value it sets - returning those settings to Windows defaults. The
    kiosk account's taskbar pins are reset to the defaults too. OneAuth stays
    installed, and the account stays a standard user. The machine-wide power
    settings (display off after 20 min, never sleep/hibernate, Fast Startup
    off) are also deliberately left in place.

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
      Standalone:   .\kioskMode.ps1 -Enabled true -SharePointTenant contoso [-KioskUser "AzureAD\user@tenant.com"]
                    .\kioskMode.ps1 -Enabled false
      SyncroRMM:    set script variables named "enabled" (true / false) and
                    "SharePointTenant", and optionally "KioskUser" - all are
                    picked up automatically, no parameters needed.

      -SharePointTenant is the customer's SharePoint prefix - the "contoso" in
      contoso-my.sharepoint.com. Edge's start page becomes
      https://<prefix>-my.sharepoint.com/favorites. It's required when
      enabling and ignored when disabling.

      -Enabled and -KioskUser default so that running the script with only
      -SharePointTenant (either standalone or from Syncro with only that
      variable set) enables kiosk mode for whichever user is currently
      logged on:
        -Enabled    defaults to "true"
        -KioskUser  defaults to "CurrentUser" - whichever user is currently
                    logged on interactively (resolved at runtime). Other
                    accepted values:
                      "AzureAD\user@tenant.com"  - an Azure AD account (a UPN)
                      "DOMAIN\User"              - an on-prem AD account
                      "COMPUTERNAME\LocalUser"   - a local account
                    With -Enabled false, the kiosk account is read from the
                    applied Assigned Access config unless -KioskUser is given.

    Must run elevated (SYSTEM or local admin). The kiosk account must have
    signed in at least once. Edit the CONFIGURATION block
    below (OneAuth AUMID, allowed domains) before first use.
#>

# ===========================================================================
# Re-launch under 64-bit PowerShell if we're running as a 32-bit process on a
# 64-bit OS. HKLM:\SOFTWARE\Policies\... (the machine-wide policy keys this
# script writes to) is subject to WOW64 registry redirection -
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
    if (-not ($relaunchArgs -contains '-SharePointTenant')) {
        if (Get-Variable -Name SharePointTenant -Scope Global -ErrorAction SilentlyContinue) {
            $relaunchArgs += @('-SharePointTenant', "$((Get-Variable -Name SharePointTenant -Scope Global).Value)")
        } elseif ($env:SharePointTenant) {
            $relaunchArgs += @('-SharePointTenant', "$env:SharePointTenant")
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
$SharePointTenant = $null
for ($i = 0; $i -lt $args.Count; $i++) {
    switch -Regex ("$($args[$i])") {
        '^-Enabled$'          { $Enabled = "$($args[++$i])" }
        '^-KioskUser$'        { $KioskUser = "$($args[++$i])" }
        '^-SharePointTenant$' { $SharePointTenant = "$($args[++$i])" }
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
# Resolve the customer's SharePoint tenant prefix (the "contoso" in
# contoso-my.sharepoint.com):
# -SharePointTenant param > pre-existing $SharePointTenant (Syncro) > env var
# Resolved before CONFIGURATION because the Edge policy tables below are
# built from it; it's only required when enabling (checked further down).
# A full URL (e.g. "https://contoso-my.sharepoint.com/favorites") is accepted
# too and reduced to the prefix.
# ===========================================================================
if ([string]::IsNullOrWhiteSpace($SharePointTenant)) {
    if (Get-Variable -Name SharePointTenant -Scope Global -ErrorAction SilentlyContinue) {
        $SharePointTenant = (Get-Variable -Name SharePointTenant -Scope Global).Value
    } elseif ($env:SharePointTenant) {
        $SharePointTenant = $env:SharePointTenant
    }
}
$SharePointTenant = ("$SharePointTenant").Trim().ToLower() -replace '^https?://', '' -replace '(-my)?\.sharepoint\.com.*$', ''

# ===========================================================================
# CONFIGURATION - edit before first use
# ===========================================================================
$OneAuthAUMID   = "ZohoCorp.44386D730E544_hfrrf6a1akhx2!App"   # Zoho OneAuth
# Microsoft Store product ID for OneAuth (apps.microsoft.com/detail/<id>) -
# used to provision it machine-wide via winget if it's missing.
$OneAuthStoreId = "9NPG98QLH8JN"
$HomepageUrl    = "https://$SharePointTenant-my.sharepoint.com/favorites"
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
# StartPins' desktopAppLink (and TaskbarLayout's DesktopApplicationLinkPath)
# only resolve a shortcut that actually lives under a Start Menu "Programs"
# folder, so Edge is pinned via its own stock shortcut there. The start page
# comes from the RestoreOnStartup/Homepage policies, not launch arguments.
$StartMenuProgramsDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$StockEdgeShortcutPath = Join-Path $StartMenuProgramsDir "Microsoft Edge.lnk"
# The %ALLUSERSPROFILE% env-var form (rather than the resolved path above) is
# what's embedded in the AssignedAccess XML/JSON, matching Microsoft's
# documented examples and staying correct even if ProgramData isn't at its
# default location.
$EdgeShortcutEnvPath = "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
# Edge policies go under the kiosk account's hive (HKU\<SID>\<this subkey>),
# not HKLM - Edge reads both, and this scopes them to that account alone.
$EdgePolicySubKey = "SOFTWARE\Policies\Microsoft\Edge"
# Scheduled tasks that relaunch Edge when the kiosk session is unlocked (see
# Register-EdgeUnlockTasks). Assigned Access's AutoLaunch covers sign-in only.
$KioskTaskPath = "\Kiosk\"
$UnlockWatchTaskName = "EdgeOnUnlock"
$EdgeLaunchTaskName = "LaunchEdge"
$ProfileGuid = "{4c9a1e2b-6f3d-4a8e-9c2f-8b1d5e7a3c90}"
# Package name (e.g. "ZohoCorp.44386D730E544"), as Get-AppxPackage/
# Get-AppxProvisionedPackage report it - the AUMID minus publisher hash and app ID.
$OneAuthPackageName = (($OneAuthAUMID -split '!')[0] -split '_')[0]

# ===========================================================================
# Edge policies, written to the kiosk account's hive. Disable deletes every
# value and list key named here (plus URLAllowlist), returning Edge to its
# defaults. Type is DWord unless given.
# ===========================================================================
$EdgePolicyValues = @(
    @{ Name = "RestoreOnStartup"; Value = 4 }
    # No "Restore pages?" prompt after an unclean shutdown - always land on
    # the start page instead.
    @{ Name = "HideRestoreDialogEnabled"; Value = 1 }
    @{ Name = "HomepageLocation"; Value = $HomepageUrl; Type = "String" }
    @{ Name = "HomepageIsNewTabPage"; Value = 0 }
    # HomepageLocation only covers the Home button/startup page - new tabs
    # (Ctrl+T, new windows) are a separate policy surface and would otherwise
    # open Edge's default New Tab page instead of the M365 start page.
    @{ Name = "NewTabPageLocation"; Value = $HomepageUrl; Type = "String" }
    # Shows the Home button on the toolbar, pointed at HomepageLocation -
    # off by default in Edge, and the kiosk has no other easy way back to
    # the M365 start page from deep inside a site.
    @{ Name = "ShowHomeButton"; Value = 1 }
    # Microsoft's own guidance: on a brand-new Edge profile (exactly the
    # kiosk account's first sign-in), HomepageLocation/RestoreOnStartup(URLs)
    # are documented to be skipped on the very first launch - Edge shows its
    # first-run welcome/splash experience instead and only starts honoring
    # these policies from the second launch onward. HideFirstRunExperience
    # suppresses that splash screen so RestoreOnStartup/HomepageLocation take
    # effect immediately, which is what testing showed was otherwise missing.
    @{ Name = "HideFirstRunExperience"; Value = 1 }
    @{ Name = "DeveloperToolsAvailability"; Value = 2 }
    @{ Name = "BrowserAddProfileEnabled"; Value = 0 }
    @{ Name = "BrowserGuestModeEnabled"; Value = 0 }
    @{ Name = "EditFavoritesEnabled"; Value = 0 }
    # No favorites or history for a shared account: hide the favorites bar and
    # stop recording history (edge://favorites and edge://history are also in
    # URLBlocklist below). Doesn't touch cookies, so M365 stays signed in.
    @{ Name = "FavoritesBarEnabled"; Value = 0 }
    @{ Name = "SavingBrowserHistoryDisabled"; Value = 1 }
    # Forced sign-in to the Edge profile. For Azure AD/hybrid-joined machines
    # this signs the kiosk account in automatically.
    @{ Name = "BrowserSignin"; Value = 2 }
    # "Automatically sign in to sites with your current work or school
    # account" (Settings > Profiles > Profile preferences) - lets M365 web
    # apps SSO the kiosk account in via the device's AAD credentials instead
    # of prompting for a password on every site.
    @{ Name = "AADWebSiteSSOUsingThisProfileEnabled"; Value = 1 }
    # The on-prem-AD equivalent of BrowserSignin's automatic sign-in, needed
    # when $KioskUser is a plain "DOMAIN\User" account on a domain-joined
    # (non-hybrid) machine: it signs that account into Edge automatically and
    # makes the resulting profile non-removable.
    @{ Name = "ConfigureOnPremisesAccountAutoSignIn"; Value = 1 }
    # 3 = block all downloads; files stay in OneDrive/SharePoint.
    @{ Name = "DownloadRestrictions"; Value = 3 }

    # Keep the shared M365 session: no InPrivate, nothing cleared on exit.
    @{ Name = "InPrivateModeAvailability"; Value = 1 }
    @{ Name = "ClearBrowsingDataOnExit"; Value = 0 }
    @{ Name = "AllowDeletingBrowserHistory"; Value = 0 }
    @{ Name = "SyncDisabled"; Value = 1 }

    # Password manager stays on so the shared M365 account password can be
    # saved (but see PasswordManagerBlocklist below).
    @{ Name = "PasswordManagerEnabled"; Value = 1 }
    @{ Name = "AutofillAddressEnabled"; Value = 0 }
    @{ Name = "AutofillCreditCardEnabled"; Value = 0 }
    @{ Name = "AutoImportAtFirstRun"; Value = 4 }

    # Declutter: sidebar/Copilot, shopping, rewards, promos, and address-bar search.
    @{ Name = "HubsSidebarEnabled"; Value = 0 }
    # HubsSidebarEnabled doesn't cover the toolbar Copilot button Entra ID
    # profiles get (Microsoft 365 Copilot Chat) - that has its own policy.
    @{ Name = "Microsoft365CopilotChatIconEnabled"; Value = 0 }
    # No "Install <site> as an app" prompts/address-bar icon (Edge 145+).
    @{ Name = "WebAppInstallByUserEnabled"; Value = 0 }
    @{ Name = "EdgeShoppingAssistantEnabled"; Value = 0 }
    @{ Name = "ShowMicrosoftRewards"; Value = 0 }
    @{ Name = "EdgeCollectionsEnabled"; Value = 0 }
    @{ Name = "EdgeWorkspacesEnabled"; Value = 0 }
    @{ Name = "ShowRecommendationsEnabled"; Value = 0 }
    @{ Name = "SpotlightExperiencesAndRecommendationsEnabled"; Value = 0 }
    @{ Name = "PromotionalTabsEnabled"; Value = 0 }
    @{ Name = "UserFeedbackAllowed"; Value = 0 }
    @{ Name = "DefaultSearchProviderEnabled"; Value = 0 }
    @{ Name = "SearchSuggestEnabled"; Value = 0 }

    # Security
    @{ Name = "SmartScreenEnabled"; Value = 1 }
    @{ Name = "PreventSmartScreenPromptOverride"; Value = 1 }
    @{ Name = "PreventSmartScreenPromptOverrideForFiles"; Value = 1 }
    @{ Name = "TaskManagerEndProcessEnabled"; Value = 0 }
    # Closing Edge fully exits it, so the next launch starts fresh at the homepage.
    @{ Name = "BackgroundModeEnabled"; Value = 0 }
    # Startup boost keeps windowless msedge.exe processes alive, which would
    # make the unlock task think Edge is already open and skip relaunching it.
    @{ Name = "StartupBoostEnabled"; Value = 0 }
)

# List-style policies: a subkey of numbered entries ("1", "2", ...), not a
# single value on the Edge key (which Edge ignores).
$EdgePolicyLists = [ordered]@{
    # "*" blocks everything not in URLAllowlist. That only covers web
    # content - internal edge:// pages aren't reliably caught by it
    # (confirmed by testing: edge://settings stayed reachable), and there's
    # no dedicated "hide Settings" policy, so Microsoft's own guidance is to
    # blocklist these edge:// URLs explicitly.
    URLBlocklist = @(
        "*",
        "edge://settings", "edge://settings/*", "edge://extensions",
        "edge://extensions/*", "edge://flags", "edge://flags/*",
        "edge://version", "edge://net-internals", "edge://net-internals/*",
        "edge://history", "edge://history/*", "edge://favorites", "edge://favorites/*"
    )
    RestoreOnStartupURLs = @($HomepageUrl)
    ExtensionInstallBlocklist = @("*")
    # Not on SharePoint/OneDrive, so the password manager doesn't offer to
    # save passwords of encrypted Office files opened in the browser. The
    # M365 sign-in page is login.microsoftonline.com, so it's unaffected.
    PasswordManagerBlocklist = @(
        "https://$SharePointTenant-my.sharepoint.com", "https://$SharePointTenant.sharepoint.com",
        "https://ukc-excel.officeapps.live.com", "https://ukw-excel.officeapps.live.com",
        "https://excel.officeapps.live.com"
    )
    # Silently deny M365 pages access to localhost/LAN (only used to reach the
    # OneDrive sync client), which suppresses the "connect to local devices"
    # prompt. Uses content-settings pattern syntax ([*.]), unlike URLAllowlist.
    LocalNetworkAccessBlockedForUrls = @(
        "https://[*.]sharepoint.com", "https://[*.]cloud.microsoft",
        "https://[*.]office.com", "https://onedrive.live.com"
    )
}
# URLAllowlist is a list policy too, but its entries come from Microsoft's
# endpoint list at runtime (see Enable-Kiosk).
$EdgeAllowlistKey = "URLAllowlist"

# Per-user Windows policies (kiosk account's hive): no Task Manager and no
# "Change a password" on the Ctrl+Alt+Del screen.
$UserSystemPolicySubKey = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$UserSystemPolicyNames = @("DisableTaskMgr", "DisableChangePassword")

# Machine-wide: the Windows Copilot taskbar button isn't an app pin
# (CustomTaskbarLayoutCollection/AllowedApps has no effect on it) - it's a
# separate shell UI element gated by its own policy, and Copilot isn't in
# AllowedApps, so it must be turned off here instead.
$CopilotPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
$CopilotPolicyName = "TurnOffWindowsCopilot"

# Machine-wide power settings, applied on enable and deliberately NOT undone
# on disable: display off after $DisplayOffMinutes of inactivity, never
# sleep or hibernate, and Fast Startup off (so a shutdown is a real one).
# Applied both to the active power scheme via powercfg (takes effect now)
# and as power policy (applies to every scheme and can't be changed from
# Settings by a standard user).
$DisplayOffMinutes = 20
$PowerPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings"
$PowerPolicySettings = [ordered]@{
    "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" = $DisplayOffMinutes * 60   # Turn off the display (seconds)
    "29f6c1db-86da-48c5-9fdb-f2b67b1f44da" = 0                         # Sleep after (0 = never)
    "9d7815a6-7ee4-497e-8888-515a05f02364" = 0                         # Hibernate after (0 = never)
}
$FastStartupPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$FastStartupName = "HiberbootEnabled"

# Edge is started maximized by the kiosk's own launches (AutoLaunch at
# sign-in and the unlock task). Edge remembers the window state, so later
# launches from the Start/taskbar pins open maximized too.
$EdgeLaunchArguments = "--start-maximized"

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
# Disabling removes Edge policies by name only, so the tenant isn't needed there.
if ($EnableKiosk -and $SharePointTenant -notmatch '^[a-z0-9][a-z0-9-]*$') {
    Write-Error "Specify -SharePointTenant <prefix> (e.g. 'contoso' for contoso-my.sharepoint.com), or set the Syncro 'SharePointTenant' script variable."
    exit 1
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
# Resolve target kiosk user:
# -KioskUser param > pre-existing $KioskUser (Syncro) > env var > "CurrentUser"
# ("CurrentUser" only when enabling - disable otherwise reads the account
# from the applied Assigned Access config.)
# ===========================================================================
if ([string]::IsNullOrWhiteSpace($KioskUser)) {
    if (Get-Variable -Name KioskUser -Scope Global -ErrorAction SilentlyContinue) {
        $KioskUser = (Get-Variable -Name KioskUser -Scope Global).Value
    } elseif ($env:KioskUser) {
        $KioskUser = $env:KioskUser
    }
}
if ($EnableKiosk) {
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

function Set-PolicyValue {
    param($Path, $Name, $Value, $Type = "DWord")
    # New-Item -Force on an existing registry key recreates it empty, wiping all values and subkeys.
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Confirm-RegistryValue -Path $Path -Name $Name -ExpectedValue $Value | Out-Null
    # Re-checked once more at the end of Enable-Kiosk.
    $script:WrittenValues += [PSCustomObject]@{ Path = $Path; Name = $Name; Value = $Value }
}

function Set-PolicyList {
    # Replaces a list-style policy key with exactly $Values, as "1".."n".
    param($Path, [string[]]$Values)
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -Path $Path -Force | Out-Null
    $i = 1
    foreach ($value in $Values) {
        New-ItemProperty -Path $Path -Name "$i" -Value $value -PropertyType String -Force | Out-Null
        $i++
    }
    $count = (Get-Item $Path -ErrorAction SilentlyContinue).Property.Count
    if ($count -eq $Values.Count) {
        Write-Host "  [OK] $Path - $count entries verified present immediately after write"
    } else {
        Write-Warning "  [VERIFY FAILED] $Path - expected $($Values.Count) entries, found $count immediately after write"
    }
}

function Remove-PolicyValue {
    param($Path, $Name)
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
}

function Remove-EmptyKey {
    # Deletes a policy key this script created once nothing is left in it.
    param($Path)
    $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if ($key -and $key.Property.Count -eq 0 -and $key.SubKeyCount -eq 0) {
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
    }
}

function Mount-KioskHive {
    # Makes HKU\<SID> available, loading the account's NTUSER.DAT if it isn't
    # signed in. Returns $true if it loaded the hive (so Dismount-KioskHive
    # must unload it again), $false if it was already loaded. Throws if the
    # account has no profile or the hive won't load.
    param([string]$Sid)
    if (Test-Path "Registry::HKEY_USERS\$Sid") { return $false }
    $profilePath = (Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction SilentlyContinue).LocalPath
    $ntUserDat = if ($profilePath) { Join-Path $profilePath "NTUSER.DAT" } else { $null }
    if (-not ($ntUserDat -and (Test-Path $ntUserDat))) {
        throw "Could not find a profile (NTUSER.DAT) for SID $Sid - the account must have signed in at least once."
    }
    & reg.exe load "HKU\$Sid" $ntUserDat *> $null
    if ($LASTEXITCODE -ne 0) { throw "Failed to load the registry hive for SID $Sid." }
    return $true
}

function Dismount-KioskHive {
    param([string]$Sid)
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    & reg.exe unload "HKU\$Sid" *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to unload the registry hive for SID $Sid - it may remain loaded until reboot, which can block that user from signing in."
    }
}

function Get-KioskAccountFromConfig {
    # The account this script's Assigned Access profile is assigned to, or
    # $null if that profile isn't the one applied.
    param([string]$Configuration)
    Add-Type -AssemblyName System.Web
    $xml = [System.Web.HttpUtility]::HtmlDecode($Configuration)
    if (-not $xml -or -not $xml.Contains($ProfileGuid)) { return $null }
    if ($xml -match '<Account>\s*([^<]+?)\s*</Account>') { return $Matches[1] }
    return $null
}

function Reset-KioskTaskbarPins {
    # Deletes the account's taskbar pins - both the Taskband registry key
    # (pin order/metadata) and the Quick Launch "User Pinned\TaskBar" folder
    # (the actual pinned .lnk files).
    param([string]$Sid)
    Remove-Item -Path "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force -ErrorAction SilentlyContinue
    $profilePath = (Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction SilentlyContinue).LocalPath
    if ($profilePath) {
        Remove-Item -Path (Join-Path $profilePath "AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar") -Recurse -Force -ErrorAction SilentlyContinue
    }
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
    param([string]$PolicyPath)
    if (-not (Test-Path "$PolicyPath\URLAllowlist")) { return @() }
    $props = Get-ItemProperty -Path "$PolicyPath\URLAllowlist" -ErrorAction SilentlyContinue
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

    # Works for "AzureAD\user@tenant.com" too on an Azure AD-joined machine
    # (confirmed by testing).
    try {
        return (New-Object System.Security.Principal.NTAccount($KioskUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { }

    # Azure AD fallback: Windows caches each AAD account that has signed in
    # here, keyed by SID, with its UPN - an exact match, unlike profile
    # folder names, which don't reliably follow the UPN (e.g.
    # workshop@lbssheetmetal.info -> C:\Users\Workshop-LBSSheetMet).
    $shortName = ($KioskUser -split '\\')[-1]
    if ($shortName -like '*@*') {
        $cachedSid = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem (Join-Path $_.PSPath "IdentityCache") -ErrorAction SilentlyContinue } |
            Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UserName -eq $shortName } |
            Select-Object -First 1 -ExpandProperty PSChildName
        if ($cachedSid) { return $cachedSid }
    }

    # Last resort: match against local profile folders named after the
    # account name / UPN's local part.
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
    # kiosk account at its next sign-in. Left installed on disable. Never
    # throws - failure only means a missing OneAuth tile, which isn't worth
    # aborting the rest of the kiosk setup over.
    param([string]$KioskSid)
    try {
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $OneAuthPackageName
        if ($provisioned) {
            Write-Host "OneAuth is already provisioned for this machine ($($provisioned.Version)) - skipping install."
            return
        }
        # Filtered from -AllUsers rather than using Get-AppxPackage -User
        # $KioskSid, which throws "No valid SID could be determined" for an
        # Azure AD account's SID on a machine that can't resolve it.
        $installedUserSids = @(
            Get-AppxPackage -AllUsers -Name $OneAuthPackageName |
                ForEach-Object { $_.PackageUserInformation } |
                ForEach-Object { $_.UserSecurityId.Sid }
        )
        if ($KioskSid -and $installedUserSids -contains $KioskSid) {
            Write-Host "OneAuth is already installed for '$KioskUser' - skipping install."
            return
        }

        $winget = Get-SystemWingetPath
        if (-not $winget) {
            Write-Warning "OneAuth isn't installed and winget (App Installer) couldn't be found - the OneAuth tile will be missing until it's installed."
            return
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
            return
        }
        Write-Host "  [OK] OneAuth $($provisioned.Version) provisioned for all users."
    } catch {
        Write-Warning "OneAuth install check/install failed: $($_.Exception.Message) - the OneAuth tile will be missing until it's installed."
        return
    }
}

function Resolve-KioskTaskAccount {
    # Task Scheduler takes an account name and resolves it to a SID itself,
    # but an Azure AD SID translates to a display-name form
    # ("AzureAD\Workshop-LBSSheetMet") that doesn't resolve back, and that's
    # also what "CurrentUser" yields. Only "AzureAD\<UPN>" round-trips, so
    # use $KioskUser if it resolves to this SID, else look up the UPN.
    param([string]$KioskUser, [string]$KioskSid)
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($KioskUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($sid -eq $KioskSid) { return $KioskUser }
    } catch { }
    $upn = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache" -ErrorAction SilentlyContinue |
        ForEach-Object { Get-Item (Join-Path $_.PSPath "IdentityCache\$KioskSid") -ErrorAction SilentlyContinue } |
        ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UserName } |
        Where-Object { $_ } | Select-Object -First 1
    if ($upn) { return "AzureAD\$upn" }
    return $KioskUser
}

function Register-EdgeUnlockTasks {
    param([string]$KioskSid, [string]$TaskAccount, [string]$EdgeExePath)
    # Two tasks, because Assigned Access's AppLocker rules only let the kiosk
    # account run AllowedApps - it can't run a script to check whether Edge is
    # already open (launching msedge.exe unconditionally would stack up a new
    # window on every unlock). So:
    #  - EdgeOnUnlock runs as SYSTEM on the kiosk account's unlock, and starts
    #    LaunchEdge only if that account has no msedge.exe running.
    #  - LaunchEdge runs msedge.exe as the kiosk account in its interactive
    #    session (msedge.exe is in AllowedApps, so it's permitted).
    Unregister-EdgeUnlockTasks

    $launchPrincipal = New-ScheduledTaskPrincipal -UserId $TaskAccount -LogonType Interactive -RunLevel Limited
    # ExecutionTimeLimit 0 = no limit; otherwise Task Scheduler kills Edge after 72h.
    $launchSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskPath $KioskTaskPath -TaskName $EdgeLaunchTaskName `
        -Action (New-ScheduledTaskAction -Execute $EdgeExePath -Argument $EdgeLaunchArguments) `
        -Principal $launchPrincipal -Settings $launchSettings -ErrorAction Stop | Out-Null

    $check = @"
`$running = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
    Where-Object { (Invoke-CimMethod -InputObject `$_ -MethodName GetOwnerSid).Sid -eq '$KioskSid' }
if (-not `$running) { Start-ScheduledTask -TaskPath '$KioskTaskPath' -TaskName '$EdgeLaunchTaskName' }
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($check))
    $watchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded"
    $unlockTriggerClass = Get-CimClass -Namespace "ROOT\Microsoft\Windows\TaskScheduler" -ClassName "MSFT_TaskSessionStateChangeTrigger"
    $unlockTrigger = New-CimInstance -CimClass $unlockTriggerClass -ClientOnly
    $unlockTrigger.StateChange = 8   # TASK_SESSION_UNLOCK
    $unlockTrigger.UserId = $TaskAccount
    $unlockTrigger.Enabled = $true
    $watchSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskPath $KioskTaskPath -TaskName $UnlockWatchTaskName `
        -Action $watchAction -Trigger $unlockTrigger `
        -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest) `
        -Settings $watchSettings -ErrorAction Stop | Out-Null
}

function Unregister-EdgeUnlockTasks {
    foreach ($name in $UnlockWatchTaskName, $EdgeLaunchTaskName) {
        if (Get-ScheduledTask -TaskPath $KioskTaskPath -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskPath $KioskTaskPath -TaskName $name -Confirm:$false
        }
    }
    # Remove the \Kiosk\ folder too, if it's now empty.
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $folder = $scheduler.GetFolder($KioskTaskPath.TrimEnd('\'))
        if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) {
            $scheduler.GetFolder("\").DeleteFolder($KioskTaskPath.Trim('\'), 0)
        }
    } catch { }
}

function Enable-Kiosk {
    Write-Host "Enabling kiosk configuration..."

    # --- Resolve the kiosk account's SID and load its registry hive up
    # front: every Edge policy and the Task Manager lockdown are written
    # there, so they apply to that account only. Without the hive the kiosk
    # would get an unrestricted Edge, so bail out here, before anything is
    # changed. ---
    $kioskSid = Resolve-KioskUserSid -KioskUser $KioskUser
    if (-not $kioskSid) {
        Write-Error "Could not resolve a SID for '$KioskUser' - its registry hive is needed for the Edge policies. Nothing was changed."
        exit 1
    }
    try {
        $loadedHere = Mount-KioskHive -Sid $kioskSid
    } catch {
        Write-Error "$($_.Exception.Message) Nothing was changed."
        exit 1
    }
    $hiveRoot = "Registry::HKEY_USERS\$kioskSid"
    $EdgePolicyPath = "$hiveRoot\$EdgePolicySubKey"
    $script:WrittenValues = @()

    $succeeded = $false
    try {

    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_AssignedAccess"
    try {
        $aaObj = Get-CimInstance -Namespace $namespaceName -ClassName $className
    } catch {
        throw "Could not access the Assigned Access (MDM_AssignedAccess) WMI class - this Windows edition/SKU likely doesn't support multi-app kiosk mode. $($_.Exception.Message)"
    }
    # Disable finds the kiosk account from the applied config, so switching
    # accounts in place would leave the old one's policies behind.
    $appliedAccount = Get-KioskAccountFromConfig -Configuration $aaObj.Configuration
    $alreadyApplied = $false
    if ($appliedAccount) {
        if ((Resolve-KioskUserSid -KioskUser $appliedAccount) -ne $kioskSid) {
            throw "Kiosk mode is already enabled for a different account ('$appliedAccount'). Run '.\kioskMode.ps1 -Enabled false' first, then re-run."
        }
        $alreadyApplied = $true
    }

    # --- Demote the kiosk account out of Administrators if it's currently a
    # member: Assigned Access refuses to configure an admin account and
    # Windows surfaces that refusal as an opaque "general error" from
    # Set-CimInstance below rather than a clear message, so this has to
    # happen before that call, not after it fails. Not undone on disable.
    $isAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID.Value -eq $kioskSid })
    if ($isAdmin) {
        Write-Host "'$KioskUser' is a local administrator - Assigned Access requires a standard account, so removing it from Administrators (it stays a standard user if kiosk mode is disabled)."
        Remove-LocalGroupMember -Group "Administrators" -Member $kioskSid
    }

    # --- Make sure OneAuth (the kiosk's packaged app) is available to the
    # kiosk account - Assigned Access doesn't install apps, it just shows
    # nothing for an AUMID that isn't installed. ---
    Install-OneAuth -KioskSid $kioskSid

    # --- Edge pins use the stock shortcut (see the note above
    # $StockEdgeShortcutPath). AllowedApps must still declare the real
    # msedge.exe path - Windows resolves a pinned shortcut's target back to an
    # AllowedApps entry to validate it. ---
    $edgeExePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path $StockEdgeShortcutPath)) {
        Write-Warning "Stock Edge shortcut not found at $StockEdgeShortcutPath - Edge will be missing from Start and the taskbar until Edge is repaired/reinstalled."
    }

    # --- Write the Assigned Access XML ---
    # StartPins/TaskbarLayout are JSON/XML inside CDATA blocks, so any path
    # substituted into the JSON one needs its backslashes doubled (a lone
    # "\" is an invalid JSON escape); the XML one takes a plain backslash.
    # Edge is allowed twice on purpose: DesktopAppPath lets msedge.exe run,
    # but Start filters its pins by AUMID - without "MSEdge" listed too, the
    # Start pin is silently dropped (the taskbar pin doesn't filter this way).
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
                    <App DesktopAppPath="$edgeExePath" rs5:AutoLaunch="true" rs5:AutoLaunchArguments="$EdgeLaunchArguments" />
                    <App AppUserModelId="MSEdge" />
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

    # --- Edge policy (kiosk account's hive) ---
    foreach ($policy in $EdgePolicyValues) {
        $type = if ($policy.Type) { $policy.Type } else { "DWord" }
        Set-PolicyValue -Path $EdgePolicyPath -Name $policy.Name -Value $policy.Value -Type $type
    }
    foreach ($listName in $EdgePolicyLists.Keys) {
        Set-PolicyList -Path "$EdgePolicyPath\$listName" -Values $EdgePolicyLists[$listName]
    }

    # --- Refresh the Microsoft 365 domain allowlist ---
    $existingDomains = Get-CurrentAllowlistDomains -PolicyPath $EdgePolicyPath
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
    Set-PolicyList -Path "$EdgePolicyPath\$EdgeAllowlistKey" -Values $domainsToApply

    # --- Disable the Windows Copilot taskbar button (see $CopilotPolicyPath) ---
    Set-PolicyValue -Path $CopilotPolicyPath -Name $CopilotPolicyName -Value 1

    # --- Power: display off after $DisplayOffMinutes min, never sleep, no
    # Fast Startup (see $PowerPolicyPath). Not undone on disable. ---
    foreach ($setting in "monitor-timeout-ac $DisplayOffMinutes", "monitor-timeout-dc $DisplayOffMinutes",
                         "standby-timeout-ac 0", "standby-timeout-dc 0",
                         "hibernate-timeout-ac 0", "hibernate-timeout-dc 0") {
        & powercfg.exe /change @($setting -split ' ') *> $null
        if ($LASTEXITCODE -ne 0) { Write-Warning "powercfg /change $setting failed (exit code $LASTEXITCODE) - the power policy below still applies it after a reboot." }
    }
    foreach ($guid in $PowerPolicySettings.Keys) {
        Set-PolicyValue -Path "$PowerPolicyPath\$guid" -Name "ACSettingIndex" -Value $PowerPolicySettings[$guid]
        Set-PolicyValue -Path "$PowerPolicyPath\$guid" -Name "DCSettingIndex" -Value $PowerPolicySettings[$guid]
    }
    Set-PolicyValue -Path $FastStartupPath -Name $FastStartupName -Value 0

    # --- Per-user: disable Task Manager and "Change a password" ---
    foreach ($name in $UserSystemPolicyNames) {
        Set-PolicyValue -Path "$hiveRoot\$UserSystemPolicySubKey" -Name $name -Value 1
    }

    # --- Clear any taskbar pins left over from before kiosk mode ---
    # Windows only fully re-applies an Assigned Access TaskbarLayout pin list
    # on a profile's first-ever sign-in. On an account that already used the
    # desktop normally, its previously-pinned Edge icon (plain, no baked-in
    # homepage) survives alongside the new kiosk shortcut pin, producing two
    # Edge icons on the taskbar. Skipped when kiosk mode is already applied:
    # the pins there now are the kiosk's own.
    if (-not $alreadyApplied) {
        Reset-KioskTaskbarPins -Sid $kioskSid
    }

    # --- Relaunch Edge on unlock (sign-in is covered by AutoLaunch in the XML) ---
    try {
        $taskAccount = Resolve-KioskTaskAccount -KioskUser $KioskUser -KioskSid $kioskSid
        Register-EdgeUnlockTasks -KioskSid $kioskSid -TaskAccount $taskAccount -EdgeExePath $edgeExePath
        Write-Host "  [OK] Scheduled tasks $KioskTaskPath$UnlockWatchTaskName / $EdgeLaunchTaskName registered for $taskAccount (Edge relaunches on unlock)."
    } catch {
        Write-Warning "Could not register the Edge-on-unlock scheduled tasks ($($_.Exception.Message)) - Edge will still auto-launch at sign-in, but not on unlock."
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
    Write-Host "Re-checking all written registry values..."
    $verifyFailures = 0
    foreach ($written in $script:WrittenValues) {
        if (-not (Confirm-RegistryValue -Path $written.Path -Name $written.Name -ExpectedValue $written.Value)) {
            $verifyFailures++
        }
    }
    $expectedBlocklistCount = $EdgePolicyLists["URLBlocklist"].Count
    $finalBlocklistCount = (Get-Item "$EdgePolicyPath\URLBlocklist" -ErrorAction SilentlyContinue).Property.Count
    $finalAllowlistCount = (Get-Item "$EdgePolicyPath\$EdgeAllowlistKey" -ErrorAction SilentlyContinue).Property.Count
    Write-Host "  URLBlocklist entries present: $finalBlocklistCount (expected $expectedBlocklistCount)"
    Write-Host "  URLAllowlist entries present: $finalAllowlistCount (expected $($domainsToApply.Count))"
    if ($verifyFailures -gt 0 -or $finalBlocklistCount -ne $expectedBlocklistCount -or $finalAllowlistCount -ne $domainsToApply.Count) {
        Write-Warning "$verifyFailures value(s) and/or the URLBlocklist/URLAllowlist counts no longer match what was just written - something is reverting these registry values during the script run itself, not just afterward."
    } else {
        Write-Host "  All written values still present immediately after the run completed."
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
        if ($loadedHere) { Dismount-KioskHive -Sid $kioskSid }
    }

    if (-not $succeeded) {
        Write-Error "Run '.\kioskMode.ps1 -Enabled false -KioskUser `"$KioskUser`"' to remove the partial changes, then re-run to retry."
        exit 1
    }

    Write-Host "Kiosk configuration applied. Reboot (or sign the kiosk account out/in) to take effect."
}

function Disable-Kiosk {
    Write-Host "Removing kiosk configuration..."
    try {

    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_AssignedAccess"
    $aaObj = Get-CimInstance -Namespace $namespaceName -ClassName $className
    $appliedAccount = Get-KioskAccountFromConfig -Configuration $aaObj.Configuration

    # --- Per-user settings, in the kiosk account's hive. Done before the
    # Assigned Access config is cleared, since that's where the account is
    # read from - so a failed disable can simply be re-run. ---
    $account = if (-not [string]::IsNullOrWhiteSpace($KioskUser)) { $KioskUser } else { $appliedAccount }
    $kioskSid = if ($account) { Resolve-KioskUserSid -KioskUser $account } else { $null }
    if (-not $kioskSid) {
        Write-Warning "Could not determine the kiosk account (no kiosk Assigned Access config applied and no -KioskUser given) - its per-user Edge/Task Manager policies were not removed. Re-run with -KioskUser to remove them."
    } else {
        $loadedHere = Mount-KioskHive -Sid $kioskSid
        try {
            $hiveRoot = "Registry::HKEY_USERS\$kioskSid"
            $EdgePolicyPath = "$hiveRoot\$EdgePolicySubKey"
            foreach ($policy in $EdgePolicyValues) {
                Remove-PolicyValue -Path $EdgePolicyPath -Name $policy.Name
            }
            foreach ($listName in @($EdgePolicyLists.Keys) + $EdgeAllowlistKey) {
                Remove-Item -Path "$EdgePolicyPath\$listName" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Remove-EmptyKey -Path $EdgePolicyPath
            foreach ($name in $UserSystemPolicyNames) {
                Remove-PolicyValue -Path "$hiveRoot\$UserSystemPolicySubKey" -Name $name
            }
            Remove-EmptyKey -Path "$hiveRoot\$UserSystemPolicySubKey"
            # Only while the kiosk layout is applied - otherwise these are the
            # account's own pins. Windows rebuilds its defaults at next sign-in.
            if ($appliedAccount) {
                Reset-KioskTaskbarPins -Sid $kioskSid
            }
            Write-Host "  [OK] Removed the kiosk policies from '$account'."
        } finally {
            if ($loadedHere) { Dismount-KioskHive -Sid $kioskSid }
        }
    }

    Remove-PolicyValue -Path $CopilotPolicyPath -Name $CopilotPolicyName
    Remove-EmptyKey -Path $CopilotPolicyPath

    # --- Clear Assigned Access, only if it's this script's config ---
    if ($appliedAccount) {
        $aaObj.Configuration = $null
        Set-CimInstance -CimInstance $aaObj
    }

    # --- Remove the scheduled tasks and C:\ProgramData\Kiosk\ ---
    Unregister-EdgeUnlockTasks
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

    } catch {
        Write-Error "Kiosk disable failed partway through: $($_.Exception.Message). Re-run '.\kioskMode.ps1 -Enabled false' to retry."
        exit 1
    }

    Write-Host "Kiosk configuration removed. Reboot to complete."
}

# ===========================================================================
# Run
# ===========================================================================
if ($EnableKiosk) { Enable-Kiosk } else { Disable-Kiosk }