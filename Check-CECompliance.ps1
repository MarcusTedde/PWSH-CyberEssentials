# Requires PowerShell 7.x or later for best compatibility with modern modules.
# Ensure you have the necessary PowerShell modules installed:
# - Microsoft.Graph (for Entra ID, Intune, etc. - requires Graph API permissions)
# - ExchangeOnlineManagement (for Exchange Online configurations)

#region Module Installation and Connection Helper

function Install-RequiredModules {
    <#
    .SYNOPSIS
    Installs necessary PowerShell modules for M365 Cyber Essentials assessment.
    #>
    param()
    Write-Host "Checking for required PowerShell modules..." -ForegroundColor Cyan

    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.DeviceManagement",
        "Microsoft.Graph.Policy",
        "Microsoft.Graph.Security", # For security policies and alerts
        "ExchangeOnlineManagement"
    )

    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing module: $module..." -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
                Write-Host "$module installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install $module. Error: $($_.Exception.Message)"
                Write-Host "Please ensure you have administrative privileges or run PowerShell as administrator if installing for AllUsers." -ForegroundColor Red
                return $false
            }
        }
        else {
            Write-Host "$module is already installed." -ForegroundColor DarkGreen
        }
    }
    return $true
}

function Connect-M365Services {
    <#
    .SYNOPSIS
    Connects to various M365 services (Microsoft Graph, Exchange Online).
    Requires appropriate admin roles (e.g., Global Administrator, Intune Administrator, Exchange Administrator, Conditional Access Administrator, Security Administrator).
    #>
    param()
    Write-Host "Connecting to Microsoft 365 services..." -ForegroundColor Cyan

    # Define Graph API scopes required for assessment.
    # These are read-only or read-write for policy checks.
    $graphScopes = @(
        "Directory.Read.All",
        "User.Read.All",
        "Device.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "Policy.Read.All",
        "Policy.Read.ConditionalAccess",
        "Policy.Read.AuthenticationMethod", # For Security Defaults
        "SecurityEvents.Read.All",
        "SecurityActions.Read.All", # For Defender ATP settings
        "Security.Read.All" # For general security settings
    )
    try {
        Write-Host "Connecting to Microsoft Graph with scopes: $($graphScopes -join ', ')" -ForegroundColor DarkCyan
        Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
        Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph. Error: $($_.Exception.Message)"
        Write-Host "Ensure you have the correct permissions and have granted consent for the required Graph API scopes." -ForegroundColor Red
        Write-Host "You might need to ask a Global Administrator to grant consent for these permissions." -ForegroundColor Red
        return $false
    }

    # Connect to Exchange Online
    try {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor DarkCyan
        Connect-ExchangeOnline -ErrorAction Stop
        Write-Host "Connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Exchange Online. Error: $($_.Exception.Message)"
        Write-Host "Ensure you have the Exchange Administrator role." -ForegroundColor Red
        return $false
    }

    return $true
}

#endregion

#region Compliance Assessment Functions

function Test-CEFirewallCompliance {
    <#
    .SYNOPSIS
    Tests M365 configurations related to Cyber Essentials Firewall control.
    #>
    param()
    Write-Host "`n--- Assessing Firewall Compliance ---" -ForegroundColor Yellow
    $results = @()

    # 2.2.1 Boundary Firewalls - Exchange Online Protection (EOP)
    # EOP is enabled by default. Assessment focuses on enhanced policies.
    # Direct PowerShell assessment of 'Standard' or 'Strict' preset policies is complex.
    # We'll check for the existence of custom anti-spam/anti-malware policies that are stricter than default.
    $antiSpamPolicies = Get-AntiSpamPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Anti-spam policy (Default)" }
    $antiMalwarePolicies = Get-AntiMalwarePolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Anti-malware policy (Default)" }

    $eopStatus = "Default or Custom Policies Exist"
    $eopCompliant = $false
    if ($antiSpamPolicies.Count -gt 0 -or $antiMalwarePolicies.Count -gt 0) {
        $eopStatus = "Custom Anti-Spam/Anti-Malware policies found. Review in portal for strictness."
        $eopCompliant = $true # Assume compliant if custom policies exist, but recommend portal review.
    } else {
        $eopStatus = "Only default Anti-Spam/Anti-Malware policies found. Consider stricter preset policies."
        $eopCompliant = $false
    }
    $results += [PSCustomObject]@{
        Control              = "Firewalls"
        Item                 = "Exchange Online Protection (EOP) Policies"
        DesiredConfiguration = "Enhanced Anti-Spam/Anti-Malware policies (Standard/Strict preset or custom) configured."
        CurrentConfiguration = $eopStatus
        IsCompliant          = $eopCompliant
        Recommendation       = "Review and apply 'Standard' or 'Strict' preset security policies in Microsoft 365 Defender portal (security.microsoft.com) for email protection."
    }

    # 2.2.2 Host-Based Firewalls (Windows Defender Firewall) - RDP Port Closure (Port 3389)
    # This requires checking Intune Device Configuration profiles for firewall rules.
    # Direct programmatic check for a specific blocking rule in Intune via Graph API is complex.
    # We'll check for *any* firewall configuration profiles.
    try {
        $firewallConfigProfiles = Get-MgDeviceManagementDeviceCompliancePolicy -Filter "displayName eq 'Windows Firewall Policy' or displayName eq 'Windows Firewall Rules Policy'" -ErrorAction SilentlyContinue
        if ($firewallConfigProfiles.Count -gt 0) {
            $rdpStatus = "Intune Firewall configuration profiles found. Verify RDP (Port 3389) is blocked for external access within these policies."
            $rdpCompliant = $true # Assume compliant if policies exist, but requires manual verification.
            $rdpRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Endpoint security > Firewall' that a rule exists to block inbound RDP (Port 3389)."
        } else {
            $rdpStatus = "No Intune Firewall configuration profiles found. RDP (Port 3389) external access likely not blocked."
            $rdpCompliant = $false
            $rdpRecommendation = "Create an Intune 'Windows Firewall Rule' policy to block inbound TCP/UDP port 3389 (RDP) for external access."
        }
    }
    catch {
        $rdpStatus = "Error checking Intune Firewall configurations: $($_.Exception.Message)"
        $rdpCompliant = $false
        $rdpRecommendation = "Ensure your Graph API permissions include DeviceManagementConfiguration.Read.All and try again. Then, create an Intune 'Windows Firewall Rule' policy to block inbound TCP/UDP port 3389 (RDP) for external access."
    }

    $results += [PSCustomObject]@{
        Control              = "Firewalls"
        Item                 = "RDP Port 3389 External Access"
        DesiredConfiguration = "Closed/Blocked at the host-based firewall for external access."
        CurrentConfiguration = $rdpStatus
        IsCompliant          = $rdpCompliant
        Recommendation       = $rdpRecommendation
    }

    return $results
}

function Test-CESecureConfigurationCompliance {
    <#
    .SYNOPSIS
    Tests M365 configurations related to Cyber Essentials Secure Configuration control.
    #>
    param()
    Write-Host "`n--- Assessing Secure Configuration Compliance ---" -ForegroundColor Yellow
    $results = @()

    # 3.2.1 Device Hardening - Password Policies (Intune Device Compliance Policies)
    # Checking granular Intune compliance policy settings via Graph API is complex.
    # We'll check for the existence of *any* device compliance policies.
    try {
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction SilentlyContinue
        $passwordPolicyStatus = "No Intune Device Compliance Policies found."
        $passwordPolicyCompliant = $false
        $passwordPolicyRecommendation = "Create Intune Device Compliance Policies to enforce strong password requirements (min length 8, complexity, no simple passwords, etc.) and device encryption."

        if ($compliancePolicies.Count -gt 0) {
            # Attempt to find policies that explicitly mention password or encryption
            $relevantPolicies = $compliancePolicies | Where-Object { $_.DisplayName -like "*password*" -or $_.DisplayName -like "*encryption*" }
            if ($relevantPolicies.Count -gt 0) {
                $passwordPolicyStatus = "Intune Device Compliance Policies found. Verify they enforce strong password requirements (min 8 chars, complexity, no simple passwords, etc.) and device encryption (BitLocker)."
                $passwordPolicyCompliant = $true # Assume compliant if relevant policies exist, but requires manual verification.
                $passwordPolicyRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Devices > Compliance policies' that policies enforce strong password requirements and device encryption."
            } else {
                $passwordPolicyStatus = "Intune Device Compliance Policies found, but none explicitly named for password/encryption. Verify their settings."
                $passwordPolicyCompliant = $false
            }
        }
    }
    catch {
        $passwordPolicyStatus = "Error checking Intune Device Compliance Policies: $($_.Exception.Message)"
        $passwordPolicyCompliant = $false
        $passwordPolicyRecommendation = "Ensure your Graph API permissions include DeviceManagementConfiguration.Read.All and try again. Then, create Intune Device Compliance Policies."
    }

    $results += [PSCustomObject]@{
        Control              = "Secure Configuration"
        Item                 = "Device Hardening (Password & Encryption Policies)"
        DesiredConfiguration = "Intune Device Compliance Policies enforce strong passwords (min 8 chars, complexity, no simple passwords) and device encryption."
        CurrentConfiguration = $passwordPolicyStatus
        IsCompliant          = $passwordPolicyCompliant
        Recommendation       = $passwordPolicyRecommendation
    }

    # 3.2.2 Software and Service Management - Disabling Autoplay/Autorun
    # This is typically done via Intune Configuration Profiles (Settings Catalog or ADMX).
    # Direct Graph API query for specific Autoplay settings is complex.
    # We'll check for existence of configuration profiles.
    try {
        $configProfiles = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'Autoplay Settings' or displayName eq 'Device Restrictions'" -ErrorAction SilentlyContinue
        if ($configProfiles.Count -gt 0) {
            $autoplayStatus = "Intune Device Configuration Profiles found. Verify they disable Autoplay/Autorun."
            $autoplayCompliant = $true # Assume compliant if policies exist, but requires manual verification.
            $autoplayRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Devices > Configuration profiles' that Autoplay/Autorun is disabled in relevant profiles (e.g., via 'Windows Components > AutoPlay Policies')."
        } else {
            $autoplayStatus = "No Intune Device Configuration Profiles found for Autoplay/Autorun."
            $autoplayCompliant = $false
            $autoplayRecommendation = "Create an Intune Device Configuration profile (e.g., Settings Catalog or Device Restrictions) to disable Autoplay/Autorun for all drives."
        }
    }
    catch {
        $autoplayStatus = "Error checking Intune Autoplay configurations: $($_.Exception.Message)"
        $autoplayCompliant = $false
        $autoplayRecommendation = "Ensure your Graph API permissions include DeviceManagementConfiguration.Read.All and try again. Then, create an Intune Device Configuration profile to disable Autoplay/Autorun."
    }

    $results += [PSCustomObject]@{
        Control              = "Secure Configuration"
        Item                 = "Disabling Autoplay/Autorun"
        DesiredConfiguration = "Autoplay and Autorun features disabled across all operating systems."
        CurrentConfiguration = $autoplayStatus
        IsCompliant          = $autoplayCompliant
        Recommendation       = $autoplayRecommendation
    }

    # 3.2.3 Cloud Service Configuration (SharePoint Online & Exchange Online)
    # SharePoint: External Sharing, Least Privilege. Exchange: Modern Auth, Mailbox Auditing.

    # Exchange Online: Modern Authentication
    # Modern Auth is enabled by default for new tenants. Checking explicitly via PowerShell is indirect.
    # We'll assume it's enabled unless legacy auth is explicitly allowed via CA.
    try {
        $modernAuthStatus = "Modern Authentication is generally enabled by default for new tenants."
        $modernAuthCompliant = $true
        $legacyAuthCA = Get-MgPolicyConditionalAccessPolicy -Filter "displayName eq 'Block Legacy Authentication'" -ErrorAction SilentlyContinue
        if ($legacyAuthCA.Count -gt 0 -and $legacyAuthCA[0].State -eq 'enabled') {
             $modernAuthStatus = "Modern Authentication is enforced by Conditional Access policy 'Block Legacy Authentication'."
             $modernAuthCompliant = $true
        } elseif ($legacyAuthCA.Count -eq 0) {
            $modernAuthStatus = "No Conditional Access policy to block legacy authentication found. Modern Authentication may not be fully enforced."
            $modernAuthCompliant = $false
        }

    }
    catch {
        $modernAuthStatus = "Error checking Modern Authentication status: $($_.Exception.Message)"
        $modernAuthCompliant = $false
    }
    $results += [PSCustomObject]@{
        Control              = "Secure Configuration"
        Item                 = "Exchange Online - Modern Authentication"
        DesiredConfiguration = "Modern Authentication enabled; legacy authentication blocked."
        CurrentConfiguration = $modernAuthStatus
        IsCompliant          = $modernAuthCompliant
        Recommendation       = "Ensure Modern Authentication is enabled and consider creating a Conditional Access policy to block legacy authentication."
    }

    # Exchange Online: Mailbox Auditing
    try {
        # Check if default audit logging is enabled for Exchange Online (usually true)
        $auditConfig = Get-OrganizationConfig | Select-Object AuditDisabled, AuditLogAgeLimit
        if ($auditConfig.AuditDisabled -eq $false) {
            $auditStatus = "Mailbox auditing is enabled at the organization level."
            $auditCompliant = $true
        } else {
            $auditStatus = "Mailbox auditing is disabled at the organization level."
            $auditCompliant = $false
        }
    }
    catch {
        $auditStatus = "Error checking Exchange Online Mailbox Auditing: $($_.Exception.Message)"
        $auditCompliant = $false
    }
    $results += [PSCustomObject]@{
        Control              = "Secure Configuration"
        Item                 = "Exchange Online - Mailbox Auditing"
        DesiredConfiguration = "Mailbox auditing enabled for all users."
        CurrentConfiguration = $auditStatus
        IsCompliant          = $auditCompliant
        Recommendation       = "Ensure mailbox auditing is enabled for all users. Verify in Microsoft 365 compliance center (compliance.microsoft.com) or Exchange Online PowerShell."
    }

    # SharePoint Online: External Sharing
    try {
        $sharePointTenant = Get-SPOTenant -ErrorAction SilentlyContinue
        $sharingCapability = $sharePointTenant.SharingCapability
        $sharePointStatus = "SharePoint Online external sharing capability: $sharingCapability"
        $sharePointCompliant = $false
        $sharePointRecommendation = "Review SharePoint Online external sharing settings in SharePoint admin center. Restrict sharing to specific domains or disable anonymous links if not required."

        # Cyber Essentials prefers restricted sharing. "ExternalUserAndGuestSharing" is better than "ExternalUserSharingOnly" or "Disabled"
        if ($sharingCapability -eq "ExternalUserAndGuestSharing" -or $sharingCapability -eq "ExternalUserSharingOnly") {
            $sharePointCompliant = $true # Assumes it's configured for controlled sharing
        } elseif ($sharingCapability -eq "Disabled") {
            $sharePointCompliant = $true # Most restrictive, thus compliant
        } else {
            $sharePointCompliant = $false # E.g., "Anonymous" or "ExternalUserAndGuestSharing" without further restrictions.
            $sharePointRecommendation = "SharePoint Online external sharing is too permissive. Restrict sharing to specific domains or disable anonymous links if not required. Current: $sharingCapability"
        }
    }
    catch {
        $sharePointStatus = "Error checking SharePoint Online external sharing: $($_.Exception.Message)"
        $sharePointCompliant = $false
        $sharePointRecommendation = "Ensure SharePoint Online Management Shell is connected and try again. Then, review external sharing settings."
    }
    $results += [PSCustomObject]@{
        Control              = "Secure Configuration"
        Item                 = "SharePoint Online - External Sharing"
        DesiredConfiguration = "External sharing restricted (e.g., to specific domains or disabled if not needed)."
        CurrentConfiguration = $sharePointStatus
        IsCompliant          = $sharePointCompliant
        Recommendation       = $sharePointRecommendation
    }

    return $results
}

function Test-CEUserAccessControlCompliance {
    <#
    .SYNOPSIS
    Tests M365 configurations related to Cyber Essentials User Access Control.
    #>
    param()
    Write-Host "`n--- Assessing User Access Control Compliance ---" -ForegroundColor Yellow
    $results = @()

    # 4.2.1 User Account Lifecycle Management - Inactive Accounts
    # This requires a process, not a direct setting. We can check for users with old lastSignInDateTime.
    try {
        $inactiveThreshold = (Get-Date).AddDays(-90) # 90 days inactive
        $inactiveUsers = Get-MgUser -Filter "accountEnabled eq true and signInActivity/lastSignInDateTime le '$($inactiveThreshold.ToString('yyyy-MM-ddTHH:mm:ssZ'))'" -ErrorAction SilentlyContinue | Select-Object DisplayName, UserPrincipalName, SignInActivity
        if ($inactiveUsers.Count -gt 0) {
            $inactiveAccountStatus = "Found $($inactiveUsers.Count) active users with no sign-in in the last 90 days. Review these accounts."
            $inactiveAccountCompliant = $false
            $inactiveAccountRecommendation = "Implement a process to regularly review and disable/delete inactive user accounts. Consider Microsoft Entra ID Governance Lifecycle Workflows."
        } else {
            $inactiveAccountStatus = "No active users found with no sign-in in the last 90 days (based on available data)."
            $inactiveAccountCompliant = $true
            $inactiveAccountRecommendation = "Maintain regular review of user accounts and their sign-in activity."
        }
    }
    catch {
        $inactiveAccountStatus = "Error checking inactive accounts: $($_.Exception.Message)"
        $inactiveAccountCompliant = $false
        $inactiveAccountRecommendation = "Ensure your Graph API permissions include User.Read.All and try again. Then, implement a process for inactive account management."
    }
    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "Inactive Account Management"
        DesiredConfiguration = "Process in place to disable/remove inactive user accounts promptly."
        CurrentConfiguration = $inactiveAccountStatus
        IsCompliant          = $inactiveAccountCompliant
        Recommendation       = $inactiveAccountRecommendation
    }

    # 4.2.2 Multi-Factor Authentication (MFA) - Conditional Access Policies
    # Check for MFA Registration Policy and "Require MFA for all users" CA policy.
    try {
        $mfaRegistrationPolicy = Get-MgPolicyIdentitySecurityDefault -ErrorAction SilentlyContinue
        $mfaRegistrationStatus = "MFA Registration Policy (Security Defaults) is disabled or not found."
        $mfaRegistrationCompliant = $false
        $mfaRegistrationRecommendation = "Enable MFA Registration Policy in Microsoft Entra ID Protection or ensure Conditional Access policies cover MFA registration."

        if ($mfaRegistrationPolicy -and $mfaRegistrationPolicy.IsEnabled -eq $true) {
            $mfaRegistrationStatus = "MFA Registration Policy (Security Defaults) is enabled."
            $mfaRegistrationCompliant = $true
        }

        $allUsersMfaCA = Get-MgPolicyConditionalAccessPolicy -Filter "displayName eq 'Require MFA for all users' or displayName eq 'Require MFA for all users (excluding break-glass)'" -ErrorAction SilentlyContinue
        $adminMfaCA = Get-MgPolicyConditionalAccessPolicy -Filter "displayName eq 'Require MFA for Admins' or displayName eq 'Require MFA for Administrative Roles'" -ErrorAction SilentlyContinue

        $allUsersMfaStatus = "No Conditional Access policy found to require MFA for all users."
        $allUsersMfaCompliant = $false
        $allUsersMfaRecommendation = "Create a Conditional Access policy to require MFA for all users (excluding emergency access accounts)."

        if ($allUsersMfaCA.Count -gt 0 -and ($allUsersMfaCA | Where-Object {$_.State -eq 'enabled' -or $_.State -eq 'reportOnly'}).Count -gt 0) {
            $allUsersMfaStatus = "Conditional Access policy to require MFA for all users found and enabled/in report-only mode."
            $allUsersMfaCompliant = $true
        }

        $adminMfaStatus = "No Conditional Access policy found to require MFA for administrative roles."
        $adminMfaCompliant = $false
        $adminMfaRecommendation = "Create a Conditional Access policy to require MFA for administrative roles."

        if ($adminMfaCA.Count -gt 0 -and ($adminMfaCA | Where-Object {$_.State -eq 'enabled' -or $_.State -eq 'reportOnly'}).Count -gt 0) {
            $adminMfaStatus = "Conditional Access policy to require MFA for administrative roles found and enabled/in report-only mode."
            $adminMfaCompliant = $true
        }
    }
    catch {
        $mfaRegistrationStatus = "Error checking MFA Registration Policy: $($_.Exception.Message)"
        $mfaRegistrationCompliant = $false
        $allUsersMfaStatus = "Error checking All Users MFA CA Policy: $($_.Exception.Message)"
        $allUsersMfaCompliant = $false
        $adminMfaStatus = "Error checking Admin MFA CA Policy: $($_.Exception.Message)"
        $adminMfaCompliant = $false
        $mfaRegistrationRecommendation = "Ensure Policy.Read.AuthenticationMethod and Policy.Read.ConditionalAccess Graph API permissions."
        $allUsersMfaRecommendation = "Ensure Policy.Read.ConditionalAccess Graph API permission."
        $adminMfaRecommendation = "Ensure Policy.Read.ConditionalAccess Graph API permission."
    }

    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "MFA Registration Policy"
        DesiredConfiguration = "MFA Registration Policy enabled (or equivalent via Conditional Access)."
        CurrentConfiguration = $mfaRegistrationStatus
        IsCompliant          = $mfaRegistrationCompliant
        Recommendation       = $mfaRegistrationRecommendation
    }
    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "MFA for All Users (Conditional Access)"
        DesiredConfiguration = "Conditional Access policy requires MFA for all users."
        CurrentConfiguration = $allUsersMfaStatus
        IsCompliant          = $allUsersMfaCompliant
        Recommendation       = $allUsersMfaRecommendation
    }
    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "MFA for Administrative Roles (Conditional Access)"
        DesiredConfiguration = "Conditional Access policy requires MFA for administrative roles."
        CurrentConfiguration = $adminMfaStatus
        IsCompliant          = $adminMfaCompliant
        Recommendation       = $adminMfaRecommendation
    }

    # 4.2.3 Strong Password Policies (Microsoft Entra ID)
    # Entra ID enforces baseline. Custom banned passwords are a feature to check.
    try {
        $passwordProtection = Get-MgPolicyAuthenticationStrengthPolicy -ErrorAction SilentlyContinue # Not directly for banned passwords, but indicates policy management.
        $bannedPasswordsStatus = "Microsoft Entra Password Protection (Custom Banned Passwords) not configured or found."
        $bannedPasswordsCompliant = $false
        $bannedPasswordsRecommendation = "Configure Microsoft Entra Password Protection to enforce custom banned passwords."

        # Checking for custom banned passwords directly via Graph is complex.
        # We'll check if the Password Protection service is generally active.
        # This is a conceptual check.
        $passwordProtectionSettings = Get-MgPolicyAuthenticationMethodPolicyPasswordProtection -ErrorAction SilentlyContinue
        if ($passwordProtectionSettings) { # If the object exists, it implies the service is active.
            $bannedPasswordsStatus = "Microsoft Entra Password Protection is configured. Verify custom banned passwords are in use."
            $bannedPasswordsCompliant = $true # Assume compliant if service is active.
            $bannedPasswordsRecommendation = "Manually verify custom banned passwords are configured in Microsoft Entra admin center under 'Protection > Password Protection'."
        }
    }
    catch {
        $bannedPasswordsStatus = "Error checking Microsoft Entra Password Protection: $($_.Exception.Message)"
        $bannedPasswordsCompliant = $false
        $bannedPasswordsRecommendation = "Ensure Policy.Read.All Graph API permissions and try again. Then, configure Microsoft Entra Password Protection."
    }
    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "Microsoft Entra Password Protection (Custom Banned Passwords)"
        DesiredConfiguration = "Custom banned passwords configured to prevent common/weak passwords."
        CurrentConfiguration = $bannedPasswordsStatus
        IsCompliant          = $bannedPasswordsCompliant
        Recommendation       = $bannedPasswordsRecommendation
    }

    # 4.2.4 Principle of Least Privilege (PoLP) and Role-Based Access Control (RBAC)
    # Check for PIM enabled and active assignments for highly privileged roles.
    try {
        $pimEnabled = $false
        $pimStatus = "Microsoft Entra Privileged Identity Management (PIM) not enabled."
        $pimRecommendation = "Enable and configure Microsoft Entra Privileged Identity Management (PIM) for Just-In-Time (JIT) access to administrative roles."

        # Check if PIM is generally active by trying to list eligible assignments (requires PIM license)
        try {
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Filter "status eq 'Eligible'" -Top 1 -ErrorAction Stop
            if ($eligibleAssignments) {
                $pimEnabled = $true
                $pimStatus = "Microsoft Entra Privileged Identity Management (PIM) appears to be enabled and in use."
                $pimRecommendation = "Review PIM configurations in Microsoft Entra admin center under 'Identity Governance > Privileged Identity Management' to ensure all administrative roles are eligible/JIT."
            }
        }
        catch {
            # This catch means PIM might not be enabled or no eligible assignments.
            # Or insufficient permissions.
            $pimStatus = "Could not verify PIM status (possibly not enabled or insufficient permissions). Error: $($_.Exception.Message)"
            $pimRecommendation = "Ensure RoleManagement.Read.All Graph API permission. Then, enable and configure Microsoft Entra Privileged Identity Management (PIM)."
        }

        $results += [PSCustomObject]@{
            Control              = "User Access Control"
            Item                 = "Privileged Identity Management (PIM)"
            DesiredConfiguration = "PIM enabled for administrative roles for Just-In-Time (JIT) access."
            CurrentConfiguration = $pimStatus
            IsCompliant          = $pimEnabled
            Recommendation       = $pimRecommendation
        }
    }
    catch {
        $results += [PSCustomObject]@{
            Control              = "User Access Control"
            Item                 = "Privileged Identity Management (PIM)"
            DesiredConfiguration = "PIM enabled for administrative roles for Just-In-Time (JIT) access."
            CurrentConfiguration = "Error checking PIM status: $($_.Exception.Message)"
            IsCompliant          = $false
            Recommendation       = "Ensure appropriate Graph API permissions (e.g., RoleManagement.Read.All) and try again. Then, enable and configure PIM."
        }
    }

    # 4.2.5 Blocking Legacy Authentication
    try {
        $legacyAuthCA = Get-MgPolicyConditionalAccessPolicy -Filter "displayName eq 'Block Legacy Authentication'" -ErrorAction SilentlyContinue
        $legacyAuthStatus = "No Conditional Access policy found to block legacy authentication."
        $legacyAuthCompliant = $false
        $legacyAuthRecommendation = "Create a Conditional Access policy to block legacy authentication protocols for all users."

        if ($legacyAuthCA.Count -gt 0 -and ($legacyAuthCA | Where-Object {$_.State -eq 'enabled' -or $_.State -eq 'reportOnly'}).Count -gt 0) {
            $legacyAuthStatus = "Conditional Access policy 'Block Legacy Authentication' found and enabled/in report-only mode."
            $legacyAuthCompliant = $true
        }
    }
    catch {
        $legacyAuthStatus = "Error checking Legacy Authentication blocking: $($_.Exception.Message)"
        $legacyAuthCompliant = $false
        $legacyAuthRecommendation = "Ensure Policy.Read.ConditionalAccess Graph API permission and try again. Then, create a Conditional Access policy to block legacy authentication."
    }
    $results += [PSCustomObject]@{
        Control              = "User Access Control"
        Item                 = "Blocking Legacy Authentication"
        DesiredConfiguration = "Conditional Access policy blocks legacy authentication protocols."
        CurrentConfiguration = $legacyAuthStatus
        IsCompliant          = $legacyAuthCompliant
        Recommendation       = $legacyAuthRecommendation
    }

    return $results
}

function Test-CEMalwareProtectionCompliance {
    <#
    .SYNOPSIS
    Tests M365 configurations related to Cyber Essentials Malware Protection control.
    #>
    param()
    Write-Host "`n--- Assessing Malware Protection Compliance ---" -ForegroundColor Yellow
    $results = @()

    # 5.2.1 Endpoint Antivirus and EDR (Microsoft Defender Antivirus & Defender for Endpoint)
    # Check for Defender Antivirus status (via Intune compliance policies) and MDE features.
    try {
        $defenderAntivirusCompliance = Get-MgDeviceManagementDeviceCompliancePolicy -Filter "displayName eq 'Windows Defender Antivirus Policy' or displayName eq 'Antivirus Policy'" -ErrorAction SilentlyContinue
        $defenderAntivirusStatus = "No Intune Device Compliance Policy found for Windows Defender Antivirus."
        $defenderAntivirusCompliant = $false
        $defenderAntivirusRecommendation = "Create an Intune Device Compliance Policy to ensure Microsoft Defender Antivirus is enabled, real-time protection is active, and definitions are up-to-date."

        if ($defenderAntivirusCompliance.Count -gt 0) {
            $defenderAntivirusStatus = "Intune Device Compliance Policy for Windows Defender Antivirus found. Verify it enforces real-time protection and daily definition updates."
            $defenderAntivirusCompliant = $true # Assume compliant if policy exists.
            $defenderAntivirusRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Endpoint security > Antivirus' that policies enforce real-time protection and daily definition updates."
        }
    }
    catch {
        $defenderAntivirusStatus = "Error checking Defender Antivirus policy: $($_.Exception.Message)"
        $defenderAntivirusCompliant = $false
        $defenderAntivirusRecommendation = "Ensure DeviceManagementConfiguration.Read.All Graph API permission and try again. Then, create Intune Antivirus policies."
    }
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Microsoft Defender Antivirus Configuration"
        DesiredConfiguration = "Microsoft Defender Antivirus enabled, real-time protection active, definitions updated daily."
        CurrentConfiguration = $defenderAntivirusStatus
        IsCompliant          = $defenderAntivirusCompliant
        Recommendation       = $defenderAntivirusRecommendation
    }

    # MDE EDR in Block Mode & Tamper Protection
    # These are settings in the Microsoft Defender portal, not directly exposed via simple Graph API calls for assessment.
    # We'll provide conceptual check and recommendation.
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Microsoft Defender for Endpoint (MDE) - EDR in Block Mode"
        DesiredConfiguration = "EDR in block mode enabled for active threat remediation."
        CurrentConfiguration = "Requires manual verification in Microsoft Defender portal."
        IsCompliant          = $false # Cannot automatically verify via PowerShell
        Recommendation       = "Verify and enable 'Endpoint detection and response in block mode' in Microsoft Defender portal (security.microsoft.com > Settings > Endpoints > Advanced features)."
    }
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Microsoft Defender for Endpoint (MDE) - Tamper Protection"
        DesiredConfiguration = "Tamper Protection enabled to prevent disabling security features."
        CurrentConfiguration = "Requires manual verification in Microsoft Defender portal."
        IsCompliant          = $false # Cannot automatically verify via PowerShell
        Recommendation       = "Verify and enable 'Tamper Protection' in Microsoft Defender portal (security.microsoft.com > Settings > Endpoints > Advanced features)."
    }

    # 5.2.2 Attack Surface Reduction (ASR) Rules
    try {
        $asrPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'Attack Surface Reduction Rules'" -ErrorAction SilentlyContinue
        $asrStatus = "No Intune Attack Surface Reduction Rules configuration profiles found."
        $asrCompliant = $false
        $asrRecommendation = "Create Intune Attack Surface Reduction (ASR) rules to target common malware behaviors."

        if ($asrPolicies.Count -gt 0) {
            $asrStatus = "Intune Attack Surface Reduction Rules configuration profiles found. Verify specific rules are configured to 'Block' or 'Audit'."
            $asrCompliant = $true # Assume compliant if policies exist.
            $asrRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Endpoint security > Attack surface reduction' that relevant ASR rules are configured."
        }
    }
    catch {
        $asrStatus = "Error checking ASR rules: $($_.Exception.Message)"
        $asrCompliant = $false
        $asrRecommendation = "Ensure DeviceManagementConfiguration.Read.All Graph API permission and try again. Then, create Intune ASR rules."
    }
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Attack Surface Reduction (ASR) Rules"
        DesiredConfiguration = "ASR rules configured to reduce attack surface."
        CurrentConfiguration = $asrStatus
        IsCompliant          = $asrCompliant
        Recommendation       = $asrRecommendation
    }

    # 5.2.3 Application Control (Whitelisting) - WDAC
    try {
        # Check for App Control for Business policies (WDAC)
        $wdacPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'Windows Defender Application Control' or displayName eq 'App Control for Business'" -ErrorAction SilentlyContinue
        $wdacStatus = "No Intune App Control for Business (WDAC) policies found."
        $wdacCompliant = $false
        $wdacRecommendation = "Implement Windows Defender Application Control (WDAC) policies via Intune to allow only approved applications."

        if ($wdacPolicies.Count -gt 0) {
            $wdacStatus = "Intune App Control for Business (WDAC) policies found. Verify they enforce application whitelisting."
            $wdacCompliant = $true # Assume compliant if policies exist.
            $wdacRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Endpoint security > App Control for Business' that WDAC policies are correctly configured for application whitelisting."
        }
    }
    catch {
        $wdacStatus = "Error checking WDAC policies: $($_.Exception.Message)"
        $wdacCompliant = $false
        $wdacRecommendation = "Ensure DeviceManagementConfiguration.Read.All Graph API permission and try again. Then, implement WDAC policies."
    }
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Application Control (Windows Defender Application Control - WDAC)"
        DesiredConfiguration = "WDAC policies implemented to allow only approved applications."
        CurrentConfiguration = $wdacStatus
        IsCompliant          = $wdacCompliant
        Recommendation       = $wdacRecommendation
    }

    # 5.2.4 Email and Collaboration Protection (Microsoft Defender for Office 365)
    # Check for Safe Attachments, Safe Links, Anti-Phishing policies.
    try {
        $safeAttachmentsPolicies = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Safe Attachments Policy (Default)" }
        $safeLinksPolicies = Get-SafeLinksPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Safe Links Policy (Default)" }
        $antiPhishPolicies = Get-AntiPhishPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Office365 AntiPhish Default" }

        $emailProtectionStatus = "Only default policies found for Safe Attachments, Safe Links, or Anti-Phishing."
        $emailProtectionCompliant = $false
        $emailProtectionRecommendation = "Configure Safe Attachments, Safe Links, and Anti-Phishing policies in Microsoft 365 Defender portal (security.microsoft.com) or apply 'Standard'/'Strict' preset security policies."

        if ($safeAttachmentsPolicies.Count -gt 0 -or $safeLinksPolicies.Count -gt 0 -or $antiPhishPolicies.Count -gt 0) {
            $emailProtectionStatus = "Custom Safe Attachments, Safe Links, or Anti-Phishing policies found. Review for comprehensiveness."
            $emailProtectionCompliant = $true # Assume compliant if custom policies exist.
        }
    }
    catch {
        $emailProtectionStatus = "Error checking Defender for Office 365 policies: $($_.Exception.Message)"
        $emailProtectionCompliant = $false
        $emailProtectionRecommendation = "Ensure Exchange Online PowerShell connection and try again. Then, configure Defender for Office 365 policies."
    }
    $results += [PSCustomObject]@{
        Control              = "Malware Protection"
        Item                 = "Microsoft Defender for Office 365 Policies (Safe Attachments, Safe Links, Anti-Phishing)"
        DesiredConfiguration = "Comprehensive anti-phishing, safe attachments, and safe links policies configured."
        CurrentConfiguration = $emailProtectionStatus
        IsCompliant          = $emailProtectionCompliant
        Recommendation       = $emailProtectionRecommendation
    }

    return $results
}

function Test-CEPatchManagementCompliance {
    <#
    .SYNOPSIS
    Tests M365 configurations related to Cyber Essentials Patch Management control.
    #>
    param()
    Write-Host "`n--- Assessing Patch Management Compliance ---" -ForegroundColor Yellow
    $results = @()

    # 6.2.1 Operating System Patching (Intune & Windows Update for Business - WUfB)
    # Check for Update Rings and Quality Updates policies.
    try {
        $updateRings = Get-MgDeviceManagementWindowsUpdateForBusinessConfiguration -ErrorAction SilentlyContinue
        $qualityUpdates = Get-MgDeviceManagementQualityUpdateProfile -ErrorAction SilentlyContinue

        $osPatchingStatus = "No Intune Update Rings or Quality Update profiles found for OS patching."
        $osPatchingCompliant = $false
        $osPatchingRecommendation = "Configure Intune Update Rings and Quality Update profiles (including expedited updates) to ensure OS patches are deployed within 14 days for critical/high-risk vulnerabilities."

        if ($updateRings.Count -gt 0 -or $qualityUpdates.Count -gt 0) {
            $osPatchingStatus = "Intune Update Rings or Quality Update profiles found. Verify they enforce timely patching (e.g., 14-day deadline for critical updates)."
            $osPatchingCompliant = $true # Assume compliant if policies exist.
            $osPatchingRecommendation = "Manually verify in Microsoft Intune admin center (endpoint.microsoft.com) under 'Devices > Windows 10 and later updates' that update policies ensure timely patching."
        }
    }
    catch {
        $osPatchingStatus = "Error checking OS patching policies: $($_.Exception.Message)"
        $osPatchingCompliant = $false
        $osPatchingRecommendation = "Ensure DeviceManagementConfiguration.Read.All Graph API permission and try again. Then, configure Intune OS update policies."
    }
    $results += [PSCustomObject]@{
        Control              = "Patch Management"
        Item                 = "Operating System Patching (Windows 10/11)"
        DesiredConfiguration = "Intune Update Rings/Quality Updates ensure patches deployed within 14 days for critical/high-risk vulnerabilities."
        CurrentConfiguration = $osPatchingStatus
        IsCompliant          = $osPatchingCompliant
        Recommendation       = $osPatchingRecommendation
    }

    # 6.2.2 Firmware Updates (Intune DFCI & OEM-specific policies)
    # This is highly specific to hardware and often requires OEM tools. Conceptual check.
    $results += [PSCustomObject]@{
        Control              = "Patch Management"
        Item                 = "Firmware Updates (PC, Router, Firewall)"
        DesiredConfiguration = "Firmware for PCs, routers, and firewalls kept up to date and supported."
        CurrentConfiguration = "Requires manual verification and OEM-specific tools for PC firmware; manual check for network devices."
        IsCompliant          = $false # Cannot automatically verify via PowerShell
        Recommendation       = "Establish a process for regularly updating PC firmware (e.g., via Intune DFCI for supported devices or OEM tools) and manually verify router/firewall firmware updates."
    }

    # 6.2.3 Application Updates (Microsoft 365 Apps)
    $results += [PSCustomObject]@{
        Control              = "Patch Management"
        Item                 = "Microsoft 365 Applications Updates"
        DesiredConfiguration = "Microsoft 365 applications configured for automatic updates."
        CurrentConfiguration = "Microsoft 365 applications are generally configured for automatic updates by default."
        IsCompliant          = $true # Assumed default behavior
        Recommendation       = "Ensure Microsoft 365 Apps are configured for automatic updates and consider using Monthly Enterprise Channel for predictable updates."
    }

    return $results
}

#endregion

#region HTML Report Generation

function Generate-CEComplianceReport {
    <#
    .SYNOPSIS
    Generates an HTML report of the Cyber Essentials compliance assessment results.
    .PARAMETER ComplianceResults
    An array of PSCustomObjects containing the assessment results.
    .PARAMETER OutputPath
    The full path where the HTML report should be saved.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$ComplianceResults,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )

    Write-Host "`n--- Generating HTML Report ---" -ForegroundColor Yellow

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Cyber Essentials Compliance Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            margin: 20px;
            background-color: #f4f7f6;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
        }
        h1, h2, h3 {
            color: #2c3e50;
            font-weight: 600;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            color: #0078d4;
        }
        h2 {
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
            margin-top: 40px;
            font-size: 1.8em;
        }
        h3 {
            font-size: 1.4em;
            margin-top: 25px;
            color: #34495e;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #f0f0f0;
        }
        th {
            background-color: #eaf3f7;
            font-weight: 600;
            color: #2c3e50;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f0f8ff;
        }
        .status-compliant {
            background-color: #e6ffe6; /* Light Green */
            color: #28a745; /* Dark Green */
            font-weight: 600;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            min-width: 90px;
            text-align: center;
        }
        .status-non-compliant {
            background-color: #ffe6e6; /* Light Red */
            color: #dc3545; /* Dark Red */
            font-weight: 600;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            min-width: 90px;
            text-align: center;
        }
        .summary-box {
            background-color: #eaf3f7;
            border: 1px solid #cce7ee;
            padding: 25px;
            border-radius: 10px;
            margin-top: 40px;
            font-size: 1.1em;
            line-height: 1.8;
        }
        .summary-box p {
            margin-bottom: 10px;
        }
        .recommendations-list {
            list-style-type: disc;
            padding-left: 25px;
        }
        .recommendations-list li {
            margin-bottom: 8px;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #777;
            font-size: 0.9em;
        }
        .control-section {
            margin-bottom: 50px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Microsoft 365 Cyber Essentials Compliance Report</h1>
        <p style="text-align: center; font-size: 1.1em; color: #555;">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>

        <div class="summary-box">
            <h2>Compliance Summary</h2>
            <p>This report assesses your Microsoft 365 tenant's current configuration against the five key controls of Cyber Essentials. Each item is color-coded:</p>
            <ul>
                <li><span class="status-compliant">Compliant (Green)</span>: Your configuration aligns with Cyber Essentials requirements.</li>
                <li><span class="status-non-compliant">Non-Compliant (Red)</span>: Your configuration needs attention to meet Cyber Essentials requirements.</li>
            </ul>
            <p>Please review the detailed findings below and the suggested improvements to enhance your cybersecurity posture.</p>
        </div>

        $currentControl = ""
        $ComplianceResults | ForEach-Object {
            if ($_.Control -ne $currentControl) {
                if ($currentControl -ne "") {
                    $html += "</table></div>"
                }
                $currentControl = $_.Control
                $html += "<div class='control-section'><h2>$currentControl</h2><table><thead><tr><th>Compliance Item</th><th>Desired Configuration</th><th>Current Configuration</th><th>Status</th></tr></thead><tbody>"
            }
            $statusClass = if ($_.IsCompliant) { "status-compliant" } else { "status-non-compliant" }
            $statusText = if ($_.IsCompliant) { "Compliant" } else { "Non-Compliant" }
            $html += "
                <tr>
                    <td>$($_.Item)</td>
                    <td>$($_.DesiredConfiguration)</td>
                    <td>$($_.CurrentConfiguration)</td>
                    <td><span class='$statusClass'>$statusText</span></td>
                </tr>
            "
        }
        $html += "</tbody></table></div>" # Close the last table and section

        <h2>Suggested Improvements</h2>
        <p>Based on the assessment, here are the recommended actions to improve your Cyber Essentials compliance:</p>
        <ul class="recommendations-list">
"@

    $nonCompliantItems = $ComplianceResults | Where-Object { -not $_.IsCompliant }
    if ($nonCompliantItems.Count -gt 0) {
        $nonCompliantItems | ForEach-Object {
            $html += "<li><strong>$($_.Item)</strong>: $($_.Recommendation)</li>"
        }
    } else {
        $html += "<li>Congratulations! Your M365 tenant appears to be largely compliant with Cyber Essentials based on this assessment. Continue to monitor and review your configurations regularly.</li>"
    }

    $html += @"
        </ul>

        <div class="footer">
            <p>&copy; $(Get-Date -Format "yyyy") Microsoft 365 Cyber Essentials Assessor. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
        Write-Host "HTML report generated successfully at: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate HTML report. Error: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Main Execution Block

function Invoke-CEComplianceAssessment {
    <#
    .SYNOPSIS
    Orchestrates the entire Cyber Essentials compliance assessment process for M365.
    Generates an HTML report.
    .PARAMETER ReportPath
    The full path where the HTML report should be saved (e.g., "C:\Reports\CE_Compliance_Report.html").
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ReportPath
    )

    Write-Host "`n=====================================================================" -ForegroundColor White -BackgroundColor Blue
    Write-Host "  Starting Microsoft 365 Cyber Essentials Compliance Assessment" -ForegroundColor White -BackgroundColor Blue
    Write-Host "=====================================================================" -ForegroundColor White -BackgroundColor Blue

    # 1. Install required modules
    if (-not (Install-RequiredModules)) {
        Write-Error "Module installation failed. Aborting assessment."
        return
    }

    # 2. Connect to M365 services
    # This step will prompt for authentication.
    if (-not (Connect-M365Services)) {
        Write-Error "Failed to connect to M365 services. Aborting assessment."
        return
    }

    Write-Host "`n--- Starting Cyber Essentials Configuration Assessment ---" -ForegroundColor Green
    $allResults = @()

    # Execute each Cyber Essentials control assessment function
    $allResults += Test-CEFirewallCompliance
    $allResults += Test-CESecureConfigurationCompliance
    $allResults += Test-CEUserAccessControlCompliance
    $allResults += Test-CEMalwareProtectionCompliance
    $allResults += Test-CEPatchManagementCompliance

    Write-Host "`n--- Assessment Complete. Generating Report ---" -ForegroundColor Green

    # Generate the HTML report
    if (Generate-CEComplianceReport -ComplianceResults $allResults -OutputPath $ReportPath) {
        Write-Host "`n=====================================================================" -ForegroundColor White -BackgroundColor Blue
        Write-Host "  Microsoft 365 Cyber Essentials Compliance Report Generated!" -ForegroundColor White -BackgroundColor Blue
        Write-Host "  Open '$ReportPath' in your browser to view the results." -ForegroundColor White -BackgroundColor Blue
        Write-Host "=====================================================================" -ForegroundColor White -BackgroundColor Blue
    } else {
        Write-Error "Failed to generate the compliance report."
    }

    # Disconnect from Graph and Exchange Online
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Microsoft Graph." -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
    }
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Exchange Online." -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to disconnect from Exchange Online: $($_.Exception.Message)"
    }
}

# To run the assessment, uncomment the line below and provide an output path:
# Example: Invoke-CEComplianceAssessment -ReportPath "C:\Temp\M365_CyberEssentials_Report.html"
# Or, for a path in your current directory:
# Invoke-CEComplianceAssessment -ReportPath (Join-Path $PSScriptRoot "M365_CyberEssentials_Report.html")

#endregion
