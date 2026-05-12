<#
.SYNOPSIS
    IT User Toolbox for AD, Microsoft 365, Exchange Online, and password generation.

.REQUIREMENTS
    Install-Module ActiveDirectory
    Install-Module Microsoft.Graph.Users
    Install-Module ExchangeOnlineManagement

    Run PowerShell as admin with appropriate AD / M365 permissions.

.NOTES
    Update $DestructionOU before using termination workflow.
#>

# =========================
# CONFIG
# =========================

$DestructionOU = "OU=Disabled Users,DC=contoso,DC=com"
$LogPath = "$PSScriptRoot\IT-UserToolbox.log"

# =========================
# LOGGING
# =========================

function Write-ToolLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $entry
    Add-Content -Path $LogPath -Value $entry
}

# =========================
# MODULE / CONNECTIONS
# =========================

function Import-ToolModules {
    Write-ToolLog "Loading required modules..."

    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}

function Connect-CloudServices {
    Write-ToolLog "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.AccessAsUser.All" -NoWelcome

    Write-ToolLog "Connecting to Exchange Online..."
    Connect-ExchangeOnline -ShowBanner:$false
}

# =========================
# HELPERS
# =========================

function Confirm-Action {
    param([string]$Prompt)

    $answer = Read-Host "$Prompt Type YES to continue"
    return $answer -eq "YES"
}

function Get-ToolADUser {
    param([string]$Identity)

    try {
        return Get-ADUser -Identity $Identity -Properties DistinguishedName, UserPrincipalName, mail, Enabled
    }
    catch {
        throw "Could not find AD user: $Identity"
    }
}

function Disable-ADAndMove {
    param(
        [string]$Identity,
        [string]$TargetOU = $DestructionOU
    )

    $user = Get-ToolADUser -Identity $Identity

    Write-ToolLog "Disabling AD account: $($user.SamAccountName)"
    Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop

    Write-ToolLog "Moving AD account to: $TargetOU"
    Move-ADObject -Identity $user.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
}

function Disable-EntraAccount {
    param([string]$UserPrincipalName)

    Write-ToolLog "Disabling Entra/M365 sign-in: $UserPrincipalName"
    Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false -ErrorAction Stop

    Write-ToolLog "Revoking Microsoft 365 sessions: $UserPrincipalName"
    Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop | Out-Null
}

# =========================
# OPTION 1: COPY GROUPS
# =========================

function Copy-ADGroupMemberships {
    $sourceIdentity = Read-Host "Source user username/UPN"
    $targetIdentity = Read-Host "Target user username/UPN"

    $source = Get-ToolADUser -Identity $sourceIdentity
    $target = Get-ToolADUser -Identity $targetIdentity

    $groups = Get-ADPrincipalGroupMembership -Identity $source |
        Where-Object { $_.Name -ne "Domain Users" }

    Write-Host "`nGroups to copy:"
    $groups | Select-Object Name | Format-Table

    if (-not (Confirm-Action "Copy these groups from $sourceIdentity to $targetIdentity?")) {
        Write-ToolLog "Group copy cancelled."
        return
    }

    foreach ($group in $groups) {
        try {
            Add-ADGroupMember -Identity $group.DistinguishedName -Members $target.DistinguishedName -ErrorAction Stop
            Write-ToolLog "Added $targetIdentity to $($group.Name)"
        }
        catch {
            Write-ToolLog "Failed adding $targetIdentity to $($group.Name): $($_.Exception.Message)" "ERROR"
        }
    }
}

# =========================
# OPTION 2: TEMP DISABLE
# =========================

function Temporarily-DisableUser {
    $identity = Read-Host "User username/UPN to disable until further notice"
    $user = Get-ToolADUser -Identity $identity
    $upn = $user.UserPrincipalName

    if (-not (Confirm-Action "Disable AD and Entra/M365 account for $identity?")) {
        Write-ToolLog "Temporary disable cancelled."
        return
    }

    Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
    Write-ToolLog "Disabled AD account: $identity"

    if ($upn) {
        Disable-EntraAccount -UserPrincipalName $upn
    }
    else {
        Write-ToolLog "No UPN found for $identity. Skipped Entra disable." "WARN"
    }
}

# =========================
# OPTION 3: TERMINATE EMPLOYEE
# =========================

function Terminate-Employee {
    $identity = Read-Host "Terminated employee username/UPN"
    $managerEmail = Read-Host "Manager email address for forwarding"

    $user = Get-ToolADUser -Identity $identity
    $upn = $user.UserPrincipalName

    Write-Host "`nTermination actions:"
    Write-Host "- Disable AD"
    Write-Host "- Move to destruction OU: $DestructionOU"
    Write-Host "- Disable Entra/M365 sign-in"
    Write-Host "- Revoke Microsoft 365 sessions"
    Write-Host "- Forward Exchange mail to manager"
    Write-Host "- Hide mailbox from company directory"
    Write-Host "- Convert mailbox to shared mailbox"
    Write-Host "- Remove Microsoft 365 app access by blocking sign-in/revoking sessions"

    if (-not (Confirm-Action "Terminate $identity?")) {
        Write-ToolLog "Termination cancelled."
        return
    }

    Disable-ADAndMove -Identity $identity

    if ($upn) {
        Disable-EntraAccount -UserPrincipalName $upn

        Write-ToolLog "Configuring Exchange mailbox forwarding to $managerEmail"
        Set-Mailbox -Identity $upn `
            -ForwardingSmtpAddress $managerEmail `
            -DeliverToMailboxAndForward $true `
            -ErrorAction Stop

        Write-ToolLog "Hiding mailbox from address lists"
        Set-Mailbox -Identity $upn `
            -HiddenFromAddressListsEnabled $true `
            -ErrorAction Stop

        Write-ToolLog "Converting mailbox to shared mailbox"
        Set-Mailbox -Identity $upn `
            -Type Shared `
            -ErrorAction Stop
    }
    else {
        Write-ToolLog "No UPN found. Skipped cloud and Exchange actions." "WARN"
    }

    Write-ToolLog "Termination workflow complete for $identity"
}

# =========================
# OPTION 4: PASSWORD GENERATOR
# =========================

function New-SecurePassword {
    param(
        [int]$Length = 16,
        [int]$Count = 1
    )

    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower = "abcdefghijkmnopqrstuvwxyz"
    $numbers = "23456789"
    $symbols = "!@#$%^&*-_=+?"
    $all = ($upper + $lower + $numbers + $symbols).ToCharArray()

    for ($i = 1; $i -le $Count; $i++) {
        $required = @(
            $upper[(Get-Random -Maximum $upper.Length)]
            $lower[(Get-Random -Maximum $lower.Length)]
            $numbers[(Get-Random -Maximum $numbers.Length)]
            $symbols[(Get-Random -Maximum $symbols.Length)]
        )

        $remaining = for ($j = 1; $j -le ($Length - 4); $j++) {
            $all[(Get-Random -Maximum $all.Length)]
        }

        -join (($required + $remaining) | Sort-Object { Get-Random })
    }
}

function Start-PasswordGenerator {
    $length = Read-Host "Password length, default 16"
    $count = Read-Host "How many passwords, default 1"

    if ([string]::IsNullOrWhiteSpace($length)) { $length = 16 }
    if ([string]::IsNullOrWhiteSpace($count)) { $count = 1 }

    New-SecurePassword -Length ([int]$length) -Count ([int]$count)
}

# =========================
# MENU
# =========================

function Show-Menu {
    Clear-Host
    Write-Host "==================================="
    Write-Host "        IT USER TOOLBOX"
    Write-Host "==================================="
    Write-Host "1. Copy AD group memberships"
    Write-Host "2. Temporarily disable AD/Azure account"
    Write-Host "3. Terminate employee"
    Write-Host "4. Password generator"
    Write-Host "5. Connect cloud services"
    Write-Host "Q. Quit"
    Write-Host "==================================="
}

function Start-Toolbox {
    Import-ToolModules

    do {
        Show-Menu
        $choice = Read-Host "Choose an option"

        switch ($choice.ToUpper()) {
            "1" { Copy-ADGroupMemberships; Pause }
            "2" { Connect-CloudServices; Temporarily-DisableUser; Pause }
            "3" { Connect-CloudServices; Terminate-Employee; Pause }
            "4" { Start-PasswordGenerator; Pause }
            "5" { Connect-CloudServices; Pause }
            "Q" { Write-ToolLog "Exiting toolbox." }
            default { Write-Host "Invalid choice."; Pause }
        }
    }
    while ($choice.ToUpper() -ne "Q")
}

Start-Toolbox