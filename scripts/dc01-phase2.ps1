#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Phase 2: Create OUs, users, and groups in Active Directory.
    Run this AFTER the server has rebooted as a Domain Controller.
    Log in as LAB\Administrator.

.DESCRIPTION
    - Creates organizational units
    - Creates test users (admin + standard)
    - Creates security groups
    - Sets up Group Policy for auditing
    - Configures Windows Event Logging for SOC integration

.NOTES
    Run on DC01 after domain promotion reboot.
#>

Write-Host "`n=== SOC Lab - AD Population (Phase 2) ===" -ForegroundColor Cyan

# Verify we are a domain controller
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "ERROR: AD module not available. Is this a domain controller?" -ForegroundColor Red
    Write-Host "Run dc01-setup.ps1 first and wait for reboot." -ForegroundColor Yellow
    exit 1
}

$domain = (Get-ADDomain).DistinguishedName
Write-Host "Domain: $((Get-ADDomain).DNSRoot)"
Write-Host "DC: $env:COMPUTERNAME`n"

# ── Step 1: Create OUs ──────────────────────────────────────────────
Write-Host "[1/5] Creating Organizational Units..." -ForegroundColor Yellow

$ous = @(
    @{ Name = "SOC Lab Users";     Path = $domain },
    @{ Name = "SOC Lab Admins";    Path = $domain },
    @{ Name = "SOC Lab Servers";   Path = $domain },
    @{ Name = "SOC Lab Workstations"; Path = $domain },
    @{ Name = "Service Accounts";  Path = $domain }
)

foreach ($ou in $ous) {
    $ouDN = "OU=$($ou.Name),$($ou.Path)"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
        Write-Host "  Created OU: $($ou.Name)" -ForegroundColor Green
    } else {
        Write-Host "  OU exists: $($ou.Name)" -ForegroundColor DarkGray
    }
}

# ── Step 2: Create Security Groups ──────────────────────────────────
Write-Host "`n[2/5] Creating Security Groups..." -ForegroundColor Yellow

$groups = @(
    @{ Name = "SOC Analysts";     Path = "OU=SOC Lab Users,$domain";  Desc = "SOC analyst team" },
    @{ Name = "SOC Admins";       Path = "OU=SOC Lab Admins,$domain"; Desc = "SOC administrators" },
    @{ Name = "IT Operations";    Path = "OU=SOC Lab Users,$domain";  Desc = "IT Ops team" },
    @{ Name = "Developers";       Path = "OU=SOC Lab Users,$domain";  Desc = "Development team" }
)

foreach ($grp in $groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($grp.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $grp.Name -GroupScope Global -GroupCategory Security `
            -Path $grp.Path -Description $grp.Desc
        Write-Host "  Created group: $($grp.Name)" -ForegroundColor Green
    } else {
        Write-Host "  Group exists: $($grp.Name)" -ForegroundColor DarkGray
    }
}

# ── Step 3: Create Users ────────────────────────────────────────────
Write-Host "`n[3/5] Creating Users..." -ForegroundColor Yellow

$defaultPass = ConvertTo-SecureString "SOClab2024!" -AsPlainText -Force

$users = @(
    # Admin accounts
    @{
        Sam = "soc.admin";   First = "SOC";     Last = "Admin"
        UPN = "soc.admin@lab.local"; Title = "SOC Administrator"
        Path = "OU=SOC Lab Admins,$domain"; Groups = @("SOC Admins", "Domain Admins")
    },
    @{
        Sam = "it.admin";    First = "IT";      Last = "Admin"
        UPN = "it.admin@lab.local"; Title = "IT Administrator"
        Path = "OU=SOC Lab Admins,$domain"; Groups = @("IT Operations", "Domain Admins")
    },
    # Analyst accounts
    @{
        Sam = "jsmith";      First = "John";    Last = "Smith"
        UPN = "jsmith@lab.local"; Title = "SOC Analyst"
        Path = "OU=SOC Lab Users,$domain"; Groups = @("SOC Analysts")
    },
    @{
        Sam = "agarcia";     First = "Ana";     Last = "Garcia"
        UPN = "agarcia@lab.local"; Title = "Senior SOC Analyst"
        Path = "OU=SOC Lab Users,$domain"; Groups = @("SOC Analysts")
    },
    @{
        Sam = "mchen";       First = "Ming";    Last = "Chen"
        UPN = "mchen@lab.local"; Title = "Threat Hunter"
        Path = "OU=SOC Lab Users,$domain"; Groups = @("SOC Analysts", "IT Operations")
    },
    # Standard users (attack simulation targets)
    @{
        Sam = "bwilson";     First = "Bob";     Last = "Wilson"
        UPN = "bwilson@lab.local"; Title = "Developer"
        Path = "OU=SOC Lab Users,$domain"; Groups = @("Developers")
    },
    @{
        Sam = "ljones";      First = "Lisa";    Last = "Jones"
        UPN = "ljones@lab.local"; Title = "HR Manager"
        Path = "OU=SOC Lab Users,$domain"; Groups = @()
    },
    # Service account
    @{
        Sam = "svc.soc";     First = "SOC";     Last = "Service"
        UPN = "svc.soc@lab.local"; Title = "SOC Service Account"
        Path = "OU=Service Accounts,$domain"; Groups = @()
    }
)

foreach ($u in $users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -SamAccountName $u.Sam `
            -UserPrincipalName $u.UPN `
            -Name "$($u.First) $($u.Last)" `
            -GivenName $u.First `
            -Surname $u.Last `
            -Title $u.Title `
            -Path $u.Path `
            -AccountPassword $defaultPass `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false

        foreach ($grp in $u.Groups) {
            Add-ADGroupMember -Identity $grp -Members $u.Sam -ErrorAction SilentlyContinue
        }
        Write-Host "  Created user: $($u.Sam) ($($u.Title))" -ForegroundColor Green
    } else {
        Write-Host "  User exists: $($u.Sam)" -ForegroundColor DarkGray
    }
}

# ── Step 4: Enable Advanced Audit Policy ─────────────────────────────
Write-Host "`n[4/5] Configuring Advanced Audit Policies..." -ForegroundColor Yellow

# Enable key audit categories for SOC visibility
$auditPolicies = @(
    @{ Sub = "Logon";                 Success = "enable"; Failure = "enable" },
    @{ Sub = "Logoff";                Success = "enable"; Failure = "disable" },
    @{ Sub = "Account Lockout";       Success = "enable"; Failure = "enable" },
    @{ Sub = "Special Logon";         Success = "enable"; Failure = "enable" },
    @{ Sub = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Sub = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Sub = "Computer Account Management"; Success = "enable"; Failure = "enable" },
    @{ Sub = "Process Creation";      Success = "enable"; Failure = "enable" },
    @{ Sub = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" },
    @{ Sub = "Security State Change"; Success = "enable"; Failure = "enable" },
    @{ Sub = "Other Object Access Events"; Success = "enable"; Failure = "enable" }
)

foreach ($pol in $auditPolicies) {
    auditpol /set /subcategory:"$($pol.Sub)" /success:$($pol.Success) /failure:$($pol.Failure) 2>$null | Out-Null
}
Write-Host "  Audit policies configured" -ForegroundColor Green

# Enable command-line in process creation events (Event 4688)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Host "  Command-line logging in 4688 events enabled" -ForegroundColor Green

# Increase Security Event Log size
wevtutil sl Security /ms:209715200  # 200 MB
Write-Host "  Security log max size set to 200 MB" -ForegroundColor Green

# ── Step 5: Add DNS forwarder for lab resolution ─────────────────────
Write-Host "`n[5/5] Configuring DNS..." -ForegroundColor Yellow

# Add forwarder to Google DNS for internet resolution
Add-DnsServerForwarder -IPAddress "8.8.8.8" -ErrorAction SilentlyContinue
Write-Host "  DNS forwarder added (8.8.8.8)" -ForegroundColor Green

# ── Summary ──────────────────────────────────────────────────────────
Write-Host "`n=== Phase 2 Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain:     lab.local" -ForegroundColor White
Write-Host "DC:         DC01.lab.local (192.168.56.10)" -ForegroundColor White
Write-Host ""
Write-Host "Admin accounts (password: SOClab2024!):" -ForegroundColor Yellow
Write-Host "  LAB\soc.admin   - SOC Administrator (Domain Admin)"
Write-Host "  LAB\it.admin    - IT Administrator (Domain Admin)"
Write-Host ""
Write-Host "Analyst accounts:" -ForegroundColor Yellow
Write-Host "  LAB\jsmith      - SOC Analyst"
Write-Host "  LAB\agarcia     - Senior SOC Analyst"
Write-Host "  LAB\mchen       - Threat Hunter"
Write-Host ""
Write-Host "Standard accounts (attack sim targets):" -ForegroundColor Yellow
Write-Host "  LAB\bwilson     - Developer"
Write-Host "  LAB\ljones      - HR Manager"
Write-Host ""
Write-Host "Service account:" -ForegroundColor Yellow
Write-Host "  LAB\svc.soc     - SOC Service Account"
Write-Host ""
Write-Host "Next step: Copy and run dc01-soc-forwarder.ps1 to start sending logs to the SOC" -ForegroundColor Cyan
