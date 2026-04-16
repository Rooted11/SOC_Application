#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Run AFTER DC promotion reboot. Creates users, groups, audit policies,
    and starts the SOC log forwarder.
    Log in as EXAMPLE\Administrator (same password you set during install).
#>

Write-Host "`n=== SOC Lab - DC01 Post-Promotion Setup ===" -ForegroundColor Cyan

# ── Verify AD ─────────────────────────────────────────────────────────
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $dom = Get-ADDomain
    Write-Host "Domain: $($dom.DNSRoot) - OK" -ForegroundColor Green
} catch {
    Write-Host "ERROR: AD not ready. Wait for reboot to complete fully." -ForegroundColor Red
    exit 1
}

$dn = $dom.DistinguishedName

# ── Create OUs ────────────────────────────────────────────────────────
Write-Host "`n[1/5] Creating OUs..." -ForegroundColor Yellow
@("SOC Lab Users", "SOC Lab Admins", "SOC Lab Servers", "Service Accounts") | ForEach-Object {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$_'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $_ -Path $dn -ProtectedFromAccidentalDeletion $false
        Write-Host "  + $_" -ForegroundColor Green
    }
}

# ── Create Groups ─────────────────────────────────────────────────────
Write-Host "`n[2/5] Creating groups..." -ForegroundColor Yellow
@("SOC Analysts", "SOC Admins", "IT Operations", "Developers") | ForEach-Object {
    if (-not (Get-ADGroup -Filter "Name -eq '$_'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $_ -GroupScope Global -GroupCategory Security -Path "OU=SOC Lab Users,$dn"
        Write-Host "  + $_" -ForegroundColor Green
    }
}

# ── Create Users ──────────────────────────────────────────────────────
Write-Host "`n[3/5] Creating users..." -ForegroundColor Yellow
$pw = ConvertTo-SecureString "<LAB_PASSWORD>" -AsPlainText -Force

$users = @(
    @{ Sam="soc-admin"; Name="SOC Admin";      OU="SOC Lab Admins"; Groups=@("SOC Admins","Domain Admins") },
    @{ Sam="it-admin";  Name="IT Admin";       OU="SOC Lab Admins"; Groups=@("IT Operations","Domain Admins") },
    @{ Sam="jsmith";    Name="John Smith";     OU="SOC Lab Users";  Groups=@("SOC Analysts") },
    @{ Sam="agarcia";   Name="Ana Garcia";     OU="SOC Lab Users";  Groups=@("SOC Analysts") },
    @{ Sam="mchen";     Name="Ming Chen";      OU="SOC Lab Users";  Groups=@("SOC Analysts","IT Operations") },
    @{ Sam="bwilson";   Name="Bob Wilson";     OU="SOC Lab Users";  Groups=@("Developers") },
    @{ Sam="ljones";    Name="Lisa Jones";     OU="SOC Lab Users";  Groups=@() },
    @{ Sam="svc.soc";   Name="SOC Service";    OU="Service Accounts"; Groups=@() }
)

foreach ($u in $users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        New-ADUser -SamAccountName $u.Sam -Name $u.Name `
            -UserPrincipalName "$($u.Sam)@example.local" `
            -Path "OU=$($u.OU),$dn" `
            -AccountPassword $pw -Enabled $true `
            -PasswordNeverExpires $true -ChangePasswordAtLogon $false
        foreach ($g in $u.Groups) {
            Add-ADGroupMember -Identity $g -Members $u.Sam -ErrorAction SilentlyContinue
        }
        Write-Host "  + $($u.Sam) ($($u.Name))" -ForegroundColor Green
    }
}

# ── Audit Policies ────────────────────────────────────────────────────
Write-Host "`n[4/5] Configuring audit policies..." -ForegroundColor Yellow
$audits = @(
    "Logon", "Logoff", "Account Lockout", "Special Logon",
    "User Account Management", "Security Group Management",
    "Process Creation", "Sensitive Privilege Use", "Security State Change"
)
foreach ($a in $audits) {
    auditpol /set /subcategory:"$a" /success:enable /failure:enable 2>$null | Out-Null
}
# Enable command line in process creation events
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
wevtutil sl Security /ms:209715200
Write-Host "  Audit policies + 200MB security log configured" -ForegroundColor Green

# ── DNS Forwarder ─────────────────────────────────────────────────────
Write-Host "`n[5/5] Configuring DNS forwarder..." -ForegroundColor Yellow
Add-DnsServerForwarder -IPAddress "8.8.8.8" -ErrorAction SilentlyContinue
Write-Host "  DNS forwarder: 8.8.8.8" -ForegroundColor Green

# ── Verify SOC connectivity ───────────────────────────────────────────
Write-Host "`n=== Connectivity Check ===" -ForegroundColor Cyan
$socReach = Test-Connection -ComputerName <SOC_UBUNTU_IP> -Count 2 -Quiet -ErrorAction SilentlyContinue
if ($socReach) {
    Write-Host "  SOC (<SOC_UBUNTU_IP>): REACHABLE" -ForegroundColor Green
    # Test the API
    try {
        $r = Invoke-RestMethod -Uri "http://<SOC_UBUNTU_IP>:8000/api/system/health" -TimeoutSec 5
        Write-Host "  SOC API: ONLINE (Redis: $($r.redis))" -ForegroundColor Green
    } catch {
        Write-Host "  SOC API: NOT RESPONDING (may need to check backend)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  SOC (<SOC_UBUNTU_IP>): UNREACHABLE - check network adapter" -ForegroundColor Red
}

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain:       example.local"
Write-Host "  DC:           DC01.example.local (<DC01_IP>)"
Write-Host "  Admin users:  EXAMPLE\soc-admin, EXAMPLE\it-admin"
Write-Host "  Analysts:     EXAMPLE\jsmith, EXAMPLE\agarcia, EXAMPLE\mchen"
Write-Host "  Test users:   EXAMPLE\bwilson, EXAMPLE\ljones"
Write-Host "  Password:     <LAB_PASSWORD>"
Write-Host ""
Write-Host "  Next: Run the SOC forwarder to start sending events:" -ForegroundColor Yellow
Write-Host '  .\dc01-soc-forwarder.ps1' -ForegroundColor White
Write-Host ""
Write-Host "  Or generate test events:" -ForegroundColor Yellow
Write-Host '  .\dc01-generate-events.ps1' -ForegroundColor White
Write-Host ""
