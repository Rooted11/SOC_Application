#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promote DC03 - third writable Domain Controller for example.local in Branch-Site.
    Run on a freshly installed Windows Server 2022 VM.

.DESCRIPTION
    - Sets static IP <DC03_IP>/24 (HQ subnet, but logically placed in Branch-Site
      so site link replication can be exercised in the lab without a real WAN)
    - Points DNS at DC01 / DC02 for join
    - Renames computer to DC03
    - Installs AD DS + DNS + OpenSSH Server
    - Promotes as additional writable DC in Branch-Site
    - Server reboots automatically after promotion

.NOTES
    Pre-reqs:
      - DC01 + DC02 healthy and reachable
      - dc01-advanced-ad.ps1 has run (Branch-Site exists)
      - Domain Admin credentials available (EXAMPLE\soc-admin)

    For a true RODC variant, change -NoGlobalCatalog or use Install-ADDSDomainController
    -ReadOnlyReplica flag (commented at the bottom of this script).
#>

Write-Host "`n=== SOC Lab - DC03 Promotion (Branch-Site) ===" -ForegroundColor Cyan

$myIP    = "<DC03_IP>"
$dc01IP  = "<DC01_IP>"
$dc02IP  = "<DC02_IP>"
$domain  = "example.local"
$site    = "Branch-Site"

# ── Step 1: Static IP ──────────────────────────────────────────────────
Write-Host "[1/6] Configuring static IP $myIP..." -ForegroundColor Yellow

$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback'
} | Select-Object -First 1
if (-not $adapter) { Write-Host "ERROR: no adapter found" -ForegroundColor Red; exit 1 }

Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute     -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress $myIP -PrefixLength 24 `
    -DefaultGateway "<VM_HOST_IP>" -ErrorAction SilentlyContinue | Out-Null

Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses @($dc01IP, $dc02IP)
Write-Host "  $myIP/24, DNS -> $dc01IP, $dc02IP" -ForegroundColor Green

# ── Step 2: Reach existing DCs ─────────────────────────────────────────
Write-Host "`n[2/6] Verifying connectivity to existing DCs..." -ForegroundColor Yellow
foreach ($ip in @($dc01IP, $dc02IP)) {
    if (Test-Connection -ComputerName $ip -Count 2 -Quiet) {
        Write-Host "  $ip reachable" -ForegroundColor Green
    } else {
        Write-Host "  $ip UNREACHABLE - aborting" -ForegroundColor Red; exit 1
    }
}

# ── Step 3: Rename ─────────────────────────────────────────────────────
Write-Host "`n[3/6] Renaming to DC03..." -ForegroundColor Yellow
if ($env:COMPUTERNAME -ne "DC03") {
    Rename-Computer -NewName "DC03" -Force
    Write-Host "  Renamed (effective at next reboot)" -ForegroundColor Green
}

# ── Step 4: Install roles + OpenSSH ────────────────────────────────────
Write-Host "`n[4/6] Installing AD DS + DNS + OpenSSH Server..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-DNS-Server `
    -IncludeManagementTools | Out-Null
Write-Host "  Roles installed" -ForegroundColor Green

# OpenSSH Server
$sshCap = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
if ($sshCap.State -ne "Installed") {
    Add-WindowsCapability -Online -Name $sshCap.Name | Out-Null
    Write-Host "  + OpenSSH.Server installed" -ForegroundColor Green
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue
if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
Write-Host "  sshd running, port 22 allowed" -ForegroundColor Green

# ── Step 5: Credentials ────────────────────────────────────────────────
Write-Host "`n[5/6] Gathering credentials..." -ForegroundColor Yellow
$cred = Get-Credential -Message "Domain Admin (EXAMPLE\soc-admin)"
$dsrm = Read-Host -AsSecureString "DSRM password for DC03"

# ── Step 6: Promote in Branch-Site ─────────────────────────────────────
Write-Host "`n[6/6] Promoting DC03 in $site..." -ForegroundColor Yellow

Install-ADDSDomainController `
    -DomainName $domain `
    -Credential $cred `
    -SafeModeAdministratorPassword $dsrm `
    -SiteName $site `
    -InstallDns:$true `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoGlobalCatalog:$false `
    -NoRebootOnCompletion:$false `
    -Force:$true

# ── RODC variant (commented) ───────────────────────────────────────────
# To make DC03 a Read-Only Domain Controller instead, replace the call above with:
#
# Install-ADDSDomainController -DomainName $domain -Credential $cred `
#     -SafeModeAdministratorPassword $dsrm -SiteName $site `
#     -ReadOnlyReplica:$true -InstallDns:$true -Force:$true
#
# RODC requires a pre-staged computer account (Add-ADDSReadOnlyDomainControllerAccount on DC01).

Write-Host "`n=== DC03 will reboot now to complete promotion ===" -ForegroundColor Cyan
Write-Host "After reboot: Get-ADDomainController -Filter * | Format-Table Name,Site,IPv4Address" -ForegroundColor Yellow
