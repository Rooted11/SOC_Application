#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promote DC02 - second writable Domain Controller for example.local.
    Run on a freshly installed Windows Server 2022 VM.

.DESCRIPTION
    - Sets static IP <DC02_IP>/24
    - Points DNS at DC01 (<DC01_IP>) so domain join works
    - Renames computer to DC02
    - Joins example.local
    - Installs AD DS + DNS roles
    - Promotes as additional writable DC in HQ-Site
    - Server reboots automatically after promotion

.NOTES
    Pre-reqs:
      - DC01 (<DC01_IP>) is up, healthy, and reachable
      - dc01-advanced-ad.ps1 has been run (HQ-Site exists)
      - You have credentials of EXAMPLE\soc-admin (or any Domain Admin)

    The script will prompt for:
      - Domain admin credentials (to join + promote)
      - DSRM (Directory Services Restore Mode) password for this DC
#>

Write-Host "`n=== SOC Lab - DC02 Promotion ===" -ForegroundColor Cyan
Write-Host "This will join example.local and promote this server as a 2nd DC.`n"

$myIP   = "<DC02_IP>"
$dc01IP = "<DC01_IP>"
$domain = "example.local"
$siteName = "HQ-Site"

# ── Step 1: Static IP ──────────────────────────────────────────────────
Write-Host "[1/6] Configuring static IP $myIP..." -ForegroundColor Yellow

$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback'
} | Select-Object -First 1

if (-not $adapter) { Write-Host "ERROR: no active adapter" -ForegroundColor Red; exit 1 }
Write-Host "  Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"

Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute     -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress $myIP -PrefixLength 24 `
    -DefaultGateway "<VM_HOST_IP>" -ErrorAction SilentlyContinue | Out-Null

# DNS MUST point at DC01 first so we can resolve example.local
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses @($dc01IP, "8.8.8.8")

Write-Host "  Static IP $myIP/24, DNS -> $dc01IP" -ForegroundColor Green

# ── Step 2: Reach DC01 ─────────────────────────────────────────────────
Write-Host "`n[2/6] Verifying connectivity to DC01..." -ForegroundColor Yellow
if (-not (Test-Connection -ComputerName $dc01IP -Count 2 -Quiet)) {
    Write-Host "ERROR: cannot ping $dc01IP. Fix networking and re-run." -ForegroundColor Red
    exit 1
}
Write-Host "  $dc01IP reachable" -ForegroundColor Green

# Resolve the domain over DNS
$resolved = Resolve-DnsName -Name $domain -Type A -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-Host "ERROR: $domain does not resolve. Check DC01 DNS." -ForegroundColor Red
    exit 1
}
Write-Host "  $domain resolves to $($resolved.IPAddress -join ', ')" -ForegroundColor Green

# ── Step 3: Rename ─────────────────────────────────────────────────────
Write-Host "`n[3/6] Renaming computer to DC02..." -ForegroundColor Yellow
if ($env:COMPUTERNAME -ne "DC02") {
    Rename-Computer -NewName "DC02" -Force
    Write-Host "  Renamed (takes effect after reboot/promotion)" -ForegroundColor Green
} else {
    Write-Host "  Already DC02" -ForegroundColor DarkGray
}

# ── Step 4: Install AD DS + DNS roles + OpenSSH ────────────────────────
Write-Host "`n[4/6] Installing AD DS + DNS + management tools + OpenSSH..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-DNS-Server `
    -IncludeManagementTools | Out-Null
Write-Host "  Roles installed" -ForegroundColor Green

# OpenSSH Server (Windows capability) - so we can SSH into DC02 after reboot
$sshCap = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
if ($sshCap.State -ne "Installed") {
    Add-WindowsCapability -Online -Name $sshCap.Name | Out-Null
    Write-Host "  + OpenSSH.Server capability installed" -ForegroundColor Green
} else {
    Write-Host "  OpenSSH.Server already installed" -ForegroundColor DarkGray
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue
if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
Write-Host "  sshd running, port 22 allowed" -ForegroundColor Green

# ── Step 5: Get credentials ────────────────────────────────────────────
Write-Host "`n[5/6] Gather credentials..." -ForegroundColor Yellow
Write-Host "  Enter Domain Admin credentials (e.g. EXAMPLE\soc-admin):"
$cred = Get-Credential -Message "Domain Admin (used to join + promote)"

Write-Host "  Enter DSRM password for DC02 (used to recover this DC if needed):"
$dsrm = Read-Host -AsSecureString "DSRM password"

# ── Step 6: Promote ────────────────────────────────────────────────────
Write-Host "`n[6/6] Promoting DC02 as additional DC in $siteName..." -ForegroundColor Yellow

Install-ADDSDomainController `
    -DomainName $domain `
    -Credential $cred `
    -SafeModeAdministratorPassword $dsrm `
    -SiteName $siteName `
    -InstallDns:$true `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoGlobalCatalog:$false `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Server reboots automatically. After reboot:
#   1. Log in as EXAMPLE\soc-admin
#   2. Verify with: Get-ADDomainController -Discover -DomainName example.local
#   3. Force replication: repadmin /syncall /AdeP
Write-Host "`n=== DC02 will reboot now to complete promotion ===" -ForegroundColor Cyan
Write-Host "After reboot, verify with: Get-ADDomainController -Filter *" -ForegroundColor Yellow
