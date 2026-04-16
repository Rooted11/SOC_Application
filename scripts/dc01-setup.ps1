#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Phase 1: Configure Windows Server 2022 as a Domain Controller for the SOC Lab.
    Run this AFTER installing Windows Server and logging in as Administrator.

.DESCRIPTION
    - Sets static IP on the Host-Only adapter (<DC01_IP>)
    - Renames computer to DC01
    - Installs AD DS + DNS roles
    - Promotes to Domain Controller for example.local
    - The server will REBOOT after promotion

.NOTES
    SOC Lab Network: <LAB_SUBNET>/24
    Ubuntu SOC:      <SOC_UBUNTU_IP>
    Windows Host:    <VM_HOST_IP>
    This DC:         <DC01_IP>
#>

Write-Host "`n=== SOC Lab - Domain Controller Setup (Phase 1) ===" -ForegroundColor Cyan
Write-Host "This script will configure this server as DC01.example.local`n"

# ── Step 1: Configure Static IP ──────────────────────────────────────
Write-Host "[1/4] Configuring static IP address..." -ForegroundColor Yellow

# Find the Host-Only adapter (the one on <LAB_SUBNET>.x or the first Ethernet adapter)
$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback'
} | Select-Object -First 1

if (-not $adapter) {
    Write-Host "ERROR: No active network adapter found!" -ForegroundColor Red
    exit 1
}

Write-Host "  Using adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"

# Remove existing IP config and set static
Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "<DC01_IP>" `
    -PrefixLength 24 `
    -DefaultGateway "<VM_HOST_IP>" -ErrorAction SilentlyContinue

# DNS: point to self (will be DNS server) and Google as fallback
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses @("<DC01_IP>", "8.8.8.8")

Write-Host "  Static IP set: <DC01_IP>/24" -ForegroundColor Green

# Check for NAT adapter and configure it for internet
$natAdapter = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.ifIndex -ne $adapter.ifIndex
} | Select-Object -First 1

if ($natAdapter) {
    Write-Host "  NAT adapter found: $($natAdapter.Name) - leaving DHCP for internet"
}

# ── Step 2: Rename Computer ──────────────────────────────────────────
Write-Host "`n[2/4] Renaming computer to DC01..." -ForegroundColor Yellow

if ($env:COMPUTERNAME -ne "DC01") {
    Rename-Computer -NewName "DC01" -Force
    Write-Host "  Computer renamed to DC01" -ForegroundColor Green
} else {
    Write-Host "  Already named DC01" -ForegroundColor Green
}

# ── Step 3: Install AD DS + DNS ──────────────────────────────────────
Write-Host "`n[3/4] Installing Active Directory Domain Services..." -ForegroundColor Yellow

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction Stop

Write-Host "  AD DS and DNS roles installed" -ForegroundColor Green

# ── Step 4: Promote to Domain Controller ─────────────────────────────
Write-Host "`n[4/4] Promoting to Domain Controller..." -ForegroundColor Yellow
Write-Host "  Domain: example.local"
Write-Host "  NetBIOS: LAB"
Write-Host ""
Write-Host "  You will be prompted for a DSRM (Directory Services Restore Mode) password."
Write-Host "  Use a strong password (e.g., <STRONG_PASSWORD>)" -ForegroundColor Yellow
Write-Host ""

# Prompt for DSRM password
$dsrmPassword = Read-Host -AsSecureString "Enter DSRM password"

Install-ADDSForest `
    -DomainName "example.local" `
    -DomainNetbiosName "<NETBIOS>" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $dsrmPassword `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Server will reboot automatically after promotion
Write-Host "`n=== Server will reboot now to complete DC promotion ===" -ForegroundColor Cyan
Write-Host "After reboot, log in as EXAMPLE\Administrator and run dc01-phase2.ps1" -ForegroundColor Yellow
