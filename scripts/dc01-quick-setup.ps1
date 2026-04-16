#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Quick Phase 1 setup for DC01 - Static IP + AD DS + Forest promotion.
    Run in an elevated PowerShell on the freshly installed Windows Server.
    The server WILL REBOOT after this script completes.
#>

Write-Host "`n=== SOC Lab - DC01 Quick Setup ===" -ForegroundColor Cyan

# ── Static IP ────────────────────────────────────────────────────────
Write-Host "[1/3] Setting static IP <DC01_IP>..." -ForegroundColor Yellow

# Find the Host-Only adapter (first active Ethernet)
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback' }
Write-Host "  Found adapters:"
foreach ($a in $adapters) { Write-Host "    - $($a.Name): $($a.InterfaceDescription)" }

# Use the first adapter for host-only (will be configured static)
$hoAdapter = $adapters | Select-Object -First 1
Write-Host "  Configuring $($hoAdapter.Name) as Host-Only (<DC01_IP>)..."

Remove-NetIPAddress -InterfaceIndex $hoAdapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $hoAdapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $hoAdapter.ifIndex `
    -IPAddress "<DC01_IP>" -PrefixLength 24 `
    -DefaultGateway "<VM_HOST_IP>" -ErrorAction SilentlyContinue | Out-Null

Set-DnsClientServerAddress -InterfaceIndex $hoAdapter.ifIndex `
    -ServerAddresses @("127.0.0.1", "8.8.8.8")

# Verify connectivity to SOC
Write-Host "  Testing connectivity to SOC (<SOC_UBUNTU_IP>)..."
$ping = Test-Connection -ComputerName <SOC_UBUNTU_IP> -Count 2 -Quiet -ErrorAction SilentlyContinue
if ($ping) {
    Write-Host "  SOC reachable!" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Cannot reach SOC yet - may need adapter configuration" -ForegroundColor Yellow
}

# ── Rename + Install AD DS ───────────────────────────────────────────
Write-Host "`n[2/3] Renaming to DC01 and installing AD DS..." -ForegroundColor Yellow

if ($env:COMPUTERNAME -ne "DC01") {
    Rename-Computer -NewName "DC01" -Force
    Write-Host "  Renamed to DC01" -ForegroundColor Green
}

Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools | Out-Null
Write-Host "  AD DS + DNS installed" -ForegroundColor Green

# ── Promote to DC ────────────────────────────────────────────────────
Write-Host "`n[3/3] Promoting to Domain Controller (example.local)..." -ForegroundColor Yellow
Write-Host "  DSRM Password will be: <DSRM_PASSWORD>" -ForegroundColor Yellow

$dsrm = ConvertTo-SecureString "<DSRM_PASSWORD>" -AsPlainText -Force

Install-ADDSForest `
    -DomainName "example.local" `
    -DomainNetbiosName "<NETBIOS>" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $dsrm `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Server reboots here
