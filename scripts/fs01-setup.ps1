#Requires -RunAsAdministrator
<#
.SYNOPSIS
    FS01 - Full member server build for the SOC Lab.
    Installs File Services + DFS-N, DHCP, AD CS (Enterprise Subordinate or
    standalone), Print Server, OpenSSH Server, and joins example.local.

.DESCRIPTION
    Run on a freshly installed Windows Server 2022 VM. The script will:
      1. Set static IP <FS01_IP>/24, DNS -> DC01 + DC02
      2. Rename to FS01 and join example.local (will reboot once after join)
      3. After the second invocation (or as part of phase 2), install:
           - File Server + File Server Resource Manager + Data Deduplication
           - DFS Namespaces + DFS Replication
           - DHCP Server (scope <DHCP_START>-<DHCP_END>)
           - AD CS (Enterprise Root CA, lab-only)
           - Print and Document Services
           - Windows Server Backup
           - OpenSSH Server (port 22)
      4. Create file shares: \\FS01\SOC$, \\FS01\Public, \\FS01\Profiles$
      5. Authorize DHCP in AD and activate the scope
      6. Configure CA, request DC certs

.NOTES
    Pre-reqs:
      - DC01 + DC02 healthy
      - dc01-advanced-ad.ps1 has run (HQ-Site, gMSA host group exists)
      - EXAMPLE\soc-admin available

    Run twice:
      Pass 1 - sets IP, joins domain, reboots
      Pass 2 - installs roles + shares + DHCP + CA
    The script auto-detects which pass to run based on domain membership.
#>

Write-Host "`n=== SOC Lab - FS01 Member Server Build ===" -ForegroundColor Cyan

$myIP    = "<FS01_IP>"
$dc01IP  = "<DC01_IP>"
$dc02IP  = "<DC02_IP>"
$domain  = "example.local"

$inDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
if (-not $inDomain) {
    # ────────────── PASS 1: configure, rename, join, reboot ──────────────
    Write-Host "Pass 1: network -> rename -> join domain`n" -ForegroundColor Cyan

    # 1. Static IP
    Write-Host "[1/4] Static IP $myIP..." -ForegroundColor Yellow
    $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback' } | Select-Object -First 1
    if (-not $a) { Write-Host "ERROR: no adapter" -ForegroundColor Red; exit 1 }
    Remove-NetIPAddress -InterfaceIndex $a.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute     -InterfaceIndex $a.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $myIP -PrefixLength 24 `
        -DefaultGateway "<VM_HOST_IP>" -ErrorAction SilentlyContinue | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @($dc01IP, $dc02IP)
    Write-Host "  $myIP/24 set" -ForegroundColor Green

    # 2. Rename
    Write-Host "`n[2/4] Renaming to FS01..." -ForegroundColor Yellow
    if ($env:COMPUTERNAME -ne "FS01") { Rename-Computer -NewName "FS01" -Force }

    # 3. Install OpenSSH first so we can SSH in immediately after reboot
    Write-Host "`n[3/4] Installing OpenSSH Server..." -ForegroundColor Yellow
    $sshCap = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
    if ($sshCap.State -ne "Installed") {
        Add-WindowsCapability -Online -Name $sshCap.Name | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd -ErrorAction SilentlyContinue
    if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }
    Write-Host "  sshd running, port 22 open" -ForegroundColor Green

    # 4. Join domain
    Write-Host "`n[4/4] Joining $domain ..." -ForegroundColor Yellow
    $cred = Get-Credential -Message "Domain Admin to join $domain (EXAMPLE\soc-admin)"
    Add-Computer -DomainName $domain -Credential $cred -OUPath "OU=SOC Lab Servers,DC=lab,DC=local" -Force -Restart
    # Reboots into pass 2 territory
    return
}

# ────────────── PASS 2: install roles, shares, DHCP, CA ──────────────
Write-Host "Pass 2: roles + shares + DHCP + AD CS`n" -ForegroundColor Cyan

# Sanity
if ($env:COMPUTERNAME -ne "FS01") {
    Write-Host "ERROR: hostname is $env:COMPUTERNAME, expected FS01. Reboot first." -ForegroundColor Red; exit 1
}

# ── 1. Install all roles in one shot ───────────────────────────────────
Write-Host "[1/6] Installing roles: FS, DFS, DHCP, AD CS, Print, Backup..." -ForegroundColor Yellow
Install-WindowsFeature -Name `
    FS-FileServer, FS-Resource-Manager, FS-Data-Deduplication, `
    FS-DFS-Namespace, FS-DFS-Replication, `
    DHCP, RSAT-DHCP, `
    ADCS-Cert-Authority, ADCS-Web-Enrollment, RSAT-ADCS, RSAT-ADCS-Mgmt, `
    Print-Server, RSAT-Print-Services, `
    Windows-Server-Backup, `
    RSAT-AD-PowerShell, RSAT-AD-AdminCenter `
    -IncludeManagementTools | Out-Null
Write-Host "  Roles installed" -ForegroundColor Green

# ── 2. Create the data shares ──────────────────────────────────────────
Write-Host "`n[2/6] Creating SMB shares..." -ForegroundColor Yellow

$shareRoot = "D:\Shares"
if (-not (Test-Path "D:\")) { $shareRoot = "C:\Shares" }
foreach ($d in @("$shareRoot\SOC", "$shareRoot\Public", "$shareRoot\Profiles")) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Hidden SOC share - for soc-admin / SOC Admins / SOC Analysts
if (-not (Get-SmbShare -Name "SOC$" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "SOC$" -Path "$shareRoot\SOC" `
        -FullAccess "EXAMPLE\Domain Admins" `
        -ChangeAccess "EXAMPLE\SOC Analysts","EXAMPLE\SOC Admins" `
        -EncryptData $true -CachingMode None | Out-Null
    Write-Host "  + \\FS01\SOC$ (hidden, encrypted)" -ForegroundColor Green
}

if (-not (Get-SmbShare -Name "Public" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Public" -Path "$shareRoot\Public" `
        -ChangeAccess "EXAMPLE\Authenticated Users" | Out-Null
    Write-Host "  + \\FS01\Public" -ForegroundColor Green
}

# Roaming profiles share
if (-not (Get-SmbShare -Name "Profiles$" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Profiles$" -Path "$shareRoot\Profiles" `
        -FullAccess "EXAMPLE\Domain Admins" `
        -ChangeAccess "EXAMPLE\Domain Users" | Out-Null
    Write-Host "  + \\FS01\Profiles$ (roaming profiles)" -ForegroundColor Green
}

# Force SMB signing on the server side
Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Confirm:$false
Write-Host "  SMB signing required, encryption on" -ForegroundColor Green

# ── 3. DFS Namespace ───────────────────────────────────────────────────
Write-Host "`n[3/6] Setting up DFS Namespace \\example.local\soc..." -ForegroundColor Yellow
$dfsRoot = "$shareRoot\DFSRoots\soc"
if (-not (Test-Path $dfsRoot)) { New-Item -ItemType Directory -Path $dfsRoot -Force | Out-Null }
if (-not (Get-SmbShare -Name "soc" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "soc" -Path $dfsRoot -FullAccess "EXAMPLE\Domain Admins" `
        -ChangeAccess "EXAMPLE\Authenticated Users" | Out-Null
}
Import-Module DFSN -ErrorAction SilentlyContinue
try {
    if (-not (Get-DfsnRoot -Path "\\example.local\soc" -ErrorAction SilentlyContinue)) {
        New-DfsnRoot -TargetPath "\\FS01\soc" -Type DomainV2 -Path "\\example.local\soc" | Out-Null
        Write-Host "  + DFS-N \\example.local\soc -> \\FS01\soc" -ForegroundColor Green
    }
    # Folder targets
    foreach ($f in @("public","tools","incidents")) {
        $folderPath = "\\example.local\soc\$f"
        if (-not (Get-DfsnFolder -Path $folderPath -ErrorAction SilentlyContinue)) {
            $localPath = "$shareRoot\Public"
            New-DfsnFolder -Path $folderPath -TargetPath "\\FS01\Public" -EnableTargetFailback $true | Out-Null
            Write-Host "  + DFS folder $folderPath" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "  DFS-N setup error: $_" -ForegroundColor DarkYellow
}

# ── 4. DHCP server ─────────────────────────────────────────────────────
Write-Host "`n[4/6] Configuring DHCP..." -ForegroundColor Yellow

# Authorize in AD
Add-DhcpServerInDC -DnsName "FS01.example.local" -IPAddress $myIP -ErrorAction SilentlyContinue
Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRRonLeaseExpiry $true -ErrorAction SilentlyContinue

# Scope for the lab subnet
if (-not (Get-DhcpServerv4Scope -ScopeId "<LAB_SUBNET_BASE>" -ErrorAction SilentlyContinue)) {
    Add-DhcpServerv4Scope -Name "SOC-Lab-HQ" `
        -StartRange "<DHCP_START>" -EndRange "<DHCP_END>" `
        -SubnetMask 255.255.255.0 -State Active
    Set-DhcpServerv4OptionValue -ScopeId <LAB_SUBNET_BASE> `
        -Router "<VM_HOST_IP>" `
        -DnsServer @($dc01IP, $dc02IP) `
        -DnsDomain "example.local"
    Write-Host "  + DHCP scope <DHCP_START>-<DHCP_END>" -ForegroundColor Green
}

# Reserve IPs we use statically (so DHCP never hands them out)
foreach ($r in @(
    @{ IP="<DC01_IP>"; Name="DC01"; MAC="00-00-00-00-00-10" },
    @{ IP="<DC02_IP>"; Name="DC02"; MAC="00-00-00-00-00-11" },
    @{ IP="<DC03_IP>"; Name="DC03"; MAC="00-00-00-00-00-12" },
    @{ IP="<FS01_IP>"; Name="FS01"; MAC="00-00-00-00-00-20" }
)) {
    if (-not (Get-DhcpServerv4Reservation -ScopeId <LAB_SUBNET_BASE> -IPAddress $r.IP -ErrorAction SilentlyContinue)) {
        try { Add-DhcpServerv4Reservation -ScopeId <LAB_SUBNET_BASE> -IPAddress $r.IP -ClientId $r.MAC -Name $r.Name -ErrorAction Stop | Out-Null } catch {}
    }
}
Restart-Service dhcpserver
Write-Host "  DHCP service restarted" -ForegroundColor Green

# ── 5. AD CS - Enterprise Root CA ──────────────────────────────────────
Write-Host "`n[5/6] Configuring AD CS (Enterprise Root CA)..." -ForegroundColor Yellow
try {
    Install-AdcsCertificationAuthority `
        -CAType EnterpriseRootCA `
        -CACommonName "SOC-Lab-Root-CA" `
        -KeyLength 2048 `
        -HashAlgorithmName SHA256 `
        -ValidityPeriod Years -ValidityPeriodUnits 10 `
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -Force -Confirm:$false
    Install-AdcsWebEnrollment -Force -Confirm:$false
    Write-Host "  Enterprise Root CA 'SOC-Lab-Root-CA' active" -ForegroundColor Green
} catch {
    Write-Host "  CA install: $_" -ForegroundColor DarkYellow
}

# ── 6. File Server Resource Manager quotas (sample) ────────────────────
Write-Host "`n[6/6] Setting FSRM 5GB hard quota on Public..." -ForegroundColor Yellow
Import-Module FileServerResourceManager -ErrorAction SilentlyContinue
try {
    if (-not (Get-FsrmQuota -Path "$shareRoot\Public" -ErrorAction SilentlyContinue)) {
        New-FsrmQuota -Path "$shareRoot\Public" -Size 5GB -Description "Public share quota" | Out-Null
        Write-Host "  + 5GB hard quota on $shareRoot\Public" -ForegroundColor Green
    }
} catch {
    Write-Host "  FSRM quota: $_" -ForegroundColor DarkYellow
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n=== FS01 Build Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:    FS01.example.local ($myIP)"
Write-Host "Joined to:   example.local"
Write-Host ""
Write-Host "Roles:" -ForegroundColor Yellow
Write-Host "  - File Server + FSRM + Dedup"
Write-Host "  - DFS Namespaces + Replication"
Write-Host "  - DHCP Server (<DHCP_START>-<DHCP_END>)"
Write-Host "  - AD CS Enterprise Root CA: SOC-Lab-Root-CA"
Write-Host "  - Print Server"
Write-Host "  - Windows Server Backup"
Write-Host "  - OpenSSH Server (port 22)"
Write-Host ""
Write-Host "Shares:" -ForegroundColor Yellow
Write-Host "  \\FS01\SOC$       (encrypted, SOC Admins/Analysts)"
Write-Host "  \\FS01\Public     (everyone, 5GB quota)"
Write-Host "  \\FS01\Profiles$  (roaming profiles)"
Write-Host "  \\example.local\soc   (DFS-N namespace)"
Write-Host ""
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  - Enroll DCs in 'Domain Controller' cert template via gpupdate"
Write-Host "  - Browse https://FS01/certsrv to test web enrollment"
