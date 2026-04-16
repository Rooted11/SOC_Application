#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Phase 3: Advanced Active Directory build-out for the SOC Lab.
    Run on DC01 AFTER dc01-phase2.ps1 has completed successfully.

.DESCRIPTION
    Adds production-grade AD features on top of the basic forest:
      - AD Recycle Bin (forest-wide, irreversible)
      - KDS root key (for gMSA / group Managed Service Accounts)
      - Sample gMSA (svc.gmsa.soc) for SOC log forwarder
      - Fine-Grained Password Policies (PSO) for admins and service accounts
      - AD Sites, Subnets and Site Links (HQ + Branch)
      - Reverse DNS lookup zone for <LAB_SUBNET>/24 + DNS scavenging
      - Tiered admin OU model (Tier 0 / 1 / 2)
      - Baseline GPOs (audit, firewall, RDP, SMB signing, password policy)
      - Windows LAPS schema extension (Server 2022 native LAPS)
      - Protected Users group population for Domain Admins

.NOTES
    Idempotent - safe to re-run. Skips anything already configured.
    Domain: example.local       NetBIOS: LAB
    DC01:   <DC01_IP>   Site: HQ-Site
    DC02:   <DC02_IP>   Site: HQ-Site
    DC03:   <DC03_IP>   Site: Branch-Site
    FS01:   <FS01_IP>   Site: HQ-Site
#>

Write-Host "`n=== SOC Lab - Advanced AD Build-Out (Phase 3) ===" -ForegroundColor Cyan

try {
    Import-Module ActiveDirectory  -ErrorAction Stop
    Import-Module DnsServer        -ErrorAction Stop
    Import-Module GroupPolicy      -ErrorAction Stop
} catch {
    Write-Host "ERROR: Required modules not available. Run on DC01 after promotion." -ForegroundColor Red
    exit 1
}

$forest = Get-ADForest
$domain = Get-ADDomain
$dn     = $domain.DistinguishedName
Write-Host "Forest: $($forest.Name)   Domain: $($domain.DNSRoot)`n"

# ── Step 1: AD Recycle Bin ─────────────────────────────────────────────
Write-Host "[1/10] Enabling AD Recycle Bin..." -ForegroundColor Yellow
$rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
if ($rb.EnabledScopes.Count -eq 0) {
    Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
        -Scope ForestOrConfigurationSet `
        -Target $forest.Name -Confirm:$false
    Write-Host "  Recycle Bin enabled (forest-wide)" -ForegroundColor Green
} else {
    Write-Host "  Recycle Bin already enabled" -ForegroundColor DarkGray
}

# ── Step 2: KDS Root Key (for gMSA) ────────────────────────────────────
Write-Host "`n[2/10] Creating KDS root key for gMSA..." -ForegroundColor Yellow
if (-not (Get-KdsRootKey -ErrorAction SilentlyContinue)) {
    # In a lab we backdate by 10 hours so gMSAs are usable immediately
    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
    Write-Host "  KDS root key created (backdated -10h for lab)" -ForegroundColor Green
} else {
    Write-Host "  KDS root key already present" -ForegroundColor DarkGray
}

# ── Step 3: Tiered Admin OU Model ──────────────────────────────────────
Write-Host "`n[3/10] Creating Tier 0/1/2 admin OU structure..." -ForegroundColor Yellow

$tierOUs = @(
    @{ N = "Admin";              P = $dn },
    @{ N = "Tier 0";             P = "OU=Admin,$dn" },   # Forest / DC admins
    @{ N = "Tier 1";             P = "OU=Admin,$dn" },   # Server admins
    @{ N = "Tier 2";             P = "OU=Admin,$dn" },   # Workstation / helpdesk
    @{ N = "Tier 0 - Accounts";  P = "OU=Tier 0,OU=Admin,$dn" },
    @{ N = "Tier 0 - Groups";    P = "OU=Tier 0,OU=Admin,$dn" },
    @{ N = "Tier 1 - Accounts";  P = "OU=Tier 1,OU=Admin,$dn" },
    @{ N = "Tier 1 - Groups";    P = "OU=Tier 1,OU=Admin,$dn" },
    @{ N = "Tier 2 - Accounts";  P = "OU=Tier 2,OU=Admin,$dn" },
    @{ N = "Tier 2 - Groups";    P = "OU=Tier 2,OU=Admin,$dn" }
)
foreach ($o in $tierOUs) {
    $ouDN = "OU=$($o.N),$($o.P)"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $o.N -Path $o.P -ProtectedFromAccidentalDeletion $true
        Write-Host "  + $ouDN" -ForegroundColor Green
    }
}

# Tiered admin groups
$tierGroups = @(
    @{ N = "T0-DomainAdmins";   P = "OU=Tier 0 - Groups,OU=Tier 0,OU=Admin,$dn"; D = "Tier 0 forest/DC admins" },
    @{ N = "T1-ServerAdmins";   P = "OU=Tier 1 - Groups,OU=Tier 1,OU=Admin,$dn"; D = "Tier 1 member-server admins" },
    @{ N = "T2-WorkstationAdmins"; P = "OU=Tier 2 - Groups,OU=Tier 2,OU=Admin,$dn"; D = "Tier 2 workstation/helpdesk admins" }
)
foreach ($g in $tierGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($g.N)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $g.N -GroupScope Global -GroupCategory Security -Path $g.P -Description $g.D
        Write-Host "  + group $($g.N)" -ForegroundColor Green
    }
}

# ── Step 4: Group Managed Service Account ──────────────────────────────
Write-Host "`n[4/10] Creating gMSA for SOC log forwarder..." -ForegroundColor Yellow

$gmsaName = "svc-soc-fwd"
if (-not (Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue)) {
    # Allow all current and future DCs / member servers in SOC Lab Servers OU to retrieve the password
    $allowGroupName = "gMSA-SOC-Forwarder-Hosts"
    if (-not (Get-ADGroup -Filter "Name -eq '$allowGroupName'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $allowGroupName -GroupScope Global -GroupCategory Security `
            -Path "OU=Service Accounts,$dn" -Description "Hosts allowed to retrieve $gmsaName password"
    }
    # Add DC01 computer object
    $dc01 = Get-ADComputer -Filter "Name -eq 'DC01'" -ErrorAction SilentlyContinue
    if ($dc01) { Add-ADGroupMember -Identity $allowGroupName -Members $dc01 -ErrorAction SilentlyContinue }

    New-ADServiceAccount -Name $gmsaName `
        -DNSHostName "$gmsaName.$($domain.DNSRoot)" `
        -PrincipalsAllowedToRetrieveManagedPassword $allowGroupName `
        -Path "OU=Service Accounts,$dn" `
        -Enabled $true
    Write-Host "  + gMSA $gmsaName (allowed-hosts: $allowGroupName)" -ForegroundColor Green
} else {
    Write-Host "  gMSA $gmsaName already exists" -ForegroundColor DarkGray
}

# ── Step 5: Fine-Grained Password Policies ─────────────────────────────
Write-Host "`n[5/10] Creating Fine-Grained Password Policies..." -ForegroundColor Yellow

# Strong PSO for admins
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'PSO-Admins'" -ErrorAction SilentlyContinue)) {
    New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" `
        -Precedence 10 `
        -ComplexityEnabled $true `
        -MinPasswordLength 16 `
        -PasswordHistoryCount 24 `
        -MaxPasswordAge (New-TimeSpan -Days 60) `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -LockoutThreshold 5 `
        -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
        -LockoutDuration (New-TimeSpan -Minutes 30) `
        -ReversibleEncryptionEnabled $false `
        -Description "Strong password policy for admin accounts"
    # Apply to Domain Admins + Tier 0 admins
    Add-ADFineGrainedPasswordPolicySubject -Identity "PSO-Admins" -Subjects "Domain Admins"
    Write-Host "  + PSO-Admins (16 char, 60-day, 5 lockout)" -ForegroundColor Green
}

# Even stronger PSO for service accounts (long, no expiry)
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'PSO-ServiceAccounts'" -ErrorAction SilentlyContinue)) {
    New-ADFineGrainedPasswordPolicy -Name "PSO-ServiceAccounts" `
        -Precedence 20 `
        -ComplexityEnabled $true `
        -MinPasswordLength 24 `
        -PasswordHistoryCount 5 `
        -MaxPasswordAge (New-TimeSpan -Days 0) `
        -MinPasswordAge (New-TimeSpan -Days 0) `
        -LockoutThreshold 0 `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -ReversibleEncryptionEnabled $false `
        -Description "Long password, never expires for service accounts"
    Write-Host "  + PSO-ServiceAccounts (24 char, no expiry)" -ForegroundColor Green
}

# ── Step 6: Sites, Subnets, Site Links ─────────────────────────────────
Write-Host "`n[6/10] Configuring AD Sites and Services..." -ForegroundColor Yellow

# Rename Default-First-Site-Name -> HQ-Site
$defaultSite = Get-ADReplicationSite -Filter "Name -eq 'Default-First-Site-Name'" -ErrorAction SilentlyContinue
if ($defaultSite) {
    Rename-ADObject -Identity $defaultSite.DistinguishedName -NewName "HQ-Site"
    Write-Host "  Renamed Default-First-Site-Name -> HQ-Site" -ForegroundColor Green
}

# Branch site
if (-not (Get-ADReplicationSite -Filter "Name -eq 'Branch-Site'" -ErrorAction SilentlyContinue)) {
    New-ADReplicationSite -Name "Branch-Site"
    Write-Host "  + Site: Branch-Site" -ForegroundColor Green
}

# Subnets
$subnets = @(
    @{ Name = "<LAB_SUBNET>/24"; Site = "HQ-Site";     Loc = "SOC Lab HQ" },
    @{ Name = "<BRANCH_SUBNET>/24"; Site = "Branch-Site"; Loc = "SOC Lab Branch" }
)
foreach ($s in $subnets) {
    if (-not (Get-ADReplicationSubnet -Filter "Name -eq '$($s.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADReplicationSubnet -Name $s.Name -Site $s.Site -Location $s.Loc
        Write-Host "  + Subnet: $($s.Name) -> $($s.Site)" -ForegroundColor Green
    }
}

# Site link HQ <-> Branch (15 min replication)
if (-not (Get-ADReplicationSiteLink -Filter "Name -eq 'HQ-Branch-Link'" -ErrorAction SilentlyContinue)) {
    New-ADReplicationSiteLink -Name "HQ-Branch-Link" `
        -SitesIncluded "HQ-Site","Branch-Site" `
        -Cost 100 `
        -ReplicationFrequencyInMinutes 15 `
        -InterSiteTransportProtocol IP
    Write-Host "  + Site link: HQ-Branch-Link (15 min, cost 100)" -ForegroundColor Green
}

# ── Step 7: Reverse DNS zone + scavenging ──────────────────────────────
Write-Host "`n[7/10] Configuring DNS reverse zone + scavenging..." -ForegroundColor Yellow

if (-not (Get-DnsServerZone -Name "56.168.192.in-addr.arpa" -ErrorAction SilentlyContinue)) {
    Add-DnsServerPrimaryZone -NetworkID "<LAB_SUBNET>/24" `
        -ReplicationScope Forest -DynamicUpdate Secure
    Write-Host "  + Reverse zone <LAB_SUBNET>/24 (AD-integrated, secure updates)" -ForegroundColor Green
}

# Scavenging (DNS housekeeping for stale records)
Set-DnsServerScavenging -ScavengingState $true `
    -RefreshInterval 7.00:00:00 `
    -NoRefreshInterval 7.00:00:00 `
    -ScavengingInterval 1.00:00:00 -ApplyOnAllZones
Write-Host "  Scavenging enabled (7d/7d, daily run)" -ForegroundColor Green

# Conditional forwarder example - keeps internet resolution working
Add-DnsServerForwarder -IPAddress "1.1.1.1" -ErrorAction SilentlyContinue
Write-Host "  Added DNS forwarder 1.1.1.1" -ForegroundColor Green

# ── Step 8: Baseline Group Policy Objects ──────────────────────────────
Write-Host "`n[8/10] Creating baseline GPOs..." -ForegroundColor Yellow

function Ensure-GPO($name, $description) {
    $g = Get-GPO -Name $name -ErrorAction SilentlyContinue
    if (-not $g) {
        $g = New-GPO -Name $name -Comment $description
        Write-Host "  + GPO: $name" -ForegroundColor Green
    }
    return $g
}

# 8a. Audit baseline (already done at DC, but enforce on all servers)
$gpoAudit = Ensure-GPO "SOC - Audit Baseline" "Process creation, logon, account management auditing"
Set-GPRegistryValue -Name $gpoAudit.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 | Out-Null

# 8b. Firewall on for all profiles
$gpoFw = Ensure-GPO "SOC - Firewall On" "Force Windows Firewall enabled, block inbound by default"
foreach ($profile in "DomainProfile","StandardProfile","PublicProfile") {
    Set-GPRegistryValue -Name $gpoFw.DisplayName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile" `
        -ValueName "EnableFirewall" -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $gpoFw.DisplayName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile" `
        -ValueName "DefaultInboundAction" -Type DWord -Value 1 | Out-Null
}

# 8c. SMB signing required (mitigates relay)
$gpoSmb = Ensure-GPO "SOC - SMB Signing Required" "Require SMB signing on client+server"
Set-GPRegistryValue -Name $gpoSmb.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoSmb.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null

# 8d. RDP NLA + restrict
$gpoRdp = Ensure-GPO "SOC - RDP Hardening" "Require NLA, restrict RDP encryption"
Set-GPRegistryValue -Name $gpoRdp.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "UserAuthentication" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoRdp.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "MinEncryptionLevel" -Type DWord -Value 3 | Out-Null

# 8e. Link the GPOs to the domain root
$existingLinks = @((Get-GPInheritance -Target $dn).GpoLinks | ForEach-Object { $_.DisplayName })
foreach ($name in @("SOC - Audit Baseline","SOC - Firewall On","SOC - SMB Signing Required","SOC - RDP Hardening")) {
    if ($existingLinks -notcontains $name) {
        try {
            New-GPLink -Name $name -Target $dn -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Host "  + linked $name" -ForegroundColor Green
        } catch {
            Write-Host "  ! could not link $name : $_" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "  $name already linked" -ForegroundColor DarkGray
    }
}

# ── Step 9: Windows LAPS schema ────────────────────────────────────────
Write-Host "`n[9/10] Extending schema for Windows LAPS..." -ForegroundColor Yellow
if (Get-Command -Name Update-LapsADSchema -ErrorAction SilentlyContinue) {
    try {
        Update-LapsADSchema -Confirm:$false -ErrorAction Stop
        Write-Host "  Windows LAPS schema attributes added" -ForegroundColor Green

        # Allow DC to manage SOC Lab Servers OU LAPS passwords
        if (Get-ADOrganizationalUnit -Filter "Name -eq 'SOC Lab Servers'" -ErrorAction SilentlyContinue) {
            Set-LapsADComputerSelfPermission -Identity "OU=SOC Lab Servers,$dn" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  LAPS self-permission granted on SOC Lab Servers OU" -ForegroundColor Green
        }
    } catch {
        Write-Host "  LAPS schema update failed: $_" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  Update-LapsADSchema not available - install Windows Updates (KB5025230 / April 2023+) to get inbox Windows LAPS, then re-run this script." -ForegroundColor DarkYellow
}

# ── Step 10: Protected Users + final summary ───────────────────────────
Write-Host "`n[10/10] Adding admins to Protected Users group..." -ForegroundColor Yellow
$protected = @("soc-admin","it-admin")
foreach ($u in $protected) {
    $usr = Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue
    if ($usr) {
        Add-ADGroupMember -Identity "Protected Users" -Members $usr -ErrorAction SilentlyContinue
        Write-Host "  + $u -> Protected Users" -ForegroundColor Green
    }
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n=== Advanced AD Build-Out Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Forest features:" -ForegroundColor Yellow
Write-Host "  - AD Recycle Bin enabled"
Write-Host "  - KDS root key created (gMSA ready)"
Write-Host "  - Schema extended for Windows LAPS"
Write-Host ""
Write-Host "Sites & Subnets:" -ForegroundColor Yellow
Write-Host "  - HQ-Site      <LAB_SUBNET>/24   (DC01, DC02, FS01)"
Write-Host "  - Branch-Site  <BRANCH_SUBNET>/24   (DC03)"
Write-Host "  - Site link:   HQ-Branch-Link, 15 min"
Write-Host ""
Write-Host "Identity hardening:" -ForegroundColor Yellow
Write-Host "  - PSO-Admins (16ch / 60d / 5 lockout)"
Write-Host "  - PSO-ServiceAccounts (24ch / no expiry)"
Write-Host "  - Tier 0/1/2 admin OUs and groups"
Write-Host "  - Domain Admins added to Protected Users"
Write-Host ""
Write-Host "Baseline GPOs linked to $($domain.DNSRoot):" -ForegroundColor Yellow
Write-Host "  - SOC - Audit Baseline"
Write-Host "  - SOC - Firewall On"
Write-Host "  - SOC - SMB Signing Required"
Write-Host "  - SOC - RDP Hardening"
Write-Host ""
Write-Host "Next: build the additional DCs:" -ForegroundColor Cyan
Write-Host "  On DC02 host -> .\dc02-promote.ps1"
Write-Host "  On DC03 host -> .\dc03-promote.ps1"
Write-Host "  On FS01 host -> .\fs01-setup.ps1"
