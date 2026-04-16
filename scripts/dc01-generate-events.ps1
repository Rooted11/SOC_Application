#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generate realistic Windows security events for SOC testing.
    Run on DC01 to create detectable activity for the Ataraxia SOC.

.DESCRIPTION
    Generates:
    - Failed login attempts (brute force simulation)
    - Successful logins
    - User account changes
    - Group membership changes
    - PowerShell execution events
    - Service creation
    - Privilege escalation indicators
#>

param(
    [switch]$All,
    [switch]$BruteForce,
    [switch]$AccountChanges,
    [switch]$PrivEsc,
    [switch]$Recon
)

# Default: run all if no specific switch
if (-not ($BruteForce -or $AccountChanges -or $PrivEsc -or $Recon)) { $All = $true }

Write-Host "`n=== SOC Lab Event Generator ===" -ForegroundColor Cyan
Write-Host "Generating security events for SOC detection testing`n"

# ── Brute Force Simulation ───────────────────────────────────────────
if ($All -or $BruteForce) {
    Write-Host "[*] Simulating brute force attack (failed logins)..." -ForegroundColor Yellow

    # Create a temporary test user for failed logins
    $testUser = "tempattacker"
    $testPass = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
    New-ADUser -SamAccountName $testUser -Name "Temp Attacker" -AccountPassword $testPass `
        -Enabled $true -Path "OU=SOC Lab Users,$((Get-ADDomain).DistinguishedName)" `
        -ErrorAction SilentlyContinue

    # Generate 10 failed login attempts with wrong password
    for ($i = 1; $i -le 10; $i++) {
        $wrongPass = ConvertTo-SecureString "WrongPass$i!" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("EXAMPLE\$testUser", $wrongPass)
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo test" -Credential $cred -ErrorAction SilentlyContinue -WindowStyle Hidden
        } catch { }
        Write-Host "  Failed login attempt $i/10 for $testUser" -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 500
    }

    # Now succeed (will generate 4624 after 4625 flood -> brute force detection)
    try {
        $goodCred = New-Object System.Management.Automation.PSCredential("EXAMPLE\$testUser", $testPass)
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo success" -Credential $goodCred -ErrorAction SilentlyContinue -WindowStyle Hidden
        Write-Host "  Successful login after brute force" -ForegroundColor Green
    } catch { }

    Write-Host "  -> Should trigger: Brute Force -> Success correlation" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}

# ── Account Change Simulation ────────────────────────────────────────
if ($All -or $AccountChanges) {
    Write-Host "`n[*] Simulating account changes..." -ForegroundColor Yellow

    # Create a suspicious user
    $suspUser = "backdoor.admin"
    $suspPass = ConvertTo-SecureString "B@ckd00r2024!" -AsPlainText -Force
    try {
        New-ADUser -SamAccountName $suspUser -Name "Backdoor Admin" `
            -AccountPassword $suspPass -Enabled $true `
            -Path "OU=SOC Lab Users,$((Get-ADDomain).DistinguishedName)" `
            -ErrorAction Stop
        Write-Host "  Created suspicious user: $suspUser (Event 4720)" -ForegroundColor Green
    } catch {
        Write-Host "  User $suspUser already exists" -ForegroundColor DarkGray
    }

    # Add to Domain Admins (VERY suspicious - Event 4728/4732)
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members $suspUser -ErrorAction Stop
        Write-Host "  Added $suspUser to Domain Admins! (Event 4728)" -ForegroundColor Red
    } catch {
        Write-Host "  $suspUser already in Domain Admins" -ForegroundColor DarkGray
    }

    # Reset another user's password (Event 4724)
    try {
        Set-ADAccountPassword -Identity "bwilson" -Reset -NewPassword (ConvertTo-SecureString "ResetPass1!" -AsPlainText -Force) -ErrorAction Stop
        Write-Host "  Reset password for bwilson (Event 4724)" -ForegroundColor Green
    } catch {
        Write-Host "  Could not reset bwilson password: $_" -ForegroundColor DarkGray
    }

    # Disable an account (Event 4725)
    try {
        Disable-ADAccount -Identity "ljones" -ErrorAction Stop
        Write-Host "  Disabled account: ljones (Event 4725)" -ForegroundColor Green
        Start-Sleep -Seconds 2
        Enable-ADAccount -Identity "ljones" -ErrorAction Stop
        Write-Host "  Re-enabled account: ljones (Event 4722)" -ForegroundColor Green
    } catch {
        Write-Host "  Account change for ljones failed: $_" -ForegroundColor DarkGray
    }

    Write-Host "  -> Should trigger: Account tampering + privilege escalation incidents" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}

# ── Privilege Escalation Simulation ──────────────────────────────────
if ($All -or $PrivEsc) {
    Write-Host "`n[*] Simulating privilege escalation indicators..." -ForegroundColor Yellow

    # Run commands that generate 4672 (special privilege) events
    Write-Host "  Executing privileged operations..." -ForegroundColor DarkGray

    # Create a scheduled task (generates events)
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo SOC_TEST"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
    Register-ScheduledTask -TaskName "SOC_Test_Task" -Action $action -Trigger $trigger `
        -Description "SOC Lab test task" -Force | Out-Null
    Write-Host "  Created scheduled task: SOC_Test_Task" -ForegroundColor Green

    # Unregister it
    Unregister-ScheduledTask -TaskName "SOC_Test_Task" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Removed test scheduled task" -ForegroundColor Green

    # Try to install a temporary service (generates 7045)
    try {
        sc.exe create "SOC_Test_Svc" binPath= "cmd.exe /c echo test" type= own start= demand 2>$null | Out-Null
        Write-Host "  Created test service: SOC_Test_Svc (Event 7045)" -ForegroundColor Green
        sc.exe delete "SOC_Test_Svc" 2>$null | Out-Null
        Write-Host "  Removed test service" -ForegroundColor Green
    } catch {
        Write-Host "  Service creation test skipped" -ForegroundColor DarkGray
    }

    Write-Host "  -> Should trigger: Service installation + privilege escalation incidents" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}

# ── Reconnaissance Simulation ────────────────────────────────────────
if ($All -or $Recon) {
    Write-Host "`n[*] Simulating reconnaissance activity..." -ForegroundColor Yellow

    # AD enumeration commands
    Write-Host "  Enumerating domain users..." -ForegroundColor DarkGray
    Get-ADUser -Filter * | Out-Null

    Write-Host "  Enumerating domain groups..." -ForegroundColor DarkGray
    Get-ADGroup -Filter * | Out-Null

    Write-Host "  Enumerating domain computers..." -ForegroundColor DarkGray
    Get-ADComputer -Filter * | Out-Null

    Write-Host "  Running network discovery..." -ForegroundColor DarkGray
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Out-Null

    # PowerShell execution generates script block logging events
    Write-Host "  Executing test PowerShell commands..." -ForegroundColor DarkGray
    Invoke-Expression "whoami /all" | Out-Null
    Invoke-Expression "net user /domain" | Out-Null
    Invoke-Expression "net group 'Domain Admins' /domain" | Out-Null
    Invoke-Expression "nltest /dclist:example.local" | Out-Null

    Write-Host "  -> Should generate: AD enumeration and process creation events" -ForegroundColor Cyan
}

# ── Cleanup ──────────────────────────────────────────────────────────
Write-Host "`n=== Cleanup ===" -ForegroundColor Yellow

# Remove backdoor user from Domain Admins (safety)
try {
    Remove-ADGroupMember -Identity "Domain Admins" -Members "backdoor.admin" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Removed backdoor.admin from Domain Admins" -ForegroundColor Green
} catch { }

# Remove temporary users
try {
    Remove-ADUser -Identity "tempattacker" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Removed tempattacker user" -ForegroundColor Green
} catch { }

try {
    Remove-ADUser -Identity "backdoor.admin" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Removed backdoor.admin user" -ForegroundColor Green
} catch { }

Write-Host "`n=== Event Generation Complete ===" -ForegroundColor Cyan
Write-Host "If the SOC forwarder is running, these events should appear in the dashboard within 30 seconds."
Write-Host "Check: http://<SOC_UBUNTU_IP>:3000 -> Live Feed (filter source: dc01.example.local)`n"
