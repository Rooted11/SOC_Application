#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Event Log forwarder for Ataraxia SOC.
    Reads security-relevant events from Windows Event Logs and POSTs them
    as JSON to the SOC backend at <SOC_UBUNTU_IP>:8000.

.DESCRIPTION
    Runs in a loop, collecting new events every $IntervalSeconds.
    Maps Windows Event IDs to SOC event types for proper detection pipeline processing.

.PARAMETER SOCEndpoint
    SOC backend URL (default: http://<SOC_UBUNTU_IP>:8000)

.PARAMETER IngestToken
    Token for the SOC ingest API (default: lab-ingest-token)

.PARAMETER IntervalSeconds
    Collection interval in seconds (default: 15)

.PARAMETER Once
    Run once and exit (don't loop)

.EXAMPLE
    .\dc01-soc-forwarder.ps1
    .\dc01-soc-forwarder.ps1 -Once
    .\dc01-soc-forwarder.ps1 -IntervalSeconds 30
#>

param(
    [string]$SOCEndpoint = "http://<SOC_UBUNTU_IP>:8000",
    [string]$IngestToken = "lab-ingest-token",
    [int]$IntervalSeconds = 15,
    [switch]$Once
)

$IngestUrl = "$SOCEndpoint/api/logs/ingest"
$Source = "dc01.example.local"

# ── Event ID to SOC event type mapping ─────────────────────────────────

$EventMap = @{
    # Authentication
    4624  = @{ Type = "auth_success";         Level = "info"    }  # Successful logon
    4625  = @{ Type = "auth_failure";         Level = "warning" }  # Failed logon
    4634  = @{ Type = "auth_logoff";          Level = "info"    }  # Logoff
    4648  = @{ Type = "auth_explicit_logon";  Level = "warning" }  # Logon with explicit creds
    4647  = @{ Type = "auth_logoff";          Level = "info"    }  # User-initiated logoff
    4776  = @{ Type = "auth_ntlm";           Level = "info"    }  # NTLM credential validation

    # Account Management
    4720  = @{ Type = "account_change";       Level = "warning" }  # User account created
    4722  = @{ Type = "account_change";       Level = "info"    }  # User account enabled
    4723  = @{ Type = "account_change";       Level = "info"    }  # Password change attempt
    4724  = @{ Type = "account_change";       Level = "warning" }  # Password reset attempt
    4725  = @{ Type = "account_change";       Level = "warning" }  # User account disabled
    4726  = @{ Type = "account_change";       Level = "warning" }  # User account deleted
    4728  = @{ Type = "account_change";       Level = "warning" }  # Member added to global group
    4732  = @{ Type = "privilege_escalation";  Level = "error"   }  # Member added to local group
    4735  = @{ Type = "account_change";       Level = "warning" }  # Local group changed
    4740  = @{ Type = "auth_failure";         Level = "error"   }  # Account locked out
    4756  = @{ Type = "privilege_escalation";  Level = "error"   }  # Member added to universal group

    # Privilege Use
    4672  = @{ Type = "privilege_escalation";  Level = "warning" }  # Special privileges assigned
    4673  = @{ Type = "privilege_escalation";  Level = "warning" }  # Privileged service called
    4674  = @{ Type = "privilege_escalation";  Level = "warning" }  # Operation on privileged object

    # Process & System
    4688  = @{ Type = "process_creation";     Level = "info"    }  # Process created
    4689  = @{ Type = "system_event";         Level = "info"    }  # Process terminated
    7045  = @{ Type = "service_install";      Level = "warning" }  # Service installed
    4697  = @{ Type = "service_install";      Level = "warning" }  # Service installed (audit)
    1102  = @{ Type = "audit_log_cleared";    Level = "error"   }  # Audit log cleared

    # Kerberos
    4768  = @{ Type = "auth_kerberos";        Level = "info"    }  # TGT requested
    4769  = @{ Type = "auth_kerberos";        Level = "info"    }  # Service ticket requested
    4771  = @{ Type = "auth_failure";         Level = "warning" }  # Kerberos pre-auth failed

    # Group Policy
    4739  = @{ Type = "policy_change";        Level = "warning" }  # Domain policy changed
}

# Security-relevant Event IDs to collect
$WatchEventIds = $EventMap.Keys | Sort-Object

# Logon type descriptions
$LogonTypes = @{
    2  = "Interactive"
    3  = "Network"
    4  = "Batch"
    5  = "Service"
    7  = "Unlock"
    8  = "NetworkCleartext"
    9  = "NewCredentials"
    10 = "RemoteInteractive"
    11 = "CachedInteractive"
}

# Track last read time (look back 30 minutes on first run to catch recent events)
$lastRead = (Get-Date).AddMinutes(-30)

Write-Host ""
Write-Host "=== Ataraxia SOC - Windows Event Forwarder ===" -ForegroundColor Cyan
Write-Host "Source:   $Source"
Write-Host "SOC:     $IngestUrl"
Write-Host "Interval: ${IntervalSeconds}s"
Write-Host "Events:   $($WatchEventIds.Count) event IDs monitored"
Write-Host ""

function Convert-EventToSOC {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $id = $Event.Id
    $mapping = $EventMap[$id]
    if (-not $mapping) { return $null }

    $eventType = $mapping.Type
    $logLevel  = $mapping.Level

    # Extract common fields from event XML
    $xml = [xml]$Event.ToXml()
    $eventData = @{}
    if ($xml.Event.EventData) {
        foreach ($data in $xml.Event.EventData.Data) {
            if ($data.Name -and $data.'#text') {
                $eventData[$data.Name] = $data.'#text'
            }
        }
    }

    $ipSrc    = $eventData["IpAddress"]
    $userName = if ($eventData["TargetUserName"]) { $eventData["TargetUserName"] } elseif ($eventData["SubjectUserName"]) { $eventData["SubjectUserName"] } else { "" }
    $ipDst    = $null
    $message  = $Event.Message

    # Clean up message (first line only for brevity)
    if ($message) {
        $message = ($message -split "`n")[0].Trim()
        if ($message.Length -gt 500) { $message = $message.Substring(0, 500) + "..." }
    } else {
        $message = "Event ID $id"
    }

    # Enrich based on event ID
    switch ($id) {
        4624 {
            $logonType = $eventData["LogonType"]
            $logonDesc = $LogonTypes[[int]$logonType]
            if ($logonDesc) { $message = "Successful $logonDesc logon for $userName" }
            # Filter out system/service logons that are noise
            if ($userName -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-)') { return $null }
        }
        4625 {
            $logLevel = "error"
            $failReason = if ($eventData['FailureReason']) { $eventData['FailureReason'] } else { $eventData['Status'] }
            $message = "Failed logon for $userName from $ipSrc (Reason: $failReason)"
        }
        4648 {
            $message = "Explicit credential logon: $($eventData['SubjectUserName']) used $userName credentials"
        }
        4672 {
            if ($userName -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)') { return $null }
            $message = "Special privileges assigned to $userName"
        }
        4688 {
            $process = $eventData["NewProcessName"]
            $cmdline = $eventData["CommandLine"]
            $message = "Process created: $process"
            if ($cmdline) { $message += " [$cmdline]" }
            # Filter common system noise
            if ($process -match '\\(conhost|WmiPrvSE|svchost|taskhostw|RuntimeBroker)\.exe$') { return $null }
        }
        4720 { $message = "User account created: $($eventData['TargetUserName']) by $($eventData['SubjectUserName'])" }
        4726 { $message = "User account deleted: $($eventData['TargetUserName']) by $($eventData['SubjectUserName'])" }
        4732 {
            $memberName = if ($eventData['MemberName']) { $eventData['MemberName'] } else { $eventData['TargetUserName'] }
            $groupName = if ($eventData['TargetUserName']) { $eventData['TargetUserName'] } else { 'Administrators' }
            $message = "User $memberName added to local group $groupName"
            $logLevel = "error"
        }
        4740 { $message = "Account locked out: $userName on $($eventData['TargetDomainName'])" }
        7045 {
            $message = "New service installed: $($eventData['ServiceName']) ($($eventData['ImagePath']))"
            $logLevel = "error"
        }
        1102 {
            $message = "SECURITY AUDIT LOG CLEARED by $($eventData['SubjectUserName'])"
            $logLevel = "error"
        }
    }

    return @{
        source     = $Source
        timestamp  = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        log_level  = $logLevel
        message    = $message
        ip_src     = if ($ipSrc -and $ipSrc -ne "-") { $ipSrc } else { "<DC01_IP>" }
        ip_dst     = $ipDst
        user       = $userName
        event_type = $eventType
        raw_data   = @{
            event_id      = $id
            computer      = $Event.MachineName
            provider      = $Event.ProviderName
            logon_type    = $eventData["LogonType"]
            process       = $eventData["NewProcessName"]
            target_user   = $eventData["TargetUserName"]
            subject_user  = $eventData["SubjectUserName"]
            target_domain = $eventData["TargetDomainName"]
            status        = $eventData["Status"]
        }
    }
}

function Send-ToSOC {
    param([array]$Logs)

    if ($Logs.Count -eq 0) { return }

    $body = @{ logs = $Logs } | ConvertTo-Json -Depth 5 -Compress

    try {
        $response = Invoke-RestMethod -Uri $IngestUrl -Method POST `
            -ContentType "application/json" `
            -Headers @{ "X-Agent-Token" = $IngestToken } `
            -Body $body `
            -TimeoutSec 10

        $mode = if ($response.mode) { $response.mode } else { "inline" }
        $count = if ($response.enqueued) { $response.enqueued } elseif ($response.ingested) { $response.ingested } else { 0 }
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] Sent $($Logs.Count) events -> SOC ($mode`: $count)" -ForegroundColor Green
    } catch {
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] ERROR sending to SOC: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Main loop ─────────────────────────────────────────────────────────

function Collect-And-Send {
    $now = Get-Date
    $logs = @()

    try {
        # Query Security log using FilterHashtable (PS 5.1 compatible)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $WatchEventIds
            StartTime = $lastRead
        } -ErrorAction SilentlyContinue

        # Also check System log for service installs (7045)
        $sysEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = 7045
            StartTime = $lastRead
        } -ErrorAction SilentlyContinue

        $allEvents = @()
        if ($events) { $allEvents += $events }
        if ($sysEvents) { $allEvents += $sysEvents }

        foreach ($evt in $allEvents) {
            $socLog = Convert-EventToSOC -Event $evt
            if ($socLog) { $logs += $socLog }
        }
    } catch {
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] Collection error: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($logs.Count -gt 0) {
        Send-ToSOC -Logs $logs
    } else {
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] No new events" -ForegroundColor DarkGray
    }

    $script:lastRead = $now
}

# Run
if ($Once) {
    Write-Host "Running single collection..." -ForegroundColor Yellow
    Collect-And-Send
    Write-Host "Done." -ForegroundColor Cyan
} else {
    Write-Host "Starting continuous collection (Ctrl+C to stop)..." -ForegroundColor Yellow
    Write-Host ""
    while ($true) {
        Collect-And-Send
        Start-Sleep -Seconds $IntervalSeconds
    }
}
