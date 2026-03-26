$dest = "http://localhost:8000/api/logs/ingest"   # change to your backend URL; add auth header in prod
$hostname = $env:COMPUTERNAME
$user = $env:USERNAME
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
$pos = 0

while ($true) {
  if (Test-Path $logPath) {
    $content = Get-Content -Path $logPath -Raw -ErrorAction SilentlyContinue
    if ($content.Length -gt $pos) {
      $new = $content.Substring($pos)
      $pos = $content.Length
      $rows = $new -split "`n" | Where-Object { $_ -match '^(ALLOW|DROP)' }
      if ($rows) {
        $logs = @()
        $now = (Get-Date).ToUniversalTime().ToString("o")
        foreach ($r in $rows) {
          $parts = $r -split ' '
          if ($parts.Count -ge 6) {
            $logs += @{
              timestamp  = $now
              source     = "win-firewall"
              log_level  = "info"
              message    = "$($parts[0]) $($parts[1]) $($parts[2]) -> $($parts[3]):$($parts[5])"
              event_type = "fw_" + $parts[0].ToLower()
              ip_src     = $parts[2]
              ip_dst     = $parts[3]
              raw_data   = @{
                hostname = $hostname
                user     = $user
                action   = $parts[0]
                proto    = $parts[1]
                sport    = $parts[4]
                dport    = $parts[5]
              }
            }
          }
        }
        if ($logs.Count -gt 0) {
          $body = @{ logs = $logs } | ConvertTo-Json -Depth 6
          Invoke-RestMethod -Uri $dest -Method Post -ContentType 'application/json' -Body $body | Out-Null
        }
      }
    }
  }
  Start-Sleep -Seconds 10
}
