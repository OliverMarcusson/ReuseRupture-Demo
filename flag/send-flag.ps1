param(
  [string]$ConfigPath = "C:\ReuseRuptureDemo\flag-config.json",
  [string]$ArmedRunIdPath = "C:\ReuseRuptureDemo\armed-run-id.txt",
  [string]$LogPath = "C:\ReuseRuptureDemo\flag-callback.log"
)

function Write-FlagLog {
  param([string]$Message)
  $timestamp = (Get-Date).ToUniversalTime().ToString("o")
  Add-Content -Path $LogPath -Value "$timestamp $Message"
}

try {
  if (-not (Test-Path $ConfigPath)) {
    Write-FlagLog "missing config $ConfigPath"
    exit 0
  }

  $config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
  Start-Sleep -Seconds ([int]$config.startup_delay_seconds)

  if (-not (Test-Path $ArmedRunIdPath)) {
    Write-FlagLog "not armed; no callback sent"
    exit 0
  }

  $runId = (Get-Content -Raw -Path $ArmedRunIdPath).Trim()
  if ([string]::IsNullOrWhiteSpace($runId)) {
    Write-FlagLog "empty run id; no callback sent"
    exit 0
  }

  $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")
  $payload = @{
    flag = [string]$config.flag
    run_id = $runId
    hostname = $env:COMPUTERNAME
    boot_time = $bootTime
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
  } | ConvertTo-Json -Depth 4

  $uri = "http://$($config.listener_ip):$($config.listener_port)/flag"
  for ($i = 1; $i -le [int]$config.retry_count; $i++) {
    try {
      Invoke-RestMethod -Method Post -Uri $uri -Body $payload -ContentType "application/json" -TimeoutSec 10 | Out-Null
      Write-FlagLog "sent flag for run_id=$runId to $uri"
      Rename-Item -Path $ArmedRunIdPath -NewName "armed-run-id.sent.$runId.txt" -Force
      exit 0
    } catch {
      Write-FlagLog "attempt $i failed: $($_.Exception.Message)"
      Start-Sleep -Seconds ([int]$config.retry_delay_seconds)
    }
  }

  Write-FlagLog "failed to send flag for run_id=$runId"
  exit 1
} catch {
  Write-FlagLog "fatal error: $($_.Exception.Message)"
  exit 1
}
