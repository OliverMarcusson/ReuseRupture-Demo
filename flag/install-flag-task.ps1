param(
  [string]$InstallDir = "C:\ReuseRuptureDemo",
  [string]$Flag = "EP284U{REUSERUPTURE_DC_REBOOT_CONFIRMED}",
  [string]$ListenerIp = "192.168.56.20",
  [int]$ListenerPort = 8080,
  [int]$StartupDelaySeconds = 20,
  [int]$RetryCount = 20,
  [int]$RetryDelaySeconds = 10
)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$config = @{
  flag = $Flag
  listener_ip = $ListenerIp
  listener_port = $ListenerPort
  startup_delay_seconds = $StartupDelaySeconds
  retry_count = $RetryCount
  retry_delay_seconds = $RetryDelaySeconds
} | ConvertTo-Json -Depth 4

Set-Content -Path (Join-Path $InstallDir "flag-config.json") -Value $config -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\send-flag.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "ReuseRupture Flag Callback" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
