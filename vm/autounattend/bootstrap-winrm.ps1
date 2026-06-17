$ErrorActionPreference = "Stop"

$installDir = "C:\ReuseRuptureDemo"
$logPath = Join-Path $installDir "winrm-bootstrap.log"
New-Item -Path $installDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path $logPath -Append

try {
    Write-Host "ReuseRupture WinRM bootstrap started."

    $targetIp = "__RR_WINDOWS_IP__"
    $prefixLength = __RR_NETWORK_PREFIX__
    $gateway = "__RR_NETWORK_GATEWAY__"
    $dnsServer = "__RR_WINDOWS_IP__"

    $adapter = Get-NetAdapter |
        Where-Object { $_.Status -ne "Disabled" } |
        Sort-Object -Property ifIndex |
        Select-Object -First 1

    if (-not $adapter) {
        throw "No enabled network adapter was found."
    }

    Write-Host "Configuring static IPv4 address $targetIp/$prefixLength on $($adapter.Name)."
    Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -ne "WellKnown" } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress `
        -InterfaceIndex $adapter.ifIndex `
        -IPAddress $targetIp `
        -PrefixLength $prefixLength `
        -DefaultGateway $gateway `
        -ErrorAction Stop | Out-Null

    Set-DnsClientServerAddress `
        -InterfaceIndex $adapter.ifIndex `
        -ServerAddresses $dnsServer

    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.NetworkCategory -ne "Private" } |
        Set-NetConnectionProfile -NetworkCategory Private

    Enable-PSRemoting -Force
    winrm quickconfig -quiet

    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

    $hostname = $env:COMPUTERNAME
    $dnsNames = @($hostname, "DC01", "localhost") | Select-Object -Unique
    $cert = New-SelfSignedCertificate `
        -DnsName $dnsNames `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(5)

    Get-ChildItem WSMan:\localhost\Listener |
        Where-Object { $_.Keys -contains "Transport=HTTPS" } |
        Remove-Item -Recurse -Force

    New-Item `
        -Path WSMan:\localhost\Listener `
        -Transport HTTPS `
        -Address * `
        -Hostname $hostname `
        -CertificateThumbPrint $cert.Thumbprint `
        -Force | Out-Null

    New-NetFirewallRule `
        -DisplayName "ReuseRupture WinRM HTTPS" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5986 `
        -ErrorAction SilentlyContinue | Out-Null

    Set-Service -Name WinRM -StartupType Automatic
    Restart-Service -Name WinRM -Force

    Write-Host "ReuseRupture WinRM bootstrap completed successfully."
} catch {
    Write-Host "ReuseRupture WinRM bootstrap failed."
    Write-Host $_
    throw
} finally {
    Stop-Transcript
}
