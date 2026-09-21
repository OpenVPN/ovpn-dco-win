<#
.SYNOPSIS
    Run OpenVPN as a point-to-point client on the driver under test.

.DESCRIPTION
    Point to point is the only mode in which this driver speaks TCP: the socket, its
    Tcp flag and its reassembly state are one per device, so a multipeer server has
    nowhere to keep a second connection. It is also the shape the driver actually ships
    in, behind OpenVPN GUI and Connect.

    The client is started through Win32_Process.Create so it outlives the SSH session
    that launched it.

.EXAMPLE
    .\Start-Client.ps1 -Up -Server 10.0.0.1 -Proto udp
    .\Start-Client.ps1 -Status
    .\Start-Client.ps1 -Down
#>
[CmdletBinding()]
param(
    [switch]$Up,
    [switch]$Down,
    [switch]$Status,
    [string]$Server = '',
    [int]$Port = 11198,
    [ValidateSet('udp', 'tcp')][string]$Proto = 'udp',
    [string]$CertDir = 'C:\ovpn-perf\keys',
    [string]$WorkDir = "$env:TEMP\ovpn-perf",
    [string]$OpenVpn = 'C:\Program Files\OpenVPN\bin\openvpn.exe'
)

$ErrorActionPreference = 'Stop'

# Match the adapter by its description, not its alias: the alias is the connection name,
# which Windows resets to 'Local Area Connection' when the device rebinds after a driver
# reinstall, and which anyone can rename. The description comes from the driver.
function Get-DcoAddress {
    $if = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like '*Data Channel Offload*' } | Select-Object -First 1
    if (-not $if) { return $null }
    (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $if.ifIndex -ErrorAction SilentlyContinue).IPAddress
}
$conf = Join-Path $WorkDir 'client.conf'
$logFile = Join-Path $WorkDir 'client.log'

if ($Down) {
    Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
    'client stopped'
    return
}

if ($Status) {
    $ip = Get-DcoAddress
    "tunnel address: $(if ($ip) { $ip } else { '(none)' })"
    if (Test-Path $logFile) {
        $log = Get-Content $logFile
        "peer-id: $(($log | Select-String 'peer-id: (\d+)' | Select-Object -Last 1).Matches.Groups[1].Value)"
        "errors: $(($log | Select-String 'ERROR|error').Count)"
    }
    return
}

if (-not $Up) { throw 'specify -Up, -Down or -Status' }
if (-not $Server) { throw 'specify -Server' }
if (-not (Test-Path $OpenVpn)) { throw "no openvpn at $OpenVpn" }
foreach ($f in 'ca.crt', 'client.crt', 'client.key') {
    if (-not (Test-Path (Join-Path $CertDir $f))) { throw "missing $f in $CertDir" }
}

New-Item -ItemType Directory -Force $WorkDir | Out-Null
Remove-Item $logFile -ErrorAction SilentlyContinue
$certs = $CertDir -replace '\\', '/'

@"
client
dev tun
proto $Proto$(if ($Proto -eq 'tcp') { '-client' })
remote $Server $Port
nobind
ca $certs/ca.crt
cert $certs/client.crt
key $certs/client.key
remote-cert-tls server
data-ciphers AES-256-GCM
verb 3
log "$($logFile -replace '\\', '/')"
"@ | Set-Content -Encoding ASCII $conf

Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

$cmd = '"' + $OpenVpn + '" --config "' + $conf + '"'
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } | Out-Null

$deadline = (Get-Date).AddSeconds(60)
$ip = $null
while ((Get-Date) -lt $deadline -and -not $ip) {
    Start-Sleep -Seconds 2
    $ip = Get-DcoAddress
}

if (-not $ip) {
    'client did not get a tunnel address:'
    if (Test-Path $logFile) { Get-Content $logFile -Tail 20 }
    throw 'client did not connect'
}

# The point of the run is the offloaded data channel, so fail rather than quietly
# measure a userspace tunnel.
$log = Get-Content $logFile -Raw
if ($log -notmatch 'Data Channel Offload|ovpn-dco') {
    throw 'client connected without data channel offload'
}

"client up on $Proto/$Port to $Server, tunnel address $ip"
