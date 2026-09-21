<#
.SYNOPSIS
    Run OpenVPN as a multipeer server on the driver under test.

.DESCRIPTION
    The server counterpart of Start-Client.ps1, and UDP only: the driver's socket, its
    Tcp flag and its reassembly state are one per device, so a multipeer server has
    nowhere to keep a second connection.

    Unlike the stress rig's server this one carries a single client on a clean path: no
    client-to-client hairpin, no iroute, no route trie. Those are correctness paths and
    the stress rig covers them; here they would only add cost the measurement cannot
    attribute.

    The server is started through Win32_Process.Create so it outlives the SSH session
    that launched it.

.EXAMPLE
    .\Start-Server.ps1 -Up
    .\Start-Server.ps1 -Status
    .\Start-Server.ps1 -Down
#>
[CmdletBinding()]
param(
    [switch]$Up,
    [switch]$Down,
    [switch]$Status,
    [int]$Port = 11198,
    [string]$Subnet = '10.88.0.0',
    [string]$Mask = '255.255.255.0',
    [string]$CertDir = 'C:\ovpn-perf\keys',
    [string]$WorkDir = "$env:TEMP\ovpn-perf",
    # a multipeer server needs a binary that knows the MP ioctls, which is the same
    # build the stress rig requires; the client end is happy with a stock one
    [string]$OpenVpn = 'C:\stage\ovpn-patched\openvpn.exe'
)

$ErrorActionPreference = 'Stop'
$conf = Join-Path $WorkDir 'server.conf'
$logFile = Join-Path $WorkDir 'server.log'
$serverIp = ($Subnet -replace '\.0$', '.1')

# A fresh Windows install accepts none of this. The rules carry a group name so -Down
# can take back exactly what -Up added, and nothing else.
$fwGroup = 'ovpn-dco perf'
function Add-Rules {
    Remove-Rules
    New-NetFirewallRule -DisplayName "$fwGroup transport" -Group $fwGroup -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $Port | Out-Null
    # iperf3 listens on the server end, and the tunnel is inside the firewall too
    New-NetFirewallRule -DisplayName "$fwGroup iperf3" -Group $fwGroup -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort 5202 | Out-Null
    # the rig pings the tunnel address before measuring, to wait for the path
    New-NetFirewallRule -DisplayName "$fwGroup icmp" -Group $fwGroup -Direction Inbound `
        -Action Allow -Protocol ICMPv4 -IcmpType 8 | Out-Null
}
function Remove-Rules {
    Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
# Match the adapter by its description, not its alias: the alias is the connection name,
# which Windows resets to 'Local Area Connection' when the device rebinds after a driver
# reinstall, and which anyone can rename. The description comes from the driver.
function Get-DcoAddress {
    $if = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like '*Data Channel Offload*' } | Select-Object -First 1
    if (-not $if) { return $null }
    (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $if.ifIndex -ErrorAction SilentlyContinue).IPAddress
}

if ($Down) {
    Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-Rules
    'server stopped'
    return
}

if ($Status) {
    "tunnel address: $(if ($ip = Get-DcoAddress) { $ip } else { '(none)' })"
    if (Test-Path $logFile) {
        $log = Get-Content $logFile
        "peer sessions: $(($log | Select-String 'MULTI: Learn').Count)"
        "errors: $(($log | Select-String 'ERROR|error').Count)"
    }
    return
}

if (-not $Up) { throw 'specify -Up, -Down or -Status' }
if (-not (Test-Path $OpenVpn)) { throw "no openvpn at $OpenVpn" }
foreach ($f in 'ca.crt', 'server.crt', 'server.key') {
    if (-not (Test-Path (Join-Path $CertDir $f))) { throw "missing $f in $CertDir" }
}

New-Item -ItemType Directory -Force $WorkDir | Out-Null
Add-Rules
Remove-Item $logFile -ErrorAction SilentlyContinue
# OpenVPN treats backslashes in quoted paths as escapes
$certs = $CertDir -replace '\\', '/'

@"
server $Subnet $Mask
proto udp4
port $Port
dev tun
ca "$certs/ca.crt"
cert "$certs/server.crt"
key "$certs/server.key"
dh none
data-ciphers AES-256-GCM
keepalive 10 60
verb 3
log "$($logFile -replace '\\', '/')"
"@ | Set-Content -Encoding ASCII $conf

Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

$cmd = '"' + $OpenVpn + '" --config "' + $conf + '"'
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } | Out-Null

$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline -and (Get-DcoAddress) -ne $serverIp) {
    Start-Sleep -Seconds 2
}

if ((Get-DcoAddress) -ne $serverIp) {
    'server did not come up:'
    if (Test-Path $logFile) { Get-Content $logFile -Tail 20 }
    throw 'server did not start'
}

# The point of the run is the offloaded data channel. The address landing on the offload
# adapter is the proof: without the driver OpenVPN would have opened a different one.
"server up on udp/$Port, tunnel address $serverIp, firewall opened"
