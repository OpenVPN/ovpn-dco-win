<#
.SYNOPSIS
    Run OpenVPN as a multipeer server on the driver under test.

.DESCRIPTION
    client-to-client is on, so traffic between two clients stays in the kernel: the
    driver decrypts from peer A and hands the plaintext to the host stack, which routes
    it straight back down the same adapter, where the driver looks the destination up in
    the peer table and encrypts to peer B. Userspace never sees those packets.

    That hairpin only happens if the adapter forwards, and a fresh Windows install does
    not. Without it every client still reaches the server while no client can reach any
    other, which resembles a broken peer table. -Up turns forwarding on and
    -Down puts it back.

    The server is started through Win32_Process.Create so it outlives the SSH session
    that launched it.

.EXAMPLE
    .\Start-Server.ps1 -Up -CertDir C:\stage\keys
    .\Start-Server.ps1 -Status
    .\Start-Server.ps1 -Down
#>
[CmdletBinding()]
param(
    [switch]$Up,
    [switch]$Down,
    [switch]$Status,
    [string]$CertDir = '',
    [string]$WorkDir = "$env:TEMP\ovpn-stress",
    [int]$Port = 11197,
    # a subnet behind each peer, so the driver's route trie is exercised
    [string]$IRoute = '10.90.0.0',
    [string]$IRouteMask = '255.255.255.0',
    [string]$Subnet = '10.79.0.0',
    # /18, so the pool can hold a flood of peers rather than 253
    [string]$Mask = '255.255.192.0',
    # must leave room for the DCO, UDP and IP headers inside the client uplink MTU
    [int]$TunMtu = 1390,
    [string]$OpenVpn = 'C:\Program Files\OpenVPN\bin\openvpn.exe'
)

# $PSScriptRoot can be empty depending on how the script is invoked (it is, over SSH),
# so resolve the script directory explicitly rather than in the parameter default.
if (-not $CertDir) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $CertDir = Join-Path $base 'keys'
}

$conf       = Join-Path $WorkDir 'server.ovpn'
$logFile    = Join-Path $WorkDir 'server.log'
$statusFile = Join-Path $WorkDir 'status.log'
$serverIp   = ($Subnet -replace '\.0$', '.1')

# The data path is a hairpin through the host stack, so the adapter has to forward.
function Set-Forwarding([string]$State) {
    $if = Get-NetAdapter | Where-Object InterfaceDescription -Match 'OpenVPN Data Channel Offload'
    if (-not $if) { return $null }
    foreach ($af in 'IPv4', 'IPv6') {
        Set-NetIPInterface -InterfaceIndex $if.ifIndex -AddressFamily $af `
            -Forwarding $State -ErrorAction SilentlyContinue
    }
    (Get-NetIPInterface -InterfaceIndex $if.ifIndex -AddressFamily IPv4).Forwarding
}

function Get-PeTimestamp([string]$Path) {
    $b = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    '0x{0:X8}' -f [BitConverter]::ToUInt32($b, $pe + 8)
}

if ($Down) {
    Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
    Set-Forwarding 'Disabled'
    'server down'
    return
}

if ($Status) {
    if (Test-Path $statusFile) {
        "connected peers: $((Get-Content $statusFile | Select-String '^CLIENT_LIST').Count)"
    }
    if (Test-Path $logFile) {
        $log = Get-Content $logFile
        "peer sessions (MULTI: Learn): $(($log | Select-String 'MULTI: Learn').Count)"

        # The swarm kills clients mid-flight by design, which produces two kinds of
        # noise the driver has nothing to do with: handshakes abandoned when the client
        # dies, and source ports the kernel hands straight back to the next client while
        # the server still has a session on that address. Count those separately.
        $churn = @(
            'TLS key negotiation failed'          # client killed mid-handshake
            'TLS handshake failed'
            'tls-error'
            'Unroutable control packet'           # control packet for a session now gone
            'reading acknowledgement record'      # ack for a session now gone
            'Disallow float'                      # reused source port, float refused
            'bad record mac'                      # reused source port, wrong TLS keys
            'record layer failure'
            'tls_read_plaintext'
            'incoming plaintext read error'
            # userspace replay window, which under DCO only ever sees packets from a
            # session that has moved on; the driver's own replay rejects are LostInData
            'bad packet ID'
            'Connection reset'
            'Inactivity timeout'
            'ping-restart'
        ) -join '|'

        # Counted on its own: a send the server failed to make, which costs the peer
        # a retransmit timer. Not a driver fault, so it does not fail a run, but it is
        # not noise either and averaging it into "churn" hid it.
        "dropped sends: $(($log | Select-String 'write UDPv4').Count)"
        "server exited: $(($log | Select-String 'Exiting due to fatal error').Count)"

        $all = $log | Select-String 'error|ERROR|TLS Error' | Select-String 'write UDPv4' -NotMatch
        "churn: $(($all | Select-String $churn).Count)"
        "errors: $(($all | Select-String $churn -NotMatch).Count)"
    }
    return
}

if (-not $Up) { throw 'specify -Up, -Down or -Status' }

foreach ($f in 'ca.crt', 'server.crt', 'server.key') {
    if (-not (Test-Path (Join-Path $CertDir $f))) { throw "missing $f in $CertDir" }
if (-not (Test-Path $OpenVpn)) { throw "no openvpn at $OpenVpn" }
}
New-Item -ItemType Directory -Force $WorkDir | Out-Null

$ccd = Join-Path $WorkDir 'ccd'
New-Item -ItemType Directory -Force $ccd | Out-Null
"iroute $IRoute $IRouteMask" | Set-Content (Join-Path $ccd 'DEFAULT')
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
data-ciphers AES-128-GCM
tun-mtu $TunMtu
client-to-client
duplicate-cn
client-config-dir "$($ccd -replace '\\', '/')"
# iroute says which peer owns the subnet, and push route makes clients send it there.
# The plain route is needed too: iroute only registers the subnet inside OpenVPN, while
# route is what puts it in the host routing table pointing at the adapter. Without it a
# packet for that subnet is decrypted, handed up, and dropped by the host for want of a
# route, so it never comes back down to the driver and no peer ever sees it.
route $IRoute $IRouteMask
push "route $IRoute $IRouteMask"
# the default is 1024, which a flood reaches
max-clients 20000
keepalive 10 60
verb 3
log "$($logFile -replace '\\', '/')"
status "$($statusFile -replace '\\', '/')" 2
"@ | Set-Content $conf

Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
$cmd = '"' + $OpenVpn + '" --config "' + $conf + '"'
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } | Out-Null

$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline -and -not (Get-NetIPAddress -IPAddress $serverIp -ErrorAction SilentlyContinue)) {
    Start-Sleep 1
}
if (-not (Get-NetIPAddress -IPAddress $serverIp -ErrorAction SilentlyContinue)) {
    'server did not come up; log tail:'
    Get-Content $logFile -Tail 15
    exit 1
}

"server up on udp/$Port, tunnel $serverIp"
"client-to-client forwarding: $(Set-Forwarding 'Enabled')"
"iroute per peer: $IRoute $IRouteMask"
"driver: $(Get-PeTimestamp "$env:SystemRoot\System32\drivers\ovpn-dco.sys")"
"verifier: $(((verifier /querysettings 2>&1 | Select-String 'Verifier Flags') -join '') -replace '\s+', ' ')"
