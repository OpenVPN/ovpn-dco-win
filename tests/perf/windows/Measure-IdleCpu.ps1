<#
.SYNOPSIS
    What the driver costs when nothing is going on.

.DESCRIPTION
    Every other gate here asks whether the driver crashed, deadlocked, or how fast it
    goes. None of them notice a core spinning with no session up: throughput is
    unaffected, nothing fails, and on a sixteen core machine it is six percent of the
    total. That is how a transmit queue that stopped draining its ring shipped in
    2.8.13 - NetAdapterCx polled it forever and burned a core after every disconnect.

    System (PID 4) is where that time lands, because the work is kernel threads and
    DPCs that belong to no process. Measuring the process rather than per-core
    percentages also survives a busy or virtualised machine, where per-core numbers
    wander: a pinned core is one CPU-second per wall second however the scheduler
    moves it around.

    Run it with the tunnel down. Idle has measured 0.02-0.05 cores on every machine
    tried; a stuck poll reads 1.0.

.EXAMPLE
    .\Measure-IdleCpu.ps1 -Seconds 15 -MaxCores 0.30
#>
[CmdletBinding()]
param(
    [int]$Seconds = 15,
    # Well clear of idle noise and well under one core, so it says "spinning", not "busy".
    [double]$MaxCores = 0.30
)

$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture

$ovpn = @(Get-Process openvpn -ErrorAction SilentlyContinue).Count
$up = @(Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like '*Data Channel Offload*' -and $_.Status -eq 'Up'
}).Count
if ($ovpn -gt 0 -or $up -gt 0) {
    # Not a pass: it means the measurement never happened.
    Write-Output "idle check skipped: openvpn=$ovpn adapters-up=$up, expected none"
    exit 2
}

$before = (Get-Process -Id 4).CPU
$t0 = Get-Date
Start-Sleep -Seconds $Seconds
$after = (Get-Process -Id 4).CPU

$wall = ((Get-Date) - $t0).TotalSeconds
$cores = ($after - $before) / $wall
Write-Output ("System CPU with no session: {0:N2} cores over {1:N0}s (limit {2:N2})" -f $cores, $wall, $MaxCores)

if ($cores -gt $MaxCores) {
    # Name the shape, because the stack is in NetAdapterCx and the driver is not on it.
    Write-Output "the driver is burning CPU with nothing connected; a packet queue is most likely being polled without draining"
    exit 1
}
exit 0
