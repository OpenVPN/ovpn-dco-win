<#
.SYNOPSIS
    Record the driver's own account of where the NIC receives the tunnel.

.DESCRIPTION
    The NIC's receive core cannot be read off the CPU samples: the driver's transmit and
    receive workers run as DPCs too, on other cores, so the core with the most DPC time is
    often a worker's. The driver logs the NIC's receive core itself each time it chooses a
    home core for its queue threads, so trace that event instead.

    -Start begins a trace session for the driver's provider; start it before the tunnel
    comes up, as the first choice is made on the first data. -Stop ends it and prints one
    line per choice, "<nic receive core> <home core>", oldest first; nothing if the driver
    chose none (no dominant receive core, or a NetAdapterCx that runs the queues in a DPC).

.EXAMPLE
    .\Trace-HomeCore.ps1 -Start -Etl C:\ovpn-perf\home.etl
    .\Trace-HomeCore.ps1 -Stop -Etl C:\ovpn-perf\home.etl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Etl,
    [switch]$Start,
    [switch]$Stop
)

$session = 'ovpn-perf-home'
$provider = '{4970f9cf-2c0c-4f11-b1cc-e3a1e9958833}'

if ($Start) {
    logman stop $session -ets 2>&1 | Out-Null
    Remove-Item $Etl, "$Etl.xml" -ErrorAction SilentlyContinue
    logman start $session -p $provider 0xffffffffffffffff 0xff -o $Etl -ets | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not start trace session $session" }
    return
}

if ($Stop) {
    logman stop $session -ets 2>&1 | Out-Null
    if (-not (Test-Path $Etl)) { return }
    tracerpt $Etl -o "$Etl.xml" -of XML -y 2>&1 | Out-Null
    [xml]$x = Get-Content "$Etl.xml" -Raw
    foreach ($event in $x.Events.Event) {
        $d = @{}
        foreach ($e in @($event.EventData.Data)) {
            if ($e -and $e.Name) { $d[$e.Name] = "$($e.'#text')".Trim() }
        }
        if ($d['Msg'] -like '*home core*') { "$($d['rxCpu']) $($d['home'])" }
    }
}
