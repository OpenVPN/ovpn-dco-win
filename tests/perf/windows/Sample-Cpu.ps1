<#
.SYNOPSIS
    Sample every core while a measurement runs, and report the busiest.

.DESCRIPTION
    The driver has one transmit and one receive queue, so its datapath is one core's
    worth of work however many the machine has. On a sixteen core box a fully saturated
    datapath reads as six percent of the total, which is indistinguishable from an idle
    machine - and the total is all the rigs have ever sampled.

    So sample per core, and keep every core rather than only the busiest: with the
    transmit fan-out the question is no longer how hot one core is but how many are
    working at all, which a single busiest-core column cannot answer. The DPC share
    comes with each, because the receive path runs in a WSK callback at DISPATCH, where
    the time belongs to no process and shows up as DPC rather than as anything a task
    manager attributes.

    One CSV line per core per interval to stdout, including the _Total pseudo-core, so a
    run that ends badly still leaves its samples.

    -StopFile ends sampling as soon as that file exists, so the samples cover one
    measurement and a sampler never runs on into the next test; -Seconds stays a cap.

.EXAMPLE
    .\Sample-Cpu.ps1 -Seconds 120 -Interval 2 -StopFile C:\ovpn-perf\cpu.stop
#>
[CmdletBinding()]
param(
    [int]$Seconds = 120,
    [int]$Interval = 2,
    [string]$StopFile
)

$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture

# Get-Counter's paths are localised, this class is not
function Cores { Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor }

'elapsed,core,pct,dpc_pct'
$start = Get-Date
$deadline = $start.AddSeconds($Seconds)

while ((Get-Date) -lt $deadline) {
    if ($StopFile -and (Test-Path $StopFile)) { break }
    $elapsed = ((Get-Date) - $start).TotalSeconds
    foreach ($c in Cores) {
        '{0:F0},{1},{2:F0},{3:F0}' -f $elapsed, $c.Name, $c.PercentProcessorTime, $c.PercentDPCTime
    }
    [Console]::Out.Flush()
    Start-Sleep -Seconds $Interval
}
