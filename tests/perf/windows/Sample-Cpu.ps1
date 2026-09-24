<#
.SYNOPSIS
    Sample every core while a measurement runs, and report the busiest.

.DESCRIPTION
    The driver has one transmit and one receive queue, so its datapath is one core's
    worth of work however many the machine has. On a sixteen core box a fully saturated
    datapath reads as six percent of the total, which is indistinguishable from an idle
    machine - and the total is all the rigs have ever sampled.

    So sample per core and report the busiest one, with its DPC share alongside: the
    receive path runs in a WSK callback at DISPATCH, where the time belongs to no process
    and shows up as DPC rather than as anything a task manager attributes.

    One CSV line per interval to stdout, so a run that ends badly still leaves its samples.

.EXAMPLE
    .\Sample-Cpu.ps1 -Seconds 120 -Interval 2
#>
[CmdletBinding()]
param(
    [int]$Seconds = 120,
    [int]$Interval = 2
)

$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture

# Get-Counter's paths are localised, this class is not
function Cores { Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor }

'elapsed,total_pct,busy_core,busy_pct,busy_dpc_pct'
$start = Get-Date
$deadline = $start.AddSeconds($Seconds)

while ((Get-Date) -lt $deadline) {
    $all = Cores
    $total = ($all | Where-Object Name -eq '_Total').PercentProcessorTime
    $busy = $all | Where-Object Name -ne '_Total' |
        Sort-Object PercentProcessorTime -Descending | Select-Object -First 1
    '{0:F0},{1:F0},{2},{3:F0},{4:F0}' -f ((Get-Date) - $start).TotalSeconds,
        $total, $busy.Name, $busy.PercentProcessorTime, $busy.PercentDPCTime
    [Console]::Out.Flush()
    Start-Sleep -Seconds $Interval
}
