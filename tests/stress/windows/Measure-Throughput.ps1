<#
.SYNOPSIS
    Sample what the driver is actually moving, while it moves it.

.DESCRIPTION
    OVPN_STATS cannot be read during a run, because OpenVPN holds the device exclusively,
    so a run can only ever show a before and after total. That hides the shape of the
    traffic: a stall halfway through and a steady load average out to the same number.

    The adapter's own counters are readable at any time, so sample those instead. One CSV
    line per interval goes to stdout as it is taken, which means a run that ends in a
    bugcheck still leaves every sample up to the moment the machine stopped answering.

    Rates are per interval, not since boot, and are reported in Mbit/s to match iperf3.
    CPU is sampled alongside, because throughput on its own does not say whether there is
    headroom to push the load harder.

.EXAMPLE
    .\Measure-Throughput.ps1 -Seconds 900 -Interval 5
#>
[CmdletBinding()]
param(
    [int]$Seconds = 900,
    [int]$Interval = 5
)

$ErrorActionPreference = 'Stop'
# so the CSV does not pick up thousand separators or a comma decimal point
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture

$if = Get-NetAdapter | Where-Object InterfaceDescription -Match 'OpenVPN Data Channel Offload'
if (-not $if) { Write-Error 'no ovpn-dco adapter'; exit 1 }

function Sample {
    $s = Get-NetAdapterStatistics -Name $if.Name
    [pscustomobject]@{
        Time = Get-Date
        Rx   = $s.ReceivedBytes
        Tx   = $s.SentBytes
    }
}

# Get-Counter's paths are localised, this class is not
function Cpu {
    (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
}

'elapsed,rx_mbit,tx_mbit,cpu_pct'
$start = Get-Date
$prev = Sample
$deadline = $start.AddSeconds($Seconds)

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $Interval
    $now = Sample
    $secs = ($now.Time - $prev.Time).TotalSeconds
    if ($secs -gt 0) {
        '{0:F0},{1:F1},{2:F1},{3:F0}' -f ($now.Time - $start).TotalSeconds,
            (($now.Rx - $prev.Rx) * 8 / $secs / 1e6),
            (($now.Tx - $prev.Tx) * 8 / $secs / 1e6),
            (Cpu)
        [Console]::Out.Flush()
    }
    $prev = $now
}
