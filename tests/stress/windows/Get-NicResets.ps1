<#
.SYNOPSIS
    Report resets of the physical NIC during a run.

.DESCRIPTION
    A run where the machine's own network adapter resets looks exactly like a driver
    fault: traffic stops, clients time out, the sampler freezes and CPU sits at zero,
    because everything is blocked on a NIC that has stopped answering. It recovers a
    minute later with nothing in the run's own output to say why.

    Windows logs it, so read it. On EC2 the adapter is ENA, whose driver resets the
    device when its watchdog sees no keep-alive or finds packets stuck in a transmit
    queue; NDIS records the reset alongside it.

    Event 56001 is the reset request, 5007 the operation timeout that usually precedes
    it, and NDIS 10400 the reset itself.

    Event 5207 is the adapter holding a packet it cannot send. That is the same
    illness short of a reset: the machine goes off the network for a minute and comes
    back with no reset ever recorded, which reads as a driver that hung and recovered.
    Counted separately, because a stall is not a reset and the two say different things.

.EXAMPLE
    .\Get-NicResets.ps1 -Seconds 300
#>
[CmdletBinding()]
param(
    [int]$Minutes = 60,
    [int]$Seconds = 0,
    [switch]$AsJson
)

# -Seconds gives the caller an exact window. Rounded up to whole minutes it reaches back
# past the start of the run, and the previous run's reset is then reported as this one's.
$window = if ($Seconds -gt 0) { $Seconds } else { $Minutes * 60 }
$since = (Get-Date).AddSeconds(-$window)
# Two minutes before it are listed but not counted: a reset just outside the window says
# the adapter is unwell, which is worth seeing and is not this run's to answer for.
$margin = $since.AddSeconds(-120)
$ids = 56001, 5007, 10400
$stallIds = 5207

$events = @(Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'ena', 'Microsoft-Windows-NDIS'
        StartTime    = $margin
    } -ErrorAction SilentlyContinue | Where-Object { ($ids + $stallIds) -contains $_.Id } | Sort-Object TimeCreated)

# NDIS 10400 is the same reset as ena 56001 seen from the other side, so counting both
# would double it. Count 56001, unless only the NDIS record landed in the window.
$inWindow = @($events | Where-Object { $_.TimeCreated -ge $since })
$stalls = @($inWindow | Where-Object { $stallIds -contains $_.Id }).Count
$resets = @($inWindow | Where-Object { $_.Id -eq 56001 }).Count
$resets += @($inWindow | Where-Object {
        $e = $_
        $e.Id -eq 10400 -and -not ($events | Where-Object {
                $_.Id -eq 56001 -and [Math]::Abs(($_.TimeCreated - $e.TimeCreated).TotalSeconds) -le 10
            })
    }).Count

$line = {
    param($e)
    '{0:yyyy-MM-dd HH:mm:ss} {1} {2}' -f $e.TimeCreated, $e.Id, $e.Message.Split([char]10)[0].Trim()
}

if ($AsJson) {
    [pscustomobject]@{
        NicResets     = $resets
        NicStalls     = $stalls
        WindowSeconds = $window
        Events        = @($inWindow | ForEach-Object { & $line $_ })
        Before        = @($events | Where-Object { $_.TimeCreated -lt $since } | ForEach-Object { & $line $_ })
    } | ConvertTo-Json -Compress
    return
}

"nic resets: $resets, held packets: $stalls  (window: the last ${window}s)"
foreach ($e in $events) {
    $tag = if ($e.TimeCreated -lt $since) { '  (before the window, not counted)' } else { '' }
    '  {0:HH:mm:ss}  {1,-5}  {2}{3}' -f $e.TimeCreated, $e.Id, $e.Message.Split([char]10)[0].Trim(), $tag
}
