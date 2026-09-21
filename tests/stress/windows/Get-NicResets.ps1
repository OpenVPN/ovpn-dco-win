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

.EXAMPLE
    .\Get-NicResets.ps1 -Minutes 30
#>
[CmdletBinding()]
param(
    [int]$Minutes = 60,
    [switch]$AsJson
)

$since = (Get-Date).AddMinutes(-$Minutes)
$ids = 56001, 5007, 10400

$events = @(Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'ena', 'Microsoft-Windows-NDIS'
        StartTime    = $since
    } -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.Id } | Sort-Object TimeCreated)

$resets = @($events | Where-Object { $_.Id -eq 56001 }).Count

if ($AsJson) {
    [pscustomobject]@{
        NicResets = $resets
        Window    = $Minutes
        Events    = @($events | ForEach-Object {
                '{0:yyyy-MM-dd HH:mm:ss} {1} {2}' -f $_.TimeCreated, $_.Id, $_.Message.Split([char]10)[0].Trim()
            })
    } | ConvertTo-Json -Compress
    return
}

"nic resets in the last $Minutes minutes: $resets"
foreach ($e in $events) {
    '  {0:HH:mm:ss}  {1,-5}  {2}' -f $e.TimeCreated, $e.Id, $e.Message.Split([char]10)[0].Trim()
}
