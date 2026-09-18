<#
.SYNOPSIS
    Record the driver's ETW events as a readable timeline, for triage rather than counting.

.DESCRIPTION
    Get-EpochRotations reduces a run to totals, which is what a verdict needs and useless
    once something has actually gone wrong. This keeps every event with its time, the
    function that logged it and the values it carried, so a failure can be placed against
    what the driver was doing either side of it.

    Written on the machine under test rather than streamed, because heavy load starves the
    control channel and a streamed capture dies with it.

.EXAMPLE
    .\Trace-Events.ps1 -Seconds 300 -OutFile C:\stage\timeline.txt
#>
[CmdletBinding()]
param(
    [int]$Seconds = 300,
    [string]$OutFile = 'C:\stage\timeline.txt'
)
$ErrorActionPreference = 'Continue'

$guid = '{4970f9cf-2c0c-4f11-b1cc-e3a1e9958833}'
$etl  = "$OutFile.etl"
$xml  = "$OutFile.xml"

logman stop ovpntrace -ets 2>$null | Out-Null
Remove-Item $etl, $xml, $OutFile -ErrorAction SilentlyContinue
logman create trace ovpntrace -ets -p $guid 0xffffffffffffffff 0xff -bs 128 -nb 64 1024 -o $etl 2>&1 | Out-Null
Start-Sleep -Seconds $Seconds
logman stop ovpntrace -ets 2>&1 | Out-Null

tracerpt $etl -o $xml -of XML -y 2>&1 | Out-Null
$t = Get-Content $xml -Raw

$lines = New-Object 'System.Collections.Generic.List[string]'
foreach ($m in [regex]::Matches($t, '(?s)<Event[^>]*>(?:(?!</Event>).)*?</Event>')) {
    $e = $m.Value
    $time = ([regex]'SystemTime="[^"]*T([^"Z]+)').Match($e).Groups[1].Value
    $func = ([regex]'<Data Name="Func">([^<]*)</Data>').Match($e).Groups[1].Value
    if (-not $func) { continue }
    $msg = ([regex]'<Data Name="Msg">([^<]*)</Data>').Match($e).Groups[1].Value
    # everything else the event carried, so peer ids and epochs come along
    $rest = @()
    foreach ($d in [regex]::Matches($e, '<Data Name="([^"]+)">([^<]*)</Data>')) {
        $n = $d.Groups[1].Value
        if ($n -in 'Func', 'Msg', 'Line') { continue }
        $rest += "$n=$($d.Groups[2].Value.Trim())"
    }
    $lines.Add(('{0}  {1,-28} {2} {3}' -f $time, $func, $msg, ($rest -join ' ')).TrimEnd())
}
$lines | Set-Content $OutFile

Remove-Item $etl, $xml -ErrorAction SilentlyContinue
"wrote $($lines.Count) events to $OutFile"
