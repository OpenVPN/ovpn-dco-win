<#
.SYNOPSIS
    Arm Driver Verifier, drive the ioctl surface, and report.

.DESCRIPTION
    The harness only reports what the driver returned. The verdict comes from the machine:
    that it is still answering afterwards, that Driver Verifier found nothing, and that the
    driver unloads cleanly at the end — pool tracking only reports leaks there.

    -Arm sets the flags this rig wants and needs a reboot before they take effect. Note
    they differ from the stress rig's: DDI compliance checking is on here, because calling
    ioctls from several threads is where DDI and IRQL misuse shows up, and pool tracking is
    on because a run creates over a million peers.

    All three of ovpn-dco.sys, netadaptercx.sys and ndis.sys are verified together.
    Verifying the client without Cx makes NetAdapterCx report false NDIS rule violations,
    and it says so on the debugger before it breaks.

.EXAMPLE
    .\Run-IoctlStress.ps1 -Arm      # then reboot
    .\Run-IoctlStress.ps1 -Run -Seconds 120
    .\Run-IoctlStress.ps1 -Unload   # force the driver out so leaks are reported
    .\Run-IoctlStress.ps1 -Disarm   # then reboot
#>
[CmdletBinding()]
param(
    [switch]$Arm,
    [switch]$Disarm,
    [switch]$Run,
    [switch]$Unload,
    [int]$Seconds = 60,
    [int]$Port = 11199,
    [string]$Exe = 'C:\ovpn-ioctl\ovpn-ioctl-test.exe'
)

$ErrorActionPreference = 'Stop'

# special pool (0x1) + pool tracking (0x8) + deadlock detection (0x20) + DDI compliance (0x20000)
$verifierFlags = '0x20029'
$drivers = 'ovpn-dco.sys', 'netadaptercx.sys', 'ndis.sys'

if ($Arm) {
    verifier /flags $verifierFlags /driver $drivers | Out-Null
    "armed: verifier flags=$verifierFlags on $($drivers -join ', ')"
    'reboot required'
    return
}

if ($Disarm) {
    verifier /reset | Out-Null
    'verifier reset'
    'reboot required'
    return
}

if ($Unload) {
    # Pool tracking reports at unload and nowhere else, so take the device down and bring
    # it back. If the driver leaked, Verifier bugchecks here and the machine goes quiet —
    # which is the same signal as any other fault.
    $dev = Get-PnpDevice -FriendlyName '*Data Channel Offload*' -ErrorAction SilentlyContinue
    if (-not $dev) { throw 'no ovpn-dco device to unload' }
    Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
    Start-Sleep 5
    Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
    Start-Sleep 5
    'driver unloaded and reloaded'
    return
}

if (-not $Run) { throw 'specify -Arm, -Disarm, -Run or -Unload' }
if (-not (Test-Path $Exe)) { throw "no harness at $Exe" }

# The device is exclusive, so anything else holding it makes every mode fail at the open.
Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$flags = (verifier /query 2>&1 | Select-String 'Verifier Flags') -join ''
"verifier: $($flags -replace '\s+', ' ')"
if ($flags -notmatch '20029') {
    Write-Warning "verifier is not armed as this rig expects; run -Arm and reboot"
}

# Ordered cheapest first: a mode that cannot even open the device should say so before
# five minutes of churn does.
$modes = @(
    @{ Name = 'unknown';     Args = @('--mode', 'unknown') }
    @{ Name = 'mutate';      Args = @('--mode', 'mutate') }
    @{ Name = 'mutate-p2p';  Args = @('--mode', 'mutate-p2p') }
    @{ Name = 'churn';       Args = @('--mode', 'churn', '--seconds', "$Seconds", '--port', "$Port") }
)

$failed = @()
foreach ($m in $modes) {
    "== $($m.Name)"
    & $Exe @($m.Args)
    if ($LASTEXITCODE -ne 0) { $failed += $m.Name }
}

if ($failed.Count -gt 0) {
    throw "modes failed: $($failed -join ', ')"
}
'all modes completed'
