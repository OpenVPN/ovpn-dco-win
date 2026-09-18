<#
.SYNOPSIS
    Set or clear TestAeadUsageLimit and Driver Verifier on the device under test.

.DESCRIPTION
    -Arm sets the checked-build AEAD usage cap so epoch keys rotate every few hundred
    packets, and turns on Driver Verifier special pool plus deadlock detection.

    NetAdapterCx and NDIS are verified alongside ovpn-dco: verifying the client driver
    alone lets Driver Verifier report false NDIS rule violations.

    Both settings take effect at the next boot, so reboot before running a test.

.EXAMPLE
    .\Set-TestMode.ps1 -Arm
    .\Set-TestMode.ps1 -Disarm
    .\Set-TestMode.ps1 -Show
#>
[CmdletBinding()]
param(
    [switch]$Arm,
    [switch]$Disarm,
    [switch]$Show,
    # The limit is compared against plaintext blocks plus packet id, so at a 1390-byte
    # MTU a packet costs about 88 of it. Measured: 2,000,000 gave 327 rotations and 2206
    # receivers that had fallen past the four future keys the driver holds, which leaves
    # them deaf until the session renegotiates. 8,000,000 trades some of that rate for
    # four times the slack: roughly 80 rotations a run, still plenty to exercise both
    # rotation paths, and a receiver can miss minutes rather than seconds.
    [uint32]$AeadUsageLimit = 8000000
)

$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\ovpn-dco\Parameters'
# 0x1 special pool + 0x20 deadlock detection
# 0x1 special pool, 0x8 pool tracking, 0x20 deadlock detection
$verifierFlags = '0x29'
$drivers = 'ovpn-dco.sys', 'netadaptercx.sys', 'ndis.sys'

if ($Show) {
    $knob = (Get-ItemProperty $paramKey -Name TestAeadUsageLimit -ErrorAction SilentlyContinue).TestAeadUsageLimit
    "TestAeadUsageLimit: $(if ($null -ne $knob) { $knob } else { '(not set)' })"
    verifier /query 2>&1 | Select-String 'MODULE:|Verifier Flags'
    return
}

if ($Arm) {
    New-Item -Path $paramKey -Force | Out-Null
    Set-ItemProperty -Path $paramKey -Name TestAeadUsageLimit -Type DWord -Value $AeadUsageLimit
    verifier /flags $verifierFlags /driver $drivers | Out-Null
    "set: TestAeadUsageLimit=$AeadUsageLimit, verifier flags=$verifierFlags on $($drivers -join ', ')"
    'reboot required'
    return
}

if ($Disarm) {
    Remove-ItemProperty -Path $paramKey -Name TestAeadUsageLimit -ErrorAction SilentlyContinue
    verifier /reset | Out-Null
    'cleared: TestAeadUsageLimit removed, verifier reset'
    'reboot required'
    return
}

throw 'specify -Arm, -Disarm or -Show'
