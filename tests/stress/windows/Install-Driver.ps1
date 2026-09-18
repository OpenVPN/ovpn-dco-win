<#
.SYNOPSIS
    Install a driver package on the device under test and verify the running image.

.DESCRIPTION
    Uses pnputil only, which ships with Windows. pnputil updates the driver on an
    existing ovpn-dco device node but does not create one, so the machine must already
    have a DCO adapter (install OpenVPN with the DCO adapter once beforehand).

    Installing a package does not always replace the running image, so this compares the
    PE timestamp of the loaded driver against the package you asked for and fails if they
    differ. A stale image invalidates a test run with nothing to show for it.

.EXAMPLE
    .\Install-Driver.ps1 -InfPath C:\stage\ovpn-dco.inf
    .\Install-Driver.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$InfPath,
    [switch]$Remove
)

function Get-PeTimestamp([string]$Path) {
    $b = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    '0x{0:X8}' -f [BitConverter]::ToUInt32($b, $pe + 8)
}

$loadedPath = "$env:SystemRoot\System32\drivers\ovpn-dco.sys"

if ($Remove) {
    $oems = pnputil /enum-drivers |
            Select-String -Context 1,0 'ovpn-dco.inf' |
            ForEach-Object { ($_.Context.PreContext -join '') -replace '.*:\s*', '' }
    foreach ($oem in $oems) {
        "removing $oem"
        pnputil /delete-driver $oem /uninstall /force | Select-String 'success|fail|error'
    }
    'a reboot is required before the removal takes full effect'
    return
}

if (-not $InfPath) { throw 'specify -InfPath <ovpn-dco.inf> or -Remove' }
if (-not (Test-Path $InfPath)) { throw "no such file: $InfPath" }

$sysPath = Join-Path (Split-Path -Parent $InfPath) 'ovpn-dco.sys'
if (-not (Test-Path $sysPath)) { throw "ovpn-dco.sys not found next to $InfPath" }

$existing = Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
            Where-Object { $_.FriendlyName -like '*OpenVPN Data Channel*' }
if (-not $existing) {
    throw 'no ovpn-dco device node present; install OpenVPN with the DCO adapter first'
}

"installing $InfPath onto $($existing.Count) device node(s)"
pnputil /add-driver $InfPath /install | Select-String 'success|fail|error|Published'
Start-Sleep 3

$want = Get-PeTimestamp $sysPath
$got  = Get-PeTimestamp $loadedPath
"staged $want   loaded $got"
if ($want -ne $got) {
    throw "loaded image does not match the package just installed; a stale driver is running"
}
'loaded image matches the staged package'
