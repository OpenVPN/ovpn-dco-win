<#
.SYNOPSIS
    Count epoch key rotations in the driver over a sampling window.

.DESCRIPTION
    Nothing in OVPN_STATS counts rotations, or decryption failures, so without this a run
    can neither show that the epoch paths were exercised rather than merely enabled, nor
    that constant rotation never broke decryption. This captures the driver's own ETW
    events for the length of the run and counts them.

    Decryption failures are counted by the function that reports them. Everything
    OvpnCryptoDecryptAEAD logs is a failure, so this does not depend on message wording.

    Needs the WPR profile shipped at the repository root (ovpn-dco-win.wprp), staged
    alongside these scripts.

.EXAMPLE
    .\Get-EpochRotations.ps1 -Seconds 8 -AsJson
#>
[CmdletBinding()]
param(
    [int]$Seconds = 8,
    [string]$OutFile = '',
    [string]$Profile = '',
    [string]$WorkDir = "$env:TEMP\ovpn-stress",
    [switch]$AsJson
)

if (-not $Profile) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $Profile = Join-Path $base 'ovpn-dco-win.wprp'
}
if (-not (Test-Path $Profile)) {
    Write-Error "WPR profile not found: $Profile"
    exit 1
}

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$etl = Join-Path $WorkDir 'epoch.etl'
$xml = Join-Path $WorkDir 'epoch.xml'

wpr -cancel 2>$null | Out-Null
wpr -start $Profile -filemode
Start-Sleep -Seconds $Seconds
wpr -stop $etl 2>&1 | Out-Null
tracerpt $etl -o $xml -of XML -y 2>&1 | Out-Null

if (-not (Test-Path $xml)) {
    Write-Error 'ETW capture produced no decodable output'
    exit 1
}
$text = Get-Content $xml -Raw

$result = [pscustomobject]@{
    WindowSeconds   = $Seconds
    TotalEvents     = ([regex]::Matches($text, '<Event ')).Count
    # receive-side rotation: the peer moved to an epoch we had not seen yet
    RecvRotations   = ([regex]::Matches($text, 'new epoch', 'IgnoreCase')).Count
    # one per derived data key: future-key generation and send-key rotation
    KeyDerivations  = ([regex]::Matches($text, 'Epoch Data Key', 'IgnoreCase')).Count
    # every one of these is a packet the driver could not decrypt
    DecryptErrors   = ([regex]::Matches($text, '<Data Name="Func">OvpnCryptoDecrypt')).Count
    # and why, so a count is something you can act on
    NoKeyForKeyId   = ([regex]::Matches($text, 'No key for KeyId')).Count
    UnknownEpoch    = ([regex]::Matches($text, 'unknown epoch')).Count
    InvalidPacketId = ([regex]::Matches($text, 'Invalid packet_id')).Count
    InvalidEpoch0   = ([regex]::Matches($text, 'Invalid epoch 0')).Count
    PacketTooShort  = ([regex]::Matches($text, 'Packet too short')).Count

    # The route trie. A route leaves it two ways: userspace deleting it, and the peer
    # being torn down, which goes through RemoveByPeerId and logs nothing about routes.
    # Counting only the first made inserts and deletes look wildly unbalanced, so count
    # by the function that logs, the way decryption failures are counted.
    IrouteAdds      = ([regex]::Matches($text, 'Add IPV[46] iroute')).Count
    IrouteDels      = ([regex]::Matches($text, 'Delete IPV[46] iroute')).Count
    TrieInserts     = ([regex]::Matches($text, '<Data Name="Func">(IPTrie::)?Insert<')).Count
    TrieRemovals    = ([regex]::Matches($text, '<Data Name="Func">(IPTrie::)?RemoveByPeerId<')).Count
    # an insert that took a prefix a live peer still held, so the old reference was
    # dropped after the lock was released
    TrieHandovers   = ([regex]::Matches($text, 'Release previous peer')).Count
}

Remove-Item $etl, $xml -ErrorAction SilentlyContinue
if ($OutFile) { $result | ConvertTo-Json -Compress | Set-Content $OutFile }
elseif ($AsJson) { $result | ConvertTo-Json -Compress } else { $result }
