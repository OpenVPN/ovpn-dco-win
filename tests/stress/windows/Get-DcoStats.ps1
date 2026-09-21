<#
.SYNOPSIS
    Read OVPN_STATS from every ovpn-dco device, without a compiled helper.

.DESCRIPTION
    The P/Invoke is compiled in memory by .NET at run time, so the rig ships no binaries.

    OpenVPN opens the DCO device exclusively, so this returns data only when no OpenVPN
    instance is holding the adapter. Stop OpenVPN first; the counters live in the device
    and survive the handle being closed.

.EXAMPLE
    .\Get-DcoStats.ps1
    .\Get-DcoStats.ps1 -AsJson
#>
[CmdletBinding()]
param([switch]$AsJson)

Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DcoNative {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inSize,
        byte[] outBuf, uint outSize, out uint returned, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    const uint GENERIC_READ   = 0x80000000;
    const uint SHARE_RW       = 0x00000003;
    const uint OPEN_EXISTING  = 3;
    // CTL_CODE(FILE_DEVICE_UNKNOWN = 0x22, function, METHOD_BUFFERED, FILE_ANY_ACCESS)
    public const uint IOCTL_GET_STATS   = (0x22 << 16) | (2 << 2);
    public const uint IOCTL_GET_VERSION = (0x22 << 16) | (8 << 2);

    public static byte[] Query(string path, uint ioctl, int size) {
        IntPtr h = CreateFileW(path, GENERIC_READ, SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) { return null; }
        try {
            byte[] buf = new byte[size];
            uint got;
            if (!DeviceIoControl(h, ioctl, IntPtr.Zero, 0, buf, (uint)size, out got, IntPtr.Zero)) { return null; }
            return buf;
        } finally { CloseHandle(h); }
    }
}
'@

# The net device interface path is derivable from the PnP instance id, so there is no
# need to walk SetupDi: \\?\ROOT#NET#0000#{cac88484-...}
$netGuid = '{cac88484-7515-4c03-82e6-71a87abac361}'
$results = @()

foreach ($dev in Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
                 Where-Object { $_.FriendlyName -like '*OpenVPN Data Channel*' }) {
    $path = '\\?\' + ($dev.InstanceId -replace '\\', '#') + '#' + $netGuid
    $ver = [DcoNative]::Query($path, [DcoNative]::IOCTL_GET_VERSION, 12)
    if ($null -eq $ver) { continue }
    $s = [DcoNative]::Query($path, [DcoNative]::IOCTL_GET_STATS, 64)
    if ($null -eq $s) { continue }

    # OVPN_STATS: 8 x LONG then 4 x LONG64 (see uapi/ovpn-dco.h)
    $results += [pscustomobject]@{
        Device                = $dev.InstanceId
        Version               = '{0}.{1}.{2}' -f [BitConverter]::ToInt32($ver,0),
                                                 [BitConverter]::ToInt32($ver,4),
                                                 [BitConverter]::ToInt32($ver,8)
        LostInControl         = [BitConverter]::ToInt32($s,  0)
        LostOutControl        = [BitConverter]::ToInt32($s,  4)
        LostInData            = [BitConverter]::ToInt32($s,  8)
        LostOutData           = [BitConverter]::ToInt32($s, 12)
        ReceivedData          = [BitConverter]::ToInt32($s, 16)
        ReceivedControl       = [BitConverter]::ToInt32($s, 20)
        SentControl           = [BitConverter]::ToInt32($s, 24)
        SentData              = [BitConverter]::ToInt32($s, 28)
        TransportBytesSent    = [BitConverter]::ToInt64($s, 32)
        TransportBytesReceived= [BitConverter]::ToInt64($s, 40)
        TunBytesSent          = [BitConverter]::ToInt64($s, 48)
        TunBytesReceived      = [BitConverter]::ToInt64($s, 56)
    }
}

if ($results.Count -eq 0) {
    Write-Error 'no ovpn-dco device answered GET_STATS (is OpenVPN holding the adapter?)'
    exit 1
}
if ($AsJson) { $results | ConvertTo-Json -Compress } else { $results }
