<#
.SYNOPSIS
    Trust the certificate that signed a driver, so a test-signed build can load.

.DESCRIPTION
    Test signing on its own is not enough: the signing certificate still has to chain to a
    trusted root, otherwise the driver store rejects the package with 0x800b0109,
    "terminated in a root certificate which is not trusted".

    Importing the certificate from the build being tested, rather than baking one into the
    machine image, keeps the image stable if CI's signing certificate ever rotates.

.EXAMPLE
    .\Trust-DriverCert.ps1 -SysPath C:\stage\ovpn-dco.sys
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SysPath)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $SysPath)) { throw "no such file: $SysPath" }

$cert = (Get-AuthenticodeSignature $SysPath).SignerCertificate
if (-not $cert) { throw "$SysPath is not signed" }

$cer = Join-Path ([IO.Path]::GetDirectoryName($SysPath)) 'signing.cer'
Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
foreach ($store in 'Root', 'TrustedPublisher') {
    Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
}
"trusted $($cert.Subject) [$($cert.Thumbprint)]"
