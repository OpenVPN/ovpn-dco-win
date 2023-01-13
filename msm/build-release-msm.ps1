param (
    [string]$TAG = "0.8.3"
)

Remove-Item -Path tmp -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path dist -Recurse -ErrorAction SilentlyContinue

New-Item -Path tmp -type directory -Force

foreach ($arch in $("amd64", "arm64", "x86")) {
    Invoke-WebRequest -Uri "https://github.com/OpenVPN/ovpn-dco-win/releases/download/$TAG/ovpn-dco-win-$TAG-$arch.zip" -OutFile tmp\$arch.zip
    Expand-Archive -Path tmp\$arch.zip -DestinationPath dist\$arch -Force
}

New-Item -Path dist -type directory -Force

Rename-Item $PWD\dist\amd64 $PWD\dist\x64

.\build.ps1
