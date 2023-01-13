param (
    [ValidateSet("x86", "x64", "arm64", "All")]
    [string]$Arch = "All",

    [string]$Wix = "C:\Program Files (x86)\WiX Toolset v3.14\"
)

$ProgramFilesDirs = @{
    "x86"="ProgramFilesFolder"
    "x64"="ProgramFiles64Folder"
    "arm64"="ProgramFiles64Folder"
}

function Build-Arch($BuildArch) {
    & "$WIX\bin\candle.exe" `
    -dPROGRAM_FILES_DIR="$($ProgramFilesDirs[$BuildArch])" `
    -dPRODUCT_NAME=OpenVPN ovpn-dco.wxs `
    -arch "$BuildArch"

    $plat = $BuildArch
    if ($BuildArch -eq "x64") {
        $plat = "amd64";
    }

    & "$WIX\bin\light.exe" `
        -sval ovpn-dco.wixobj `
        -b arch="$BuildArch" `
        -b ovpndco="dist\$BuildArch" `
        -out ovpn-dco-"$plat".msm

    # build sample installer
    & "$WIX\bin\candle.exe" `
        -dPROGRAM_FILES_DIR="$($ProgramFilesDirs[$BuildArch])" `
        -dPRODUCT_NAME=OpenVPN sampleinstaller.wxs `
        -dPRODUCT_PLATFORM="$plat" `
        -arch "$BuildArch"

    & "$WIX\bin\light.exe" `
        -sval sampleinstaller.wixobj `
        -b arch="$BuildArch" `
        -b ovpndco="dist\$BuildArch" `
        -out sampleinstaller-"$plat".msi
}

if ($Arch -eq "All") {
    Build-Arch x86
    Build-Arch x64
    Build-Arch arm64
} else {
    Build-Arch $Arch
}
