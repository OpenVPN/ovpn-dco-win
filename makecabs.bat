rem This is supposed to be run under EWDK dev prompt

msbuild /p:Configuration=Release /p:Platform="x86"
msbuild /p:Configuration=Release-Win11 /p:Platform="x86"

msbuild /p:Configuration=Release /p:Platform="x64"
msbuild /p:Configuration=Release-Win11 /p:Platform="x64"

msbuild /p:Configuration=Release /p:Platform="arm64"
msbuild /p:Configuration=Release-Win11 /p:Platform="arm64"

copy ovpn-dco-win.ddf x86\Release&& cd x86\Release&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-x86-win10.cab&& cd ..\..
copy ovpn-dco-win.ddf x86\Release-Win11&& cd x86\Release-Win11&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-x86-win11.cab&& cd ..\..

copy ovpn-dco-win.ddf x64\Release&& cd x64\Release&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-x64-win10.cab&& cd ..\..
copy ovpn-dco-win.ddf x64\Release-Win11&& cd x64\Release-Win11&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-x64-win11.cab&& cd ..\..

copy ovpn-dco-win.ddf ARM64\Release&& cd ARM64\Release&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-arm64-win10.cab&& cd ..\..
copy ovpn-dco-win.ddf ARM64\Release-Win11&& cd ARM64\Release-Win11&& makecab -f ovpn-dco-win.ddf&& copy disk1\ovpn-dco-win.cab ..\..\ovpn-dco-win-arm64-win11.cab&& cd ..\..
