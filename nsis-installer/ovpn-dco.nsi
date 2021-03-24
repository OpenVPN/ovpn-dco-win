; ****************************************************************************
; * Copyright (C) 2002-2010 OpenVPN Technologies, Inc.                       *
; * Copyright (C)      2012 Alon Bar-Lev <alon.barlev@gmail.com>             *
; * Copyright (C)      2021 Lev Stipakov <lev@openvpn.net>                   *
; *  This program is free software; you can redistribute it and/or modify    *
; *  it under the terms of the GNU General Public License version 2          *
; *  as published by the Free Software Foundation.                           *
; ****************************************************************************

; ovpn-dco-win install script for Windows, using NSIS

SetCompressor /SOLID lzma

!addplugindir .
!include "MUI.nsh"
!include "StrFunc.nsh"
!include "wow.nsh"
!define MULTIUSER_EXECUTIONLEVEL Admin
!include "MultiUser.nsh"
!include FileFunc.nsh
!insertmacro GetParameters
!insertmacro GetOptions

${StrLoc}

;--------------------------------
;Configuration

;General

OutFile "ovpn-dco-installer-${PRODUCT_VERSION}.exe"

ShowInstDetails show
ShowUninstDetails show

;Remember install folder
InstallDirRegKey HKLM "SOFTWARE\ovpn-dco" ""

;--------------------------------
;Modern UI Configuration

Name "ovpn-dco ${PRODUCT_VERSION}"

!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ovpn-dco, a kernel driver to provide OpenVPN data channel offload functionality on Windows originally written by James Yonan.\r\n\r\nNote that ovpn-dco will only run on Windows Vista or later.\r\n\r\n\r\n"

!define MUI_COMPONENTSPAGE_TEXT_TOP "Select the components to install/upgrade.  Stop any ovpn-dco processes or the ovpn-dco service if it is running.  All DLLs are installed locally."

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "install-whirl.bmp"
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
;Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Language Strings

LangString DESC_SecDCO ${LANG_ENGLISH} "Install/Upgrade the OpenVPN Data Channel Offload virtual device driver.  Will not interfere with CIPE."
LangString DESC_SecDCOUtilities ${LANG_ENGLISH} "Install the DCO Utilities."

;--------------------------------
;Reserve Files

;Things that need to be extracted on first (keep these lines before any File command!)
;Only useful for BZIP2 compression

ReserveFile "install-whirl.bmp"

;--------------------------------
;Macros

!macro SelectByParameter SECT PARAMETER DEFAULT
	${GetOptions} $R0 "/${PARAMETER}=" $0
	${If} ${DEFAULT} == 0
		${If} $0 == 1
			!insertmacro SelectSection ${SECT}
		${EndIf}
	${Else}
		${If} $0 != 0
			!insertmacro SelectSection ${SECT}
		${EndIf}
	${EndIf}
!macroend

;--------------------------------
;Installer Sections

Section /o "OpenVPN Data Channel Offload" SecDCO

	SetOverwrite on

	${If} ${RunningX64}
		DetailPrint "We are running on an x86_64 64-bit system."

		SetOutPath "$INSTDIR\bin"
		File "amd64\devcon.exe"

		SetOutPath "$INSTDIR\driver"
		File "amd64\ovpn-dco.inf"
		File "amd64\ovpn-dco.cat"
		File "amd64\ovpn-dco.sys"
	${ElseIf} ${RunningArm64}
		DetailPrint "We are running on an ARM64 64-bit system."

		SetOutPath "$INSTDIR\bin"
		File "arm64\devcon.exe"

		SetOutPath "$INSTDIR\driver"
		File "arm64\ovpn-dco.inf"
		File "arm64\ovpn-dco.cat"
		File "arm64\ovpn-dco.sys"
	${Else}
		DetailPrint "Architecture not supported!"
	${EndIf}
SectionEnd

Function .onInit
	${GetParameters} $R0
	ClearErrors

${IfNot} ${AtLeastWin10}
	MessageBox MB_OK "This package requires at least Windows 10"
	SetErrorLevel 1
	Quit
${EndIf}

	!insertmacro SelectByParameter ${SecDCO} SELECT_DCO 1

	!insertmacro MULTIUSER_INIT
	SetShellVarContext all

	${If} ${RunningX64}
		SetRegView 64
		StrCpy $INSTDIR "$PROGRAMFILES64\ovpn-dco"
	${Else}
		StrCpy $INSTDIR "$PROGRAMFILES\ovpn-dco"
	${EndIf}
FunctionEnd

;--------------------
;Post-install section

Section -post

	; Store README, license, icon
	SetOverwrite on
	SetOutPath $INSTDIR
	File "icon.ico"

	${If} ${SectionIsSelected} ${SecDCO}
		;
		; install/upgrade DCO driver if selected, using devcon
		;
		; DCO install/update was selected.
		; Should we install or update?
		; If devcon error occurred, $R5 will
		; be nonzero.
		IntOp $R5 0 & 0
		nsExec::ExecToStack '"$INSTDIR\bin\devcon.exe" hwids ovpn-dco'
		Pop $R0 # return value/error/timeout
		IntOp $R5 $R5 | $R0
		DetailPrint "devcon.exe hwids returned: $R0"

		; If devcon output string contains "ovpn-dco" we assume
		; that DCO device has been previously installed,
		; therefore we will update, not install.
		Push "ovpn-dco"
		Push ">"
		Call StrLoc
		Pop $R0

		${If} $R5 == 0
			${If} $R0 == ""
				StrCpy $R1 "install"
			${Else}
				StrCpy $R1 "update"
			${EndIf}
			DetailPrint "DCO $R1 (ovpn-dco) (May require confirmation)"
			nsExec::ExecToLog '"$INSTDIR\bin\devcon.exe" $R1 "$INSTDIR\driver\ovpn-dco.inf" ovpn-dco'
			Pop $R0 # return value/error/timeout
			${If} $R0 == ""
				IntOp $R0 0 & 0
				SetRebootFlag true
				DetailPrint "REBOOT flag set"
			${EndIf}
			IntOp $R5 $R5 | $R0
			DetailPrint "devcon.exe returned: $R0"
		${EndIf}

		DetailPrint "devcon.exe cumulative status: $R5"
		${If} $R5 != 0
			MessageBox MB_OK "An error occurred installing the TAP device driver."
		${EndIf}

		; Store install folder in registry
		WriteRegStr HKLM SOFTWARE\ovpn-dco "" $INSTDIR
	${EndIf}

	; Create uninstaller
	WriteUninstaller "$INSTDIR\Uninstall.exe"

	; Show up in Add/Remove programs
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "DisplayName" "ovpn-dco ${PRODUCT_VERSION}"
	WriteRegExpandStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "UninstallString" "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "DisplayIcon" "$INSTDIR\icon.ico"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "DisplayVersion" "${PRODUCT_VERSION}"
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "NoModify" 1
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "NoRepair" 1
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "Publisher" "OpenVPN, Inc"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "HelpLink" "https://openvpn.net/index.php/open-source.html"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "URLInfoAbout" "https://openvpn.net"

	${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
	IntFmt $0 "0x%08X" $0
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco" "EstimatedSize" "$0"

SectionEnd

;--------------------------------
;Descriptions

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SecDCO} $(DESC_SecDCO)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Function un.onInit
	ClearErrors
	!insertmacro MULTIUSER_UNINIT
	SetShellVarContext all
	${If} ${RunningX64}
		SetRegView 64
	${EndIf}
FunctionEnd

Section "Uninstall"
	DetailPrint "DCO REMOVE"
	nsExec::ExecToLog '"$INSTDIR\bin\devcon.exe" remove ovpn-dco'
	Pop $R0 # return value/error/timeout
	DetailPrint "devcon.exe remove returned: $R0"

	Delete "$INSTDIR\bin\devcon.exe"
	Delete "$INSTDIR\bin\adddco.bat"
	Delete "$INSTDIR\bin\deldcoall.bat"

	Delete "$INSTDIR\driver\ovpn-dco.inf"
	Delete "$INSTDIR\driver\ovpn-dco.cat"
	Delete "$INSTDIR\driver\ovpn-dco.sys"

	Delete "$INSTDIR\icon.ico"
	Delete "$INSTDIR\Uninstall.exe"

	RMDir "$INSTDIR\bin"
	RMDir "$INSTDIR\driver"
	RMDir "$INSTDIR\include"
	RMDir "$INSTDIR"
	RMDir /r "$SMPROGRAMS\ovpn-dco"

	DeleteRegKey HKLM "SOFTWARE\ovpn-dco"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ovpn-dco"

SectionEnd
