/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2023 OpenVPN Inc <sales@openvpn.net>
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <Windows.h>

#include <devguid.h>
#include <Msi.h>
#include <msiquery.h>
#include <newdev.h>
#include <objbase.h>
#include <shlwapi.h>
#include <SetupAPI.h>

#include <stdio.h>

#include "log.h"

#define FILE_NEED_REBOOT        L".ovpn_need_reboot"

// this must match <Package Id= in ovpn-dco.wxs with "-" replaced by "_"
#define PACKAGE_ID              "1057B5BE_89F7_469C_A3FD_D6662CD1D229"

#define CMP_OVPN_DCO_INF        L"CMP_ovpn_dco.inf." PACKAGE_ID
#define OVPNDCO_PROP            L"OVPNDCO." PACKAGE_ID

#define ACTION_ADD_DRIVER       L"AddDriver"
#define ACTION_DELETE_DRIVER    L"DeleteDriver"
#define ACTION_NOOP             L"Noop"
#define FILE_OVPN_DCO_INF       L"ovpn-dco.inf"
#define OVPN_DCO_HWID           L"ovpn-dco"

#define ACTION_LEN              0x400

static BOOL
IsInstalling(_In_ INSTALLSTATE InstallState, _In_ INSTALLSTATE ActionState)
{
    return INSTALLSTATE_LOCAL == ActionState || INSTALLSTATE_SOURCE == ActionState
        || (INSTALLSTATE_DEFAULT == ActionState
            && (INSTALLSTATE_LOCAL == InstallState || INSTALLSTATE_SOURCE == InstallState));
}

static BOOL
IsReInstalling(_In_ INSTALLSTATE InstallState, _In_ INSTALLSTATE ActionState)
{
    return (INSTALLSTATE_LOCAL == ActionState || INSTALLSTATE_SOURCE == ActionState
        || INSTALLSTATE_DEFAULT == ActionState)
        && (INSTALLSTATE_LOCAL == InstallState || INSTALLSTATE_SOURCE == InstallState);
}

static BOOL
IsUninstalling(_In_ INSTALLSTATE InstallState, _In_ INSTALLSTATE ActionState)
{
    return (INSTALLSTATE_ABSENT == ActionState || INSTALLSTATE_REMOVED == ActionState)
        && (INSTALLSTATE_LOCAL == InstallState || INSTALLSTATE_SOURCE == InstallState);
}


/**
 * Create empty file in user's temp directory. The existence of this file
 * is checked in the end of installation by ScheduleReboot immediate custom action
 * which schedules reboot.
 *
 * @param szTmpDir path to user's temp dirctory
 *
 */
static void
CreateRebootFile(_In_z_ LPCWSTR szTmpDir)
{
    WCHAR path[MAX_PATH];
    swprintf_s(path, _countof(path), L"%s%s", szTmpDir, FILE_NEED_REBOOT);

    msg(M_WARN, "%s: Reboot required, create reboot indication file \"%ls\"", __FUNCTION__, path);

    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        msg(M_NONFATAL | M_ERRNO, "%s: CreateFile(\"%ls\") failed", __FUNCTION__, path);
    }
    else {
        CloseHandle(file);
    }
}

static UINT
MsiGetString(MSIHANDLE hInstall, LPCWSTR name, LPWSTR *value)
{
    DWORD len = 0;
    UINT res = MsiGetProperty(hInstall, name, TEXT(""), &len);
    if (res != ERROR_MORE_DATA) {
        SetLastError(res);
        msg(M_NONFATAL | M_ERRNO, "%s: MsiGetProperty failed", __FUNCTION__);
        return res;
    }

    *value = malloc(++len * sizeof(WCHAR));
    if (*value == NULL) {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, len * sizeof(WCHAR));
        return ERROR_OUTOFMEMORY;
    }
    
    res = MsiGetProperty(hInstall, name, *value, &len);
    if (res != ERROR_SUCCESS)
        free(*value);

    return res;
}

// figure out what to do with the driver - install, uninstall, nothing
UINT __stdcall
MsiEvaluate(MSIHANDLE handle)
{
    BOOL coInitialsed = SUCCEEDED(CoInitialize(NULL));

    OVPNDCO_SAVE_MSI_SESSION(handle);

    WCHAR pathToInf[MAX_PATH];
    DWORD pathLen = _countof(pathToInf);

    INSTALLSTATE InstallState, ActionState;
    UINT ret = MsiGetComponentState(handle, CMP_OVPN_DCO_INF, &InstallState, &ActionState);
    if (ret != ERROR_SUCCESS) {
        SetLastError(ret);
        msg(M_NONFATAL | M_ERRNO, "%s: MsiGetComponentState(\"%ls\") failed", __FUNCTION__, CMP_OVPN_DCO_INF);
        goto cleanup;
    }

    /* get user-specific temp path, to where we create reboot indication file */
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    ret = MsiGetProperty(handle, OVPNDCO_PROP, pathToInf, &pathLen);
    if (ret != ERROR_SUCCESS) {
        SetLastError(ret);
        msg(M_NONFATAL | M_ERRNO, "%s: MsiGetProperty failed", __FUNCTION__);
        goto cleanup;
    }

    WCHAR action[ACTION_LEN];
    if ((IsReInstalling(InstallState, ActionState) || IsInstalling(InstallState, ActionState))) {
        swprintf_s(action, _countof(action), L"%s|%s%s|%s", ACTION_ADD_DRIVER, pathToInf, FILE_OVPN_DCO_INF, tempPath);
    }
    else if (IsUninstalling(InstallState, ActionState)) {
        swprintf_s(action, _countof(action), L"%s|%s%s|%s", ACTION_DELETE_DRIVER, pathToInf, FILE_OVPN_DCO_INF, tempPath);
    }
    else {
        swprintf_s(action, _countof(action), L"%s||", ACTION_NOOP);
    }

    ret = MsiSetProperty(handle, L"OvpnDco_Process", action);

cleanup:
    if (coInitialsed) {
        CoUninitialize();
    }
    return ret;
}

static void
AddDriver(_In_z_ LPCWSTR pathToInf, _In_z_ LPCWSTR pathToTmp)
{
    /* copy driver to driver store */
    if (!SetupCopyOEMInfW(pathToInf, NULL, SPOST_PATH, 0, NULL, 0, NULL, NULL)) {
        msg(M_NONFATAL | M_ERRNO, "%s: SetupCopyOEMInf(\"%ls\") failed", __FUNCTION__, pathToInf);
        return;
    }

    /* update driver for existing devices (if any) */
    BOOL rebootRequired = FALSE;
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, OVPN_DCO_HWID, pathToInf, INSTALLFLAG_NONINTERACTIVE | INSTALLFLAG_FORCE, &rebootRequired)) {
        /* ERROR_NO_SUCH_DEVINST means that no devices exist, which is normal case - device (adapter) is created at later stage */
        if (GetLastError() != ERROR_NO_SUCH_DEVINST) {
            msg(M_NONFATAL | M_ERRNO, "%s: UpdateDriverForPlugAndPlayDevices(\"%ls\", \"%ls\") failed", __FUNCTION__, OVPN_DCO_HWID, pathToInf);
            return;
        }
    }

    if (rebootRequired) {
        CreateRebootFile(pathToTmp);
    }
}

static BOOL
GetPublishedDriverName(_In_z_ LPCWSTR hwid, _Out_writes_z_(len) LPWSTR publishedName, _In_ DWORD len)
{
    wcscpy_s(publishedName, len, L"");

    HDEVINFO devInfoSet = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!devInfoSet) {
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetClassDevsW failed", __FUNCTION__);
        return FALSE;
    }
    BOOL res = FALSE;
    if (!SetupDiBuildDriverInfoList(devInfoSet, NULL, SPDIT_CLASSDRIVER)) {
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiBuildDriverInfoList failed", __FUNCTION__);
        goto cleanupDeviceInfoSet;
    }
    for (DWORD idx = 0;; ++idx) {
        SP_DRVINFO_DATA_W drvInfo = { .cbSize = sizeof(drvInfo) };
        if (!SetupDiEnumDriverInfoW(devInfoSet, NULL, SPDIT_CLASSDRIVER, idx, &drvInfo)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                break;
            }
            msg(M_NONFATAL | M_ERRNO, "%s: SetupDiEnumDriverInfoW failed", __FUNCTION__);
            goto cleanupDriverInfoList;
        }
        DWORD size;
        if (SetupDiGetDriverInfoDetailW(devInfoSet, NULL, &drvInfo, NULL, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetDriverInfoDetailW failed", __FUNCTION__);
            goto cleanupDriverInfoList;
        }
        PSP_DRVINFO_DETAIL_DATA_W drvDetails = calloc(1, size);
        if (!drvDetails) {
            msg(M_NONFATAL, "%s: calloc(1, %u) failed", __FUNCTION__, size);
            goto cleanupDriverInfoList;
        }
        drvDetails->cbSize = sizeof(*drvDetails);
        if (!SetupDiGetDriverInfoDetailW(devInfoSet, NULL, &drvInfo, drvDetails, size, &size)) {
            msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetDriverInfoDetailW failed", __FUNCTION__);
            free(drvDetails);
            goto cleanupDriverInfoList;
        }
        if (wcscmp(hwid, drvDetails->HardwareID) == 0) {
            PathStripPathW(drvDetails->InfFileName);
            wcscpy_s(publishedName, len, drvDetails->InfFileName);
            free(drvDetails);
            res = TRUE;
            break;
        }
        free(drvDetails);
    }

cleanupDriverInfoList:
    SetupDiDestroyDriverInfoList(devInfoSet, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(devInfoSet);

    return res;
}

static void
DeleteDriver(_In_z_ LPCWSTR pathToTmp)
{
    /* delete driver */
    WCHAR publishedName[MAX_PATH] = { 0 };
    if (GetPublishedDriverName(OVPN_DCO_HWID, publishedName, _countof(publishedName))) {
        if (!SetupUninstallOEMInfW(publishedName, 0, NULL)) {
            msg(M_NONFATAL | M_ERRNO, "%s: SetupUninstallOEMInfW(\"%ls\") failed", __FUNCTION__, publishedName);
        }
    }
}

UINT __stdcall
MsiProcess(MSIHANDLE handle)
{
    BOOL coInitialsed = SUCCEEDED(CoInitialize(NULL));

    LPWSTR customData = NULL;
    UINT res = MsiGetString(handle, L"CustomActionData", &customData);
    if (res != ERROR_SUCCESS) {
        goto cleanup;
    }

    int i = 0;
    WCHAR action[ACTION_LEN] = { 0 };
    WCHAR pathToInf[MAX_PATH] = { 0 };
    WCHAR pathToTmp[MAX_PATH] = { 0 };

    WCHAR* pos = NULL;
    WCHAR* token = wcstok_s(customData, L"|", &pos);
    /* action|path_to_inf_file|path_to_tmp_dir */
    while (token) {
        switch (i++) {
        case 0:
            wcscpy_s(action, _countof(action), token);
            break;

        case 1:
            wcscpy_s(pathToInf, _countof(pathToInf), token);
            break;

        case 2:
            wcscpy_s(pathToTmp, _countof(pathToTmp), token);
            break;
        }
        token = wcstok_s(NULL, L"|", &pos);
    }

    if (wcscmp(action, ACTION_ADD_DRIVER) == 0) {
        AddDriver(pathToInf, pathToTmp);
    }
    else if (wcscmp(action, ACTION_DELETE_DRIVER) == 0) {
        DeleteDriver(pathToTmp);
    }

cleanup:
    free(customData);

    if (coInitialsed) {
        CoUninitialize();
    }

    return 0;
}
