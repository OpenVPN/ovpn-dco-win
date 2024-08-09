/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2024- OpenVPN Inc <sales@openvpn.net>
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

#include "control.h"
#include "Driver.h"
#include "uapi\ovpn-dco.h"
#include "trace.h"

_Use_decl_annotations_
NTSTATUS
OvpnGetVersion(WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    LOG_ENTER();

    *bytesReturned = 0;

    NTSTATUS status;
    POVPN_VERSION version = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveOutputBuffer(request, sizeof(OVPN_VERSION), (PVOID*)&version, NULL));

    version->Major = OVPN_DCO_VERSION_MAJOR;
    version->Minor = OVPN_DCO_VERSION_MINOR;
    version->Patch = OVPN_DCO_VERSION_PATCH;

    LOG_INFO("Version", TraceLoggingValue(version->Major, "Major"), TraceLoggingValue(version->Minor, "Minor"), TraceLoggingValue(version->Patch, "Patch"));

    *bytesReturned = sizeof(OVPN_VERSION);

done:
    LOG_EXIT();

    return status;
}

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OvpnEvtControlDeviceIOControl;

VOID
OvpnEvtControlDeviceIOControl(WDFQUEUE queue, WDFREQUEST request, size_t outputBufferLength, size_t inputBufferLength, ULONG ioControlCode)
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesReturned = 0;

    switch (ioControlCode)
    {
    case OVPN_IOCTL_GET_VERSION:
        status = OvpnGetVersion(request, &bytesReturned);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(request, status, bytesReturned);
}

NTSTATUS
OvpnCreateControlDevice(WDFDRIVER wdfDriver)
{
    LOG_ENTER();

    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\ovpn-dco-ver"); // this will be used by CreateFile
    DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\ovpn-dco-ver"); // this is required tp create symlink

    // allocate control device initialization structure
    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(wdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R_RES_R);
    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // create the control device
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    WDFDEVICE controlDevice;
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceInitAssignName(deviceInit, &deviceName));
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreate(&deviceInit, &deviceAttributes, &controlDevice));

    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());
    driverCtx->ControlDevice = controlDevice;

    // symlink for control device
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreateSymbolicLink(controlDevice, &symLink));

    // queue to handle IO
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = OvpnEvtControlDeviceIOControl;
    WDFQUEUE queue;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(controlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue));

    // Complete the control device initialization
    WdfControlFinishInitializing(controlDevice);

 done:
    if (deviceInit)
    {
        WdfDeviceInitFree(deviceInit);
    }

    LOG_EXIT();

    return status;
}
