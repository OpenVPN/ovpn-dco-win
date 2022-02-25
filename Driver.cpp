/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
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

#include <intrin.h>
#include <ntddk.h>
#include <wsk.h>
#include <wdf.h>
#include <wdfrequest.h>

#include "bufferpool.h"
#include "driver.h"
#include "trace.h"
#include "peer.h"
#include "uapi\ovpn-dco.h"
#include "socket.h"

TRACELOGGING_DEFINE_PROVIDER(g_hOvpnEtwProvider,
  "OpenVPN.OvpnDCO",
  (0x4970f9cf, 0x2c0c, 0x4f11, 0xb1, 0xcc, 0xe3, 0xa1, 0xe9, 0x95, 0x88, 0x33));

// WSK Client Dispatch table that denotes the WSK version
// that the WSK application wants to use and optionally a pointer
// to the WskClientEvent callback function
const WSK_CLIENT_DISPATCH WskAppDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

EVT_WDF_DRIVER_UNLOAD OvpnEvtDriverUnload;

_Use_decl_annotations_
VOID
OvpnEvtDriverUnload(_In_ WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);

    TraceLoggingUnregister(g_hOvpnEtwProvider);

    // tail call optimization incorrectly eliminates TraceLoggingUnregister() call
    // add __nop() to prevent TCO
    __nop();
}

EXTERN_C DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

_Use_decl_annotations_
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath)
{
    WSK_CLIENT_NPI wskClientNpi = {};

    NTSTATUS status;
    BOOLEAN traceLoggingRegistered = FALSE;
    GOTO_IF_NOT_NT_SUCCESS(done, status, TraceLoggingRegister(g_hOvpnEtwProvider));
    traceLoggingRegistered = TRUE;

    LOG_INFO("Driver Version", TraceLoggingValue(OVPN_DCO_VERSION_MAJOR, "Major"), TraceLoggingValue(OVPN_DCO_VERSION_MINOR, "Minor"), TraceLoggingValue(OVPN_DCO_VERSION_PATCH, "Patch"));

    WDF_OBJECT_ATTRIBUTES driverAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttrs);
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&driverAttrs, OVPN_DRIVER);

    WDF_DRIVER_CONFIG driverConfig;
    WDF_DRIVER_CONFIG_INIT(&driverConfig, OvpnEvtDeviceAdd);
    driverConfig.EvtDriverUnload = OvpnEvtDriverUnload;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDriverCreate(driverObject, registryPath, &driverAttrs, &driverConfig, WDF_NO_HANDLE));

    // Register the WSK application
    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &WskAppDispatch;

    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());

    GOTO_IF_NOT_NT_SUCCESS(done, status, WskRegister(&wskClientNpi, &driverCtx->WskRegistration));

done:
    if (traceLoggingRegistered) {
        if (!NT_SUCCESS(status)) {
            TraceLoggingUnregister(g_hOvpnEtwProvider);
        }
    }

    return status;
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoRead;

_Use_decl_annotations_
VOID
OvpnEvtIoRead(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    UNREFERENCED_PARAMETER(length);

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // do we have pending control packets?
    LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->ControlRxBufferQueue);
    if (entry == NULL) {
        // no pending control packets, move request to manual queue
        LOG_IF_NOT_NT_SUCCESS(WdfRequestForwardToIoQueue(request, device->PendingReadsQueue));
        return;
    }

    OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);

    NTSTATUS status;

    // retrieve IO request buffer
    PVOID inputBuffer;
    size_t inputBufferLength;
    ULONG_PTR bytesSent;

    LOG_IF_NOT_NT_SUCCESS(status = WdfRequestRetrieveOutputBuffer(request, buffer->Len, &inputBuffer, &inputBufferLength));

    if (NT_SUCCESS(status)) {
        // copy packet into IO request buffer
        RtlCopyMemory(inputBuffer, buffer->Data, buffer->Len);
        bytesSent = buffer->Len;

        InterlockedIncrementNoFence(&device->Stats.ReceivedControlPackets);
    }
    else {
        // likely userspace buffer is too small
        bytesSent = 0;
    }

    // complete IO request
    WdfRequestCompleteWithInformation(request, status, bytesSent);

    // return buffer back to pool
    OvpnRxBufferPoolPut(buffer);
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoWrite;

_Use_decl_annotations_
VOID
OvpnEvtIoWrite(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    UNREFERENCED_PARAMETER(length);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // acquire spinlock, since we access device->TransportSocket
    KIRQL kiqrl = ExAcquireSpinLockShared(&device->SpinLock);

    OVPN_TX_BUFFER* buffer = NULL;

    if (device->Socket.Socket == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        LOG_ERROR("TransportSocket is not initialized");
        goto error;
    }

    // fetch tx buffer
    GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnTxBufferPoolGet(device->TxBufferPool, &buffer));

    // get request buffer
    PVOID requestBuffer;
    size_t requestBufferLength;
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestRetrieveInputBuffer(request, 0, &requestBuffer, &requestBufferLength));

    // copy data from request to tx buffer
    PUCHAR buf = OvpnTxBufferPut(buffer, requestBufferLength);
    RtlCopyMemory(buf, requestBuffer, requestBufferLength);

    buffer->IoQueue = device->PendingWritesQueue;

    // move request to manual queue
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestForwardToIoQueue(request, device->PendingWritesQueue));

    // send
    LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, buffer));

    goto done_not_complete;

error:
    if (buffer != NULL) {
        OvpnTxBufferPoolPut(buffer);
    }

    ULONG_PTR bytesCopied = 0;
    WdfRequestCompleteWithInformation(request, status, bytesCopied);

done_not_complete:
    ExReleaseSpinLockShared(&device->SpinLock, kiqrl);
}

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OvpnEvtIoDeviceControl;

_Use_decl_annotations_
VOID
OvpnEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outputBufferLength, size_t inputBufferLength, ULONG ioControlCode) {
    UNREFERENCED_PARAMETER(outputBufferLength);
    UNREFERENCED_PARAMETER(inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    ULONG_PTR bytesReturned = 0;

    KIRQL kirql = 0;
    switch ((long)ioControlCode) {
    case OVPN_IOCTL_GET_STATS:
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
        status = OvpnPeerGetStats(device, request, &bytesReturned);
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_NEW_PEER:
        status = OvpnPeerNew(device, request);
        if (status == STATUS_PENDING) {
            LOG_IF_NOT_NT_SUCCESS(WdfRequestForwardToIoQueue(request, device->PendingNewPeerQueue));
        }
        break;

    case OVPN_IOCTL_START_VPN:
        status = OvpnPeerStartVPN(device);
        break;

    case OVPN_IOCTL_NEW_KEY:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerNewKey(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SWAP_KEYS:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSwapKeys(device);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SET_PEER:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSet(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    default:
        LOG_WARN("Unknown <ioControlCode>", TraceLoggingValue(ioControlCode, "ioControlCode"));
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    if (status != STATUS_PENDING) {
        WdfRequestCompleteWithInformation(request, status, bytesReturned);
    }
}

EVT_WDF_FILE_CLEANUP OvpnEvtFileCleanup;

_Use_decl_annotations_
VOID OvpnEvtFileCleanup(WDFFILEOBJECT fileObject) {
    POVPN_DEVICE device = OvpnGetDeviceContext(WdfFileObjectGetDevice(fileObject));

    OvpnPeerUninit(device);
}

EVT_WDF_DEVICE_CONTEXT_CLEANUP OvpnEvtDeviceCleanup;

_Use_decl_annotations_
VOID OvpnEvtDeviceCleanup(WDFOBJECT obj) {
    LOG_INFO("");

    OVPN_DEVICE* device = OvpnGetDeviceContext(obj);

    OvpnTxBufferPoolDelete((OVPN_BUFFER_POOL)device->TxBufferPool);
    OvpnRxBufferPoolDelete((OVPN_BUFFER_POOL)device->RxBufferPool);

    OvpnBufferQueueDelete(device->ControlRxBufferQueue);
    OvpnBufferQueueDelete(device->DataRxBufferQueue);
}


EVT_WDF_DRIVER_DEVICE_ADD OvpnEvtDeviceAdd;

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceAdd(WDFDRIVER wdfDriver, PWDFDEVICE_INIT deviceInit) {
    LOG_INFO("");

    // make sure only one app can access driver at time
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, OvpnEvtFileCleanup);

    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\ovpn-dco");

    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, NetDeviceInitConfig(deviceInit));

    WDF_OBJECT_ATTRIBUTES objAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&objAttributes, OVPN_DEVICE);
    // BCryptOpenAlgorithmProvider with BCRYPT_PROV_DISPATCH returns STATUS_NOT_SUPPORTED if sync scope is WdfSynchronizationScopeDevice
    objAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
    objAttributes.EvtCleanupCallback = OvpnEvtDeviceCleanup;

    WDFDEVICE wdfDevice;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreate(&deviceInit, &objAttributes, &wdfDevice));

    // this will fail if one device has already been created but that's ok, since
    // openvpn2/3 accesses devices via Device Interface GUID, and symlink is used only by test client.
    LOG_IF_NOT_NT_SUCCESS(WdfDeviceCreateSymbolicLink(wdfDevice, &symLink));

    UNICODE_STRING referenceString;
    RtlInitUnicodeString(&referenceString, L"ovpn-dco");
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreateDeviceInterface(wdfDevice, &GUID_DEVINTERFACE_NET, &referenceString));

    // create main queue which handles reads/writes from userspace
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoRead = OvpnEvtIoRead;
    queueConfig.EvtIoWrite = OvpnEvtIoWrite;
    queueConfig.EvtIoDeviceControl = OvpnEvtIoDeviceControl;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE));

    POVPN_DEVICE device = OvpnGetDeviceContext(wdfDevice);
    device->WdfDevice = wdfDevice;

    // create manual pending queue which handles async reads
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingReadsQueue));

    // create manual pending queue which handles async writes
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingWritesQueue));

    // create manual pending queue which handles async NewPeer requests (when proto is TCP, connect is async)
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingNewPeerQueue));

    POVPN_DRIVER driver = OvpnGetDriverContext(wdfDriver);

    // Capture the WSK Provider NPI. If WSK subsystem is not ready yet, wait until it becomes ready.
    GOTO_IF_NOT_NT_SUCCESS(done, status, WskCaptureProviderNPI(&driver->WskRegistration, WSK_INFINITE_WAIT, &driver->WskProviderNpi));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTxBufferPoolCreate(&device->TxBufferPool, device));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnRxBufferPoolCreate(&device->RxBufferPool));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnBufferQueueCreate(&device->ControlRxBufferQueue));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnBufferQueueCreate(&device->DataRxBufferQueue));

done:
    return status;
}
